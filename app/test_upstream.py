"""
Scriptable local upstream used by the Docker Compose demo and the test suite.

Normal queries are answered with a deterministic A record derived from the
domain name (so different names produce visibly different answers).  Magic
labels select misbehaviour scenarios used to exercise the forwarder's
hardening:

    drop        never answer                       -> client gets SERVFAIL
    wrongq      send a wrong-question packet first, then the correct answer
    wrongqr     send a QR=0 packet first, then the correct answer
    wrongsrc    send a response from a different source port first, then the
                correct answer
    delay       wait UPSTREAM_DELAY_SECONDS before answering
    ooo         queue concurrent queries and answer them in reverse order
    ttlN        use TTL N for the answers (e.g. ttl5)
    cname       reply CNAME + A (valid but not cacheable)
    mixed       reply A for the queried name plus A for another owner
                (valid but not cacheable)
    multi       reply two A records for the queried name with different TTLs
    trunc       reply with TC=1 (not cacheable)
    nxdomain    reply NXDOMAIN with no answers (not cacheable)

The first matching token wins, in the order listed above (drop, then errors,
then poisoning attempts, then delays/reordering).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import os
import re
import signal
import socket
from dataclasses import dataclass
from typing import Optional

from .dns import (
    CLASS_IN,
    QR_MASK,
    RCODE_FORMERR,
    RCODE_NOTIMP,
    RCODE_NXDOMAIN,
    TC_MASK,
    TYPE_A,
    DnsFormatError,
    Question,
    build_error_response,
    build_message,
    header_from_bytes,
    make_a_rr,
    make_cname_rr,
    make_question,
    parse_message,
)

LOG = logging.getLogger("dns.test_upstream")

FORGED_WRONG_QNAME = ("poison", "invalid")
FORGED_IP = "203.0.113.66"
FORGED_IP_2 = "203.0.113.77"


def _env_first(*names: str, default: Optional[str] = None) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return default


def _env_int(*names: str, default: int) -> int:
    value = _env_first(*names)
    return default if value is None else int(value)


def _env_float(*names: str, default: float) -> float:
    value = _env_first(*names)
    return default if value is None else float(value)


@dataclass
class UpstreamConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 25354
    default_ttl: int = 30
    delay_seconds: float = 0.6
    wrongq_delay: float = 0.05
    ooo_window: float = 0.25
    # Optional global scenario; magic domain labels always work too.
    mode: str = "normal"

    @classmethod
    def from_env(cls) -> "UpstreamConfig":
        return cls(
            listen_host=_env_first("UPSTREAM_LISTEN_HOST", "TEST_UPSTREAM_HOST",
                                   default=cls.listen_host) or cls.listen_host,
            listen_port=_env_int("UPSTREAM_LISTEN_PORT", "TEST_UPSTREAM_PORT",
                                 default=cls.listen_port),
            default_ttl=_env_int("UPSTREAM_TTL", default=cls.default_ttl),
            delay_seconds=_env_float("UPSTREAM_DELAY_SECONDS",
                                     "TEST_UPSTREAM_DELAY",
                                     default=cls.delay_seconds),
            wrongq_delay=_env_float("UPSTREAM_WRONGQ_DELAY",
                                    default=cls.wrongq_delay),
            ooo_window=_env_float("UPSTREAM_OOO_WINDOW",
                                  default=cls.ooo_window),
            mode=_env_first("UPSTREAM_MODE", default=cls.mode) or cls.mode,
        )

    def validate(self) -> None:
        if not 0 <= self.listen_port <= 65535:
            raise ValueError("监听端口必须在 0..65535 之间（0 表示随机端口）")
        if self.default_ttl < 0:
            raise ValueError("TTL 不能为负数")
        if self.delay_seconds < 0 or self.wrongq_delay < 0 or self.ooo_window < 0:
            raise ValueError("延迟不能为负数")
        allowed = {"normal", "drop", "wrongq", "wrongqr", "wrongsrc",
                   "delay", "slow", "ooo", "reverse", "cname", "mixed",
                   "multi", "trunc", "nxdomain", "nx"}
        if self.mode.casefold() not in allowed:
            raise ValueError(
                f"未知的 UPSTREAM_MODE={self.mode!r}，可选值：{sorted(allowed)}")


def _answer_ip(name: str, offset: int = 0) -> str:
    digest = int(hashlib.sha256(name.casefold().encode("utf-8")).hexdigest(), 16)
    return f"198.51.100.{1 + (digest + offset) % 254}"


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, server: "TestUpstreamServer") -> None:
        self.server = server
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if self.transport is not None:
            self.server.handle_packet(data, addr, self.transport)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        LOG.warning("test upstream socket error: %s", exc)


class TestUpstreamServer:
    """A scriptable UDP DNS upstream.  Use magic labels to select behaviour."""

    # Keep pytest from trying to collect this helper class as a test case.
    __test__ = False

    def __init__(self, config: UpstreamConfig) -> None:
        config.validate()
        self.config = config
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.address: Optional[tuple[str, int]] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._ooo_queue: list[tuple[int, tuple[str, int], bytes]] = []
        self._ooo_handle: Optional[asyncio.TimerHandle] = None
        self._ooo_seq = 0
        self._tasks: set[asyncio.Task] = set()
        self._closed = False
        # Introspection for tests/demos.
        self.query_count = 0
        self.queries: list[dict] = []
        self.sent_ids: list[int] = []

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self.transport, _ = await self._loop.create_datagram_endpoint(
            lambda: _Protocol(self),
            local_addr=(self.config.listen_host, self.config.listen_port),
            family=socket.AF_INET,
        )
        self.address = self.transport.get_extra_info("sockname")[:2]
        LOG.info("scriptable upstream listening on %s:%s (ttl=%s)",
                 self.address[0], self.address[1], self.config.default_ttl)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._ooo_handle is not None:
            self._ooo_handle.cancel()
            self._ooo_handle = None
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    @property
    def port(self) -> int:
        if self.address is None:  # pragma: no cover
            raise RuntimeError("upstream has not been started")
        return int(self.address[1])

    # ------------------------------------------------------------------ #
    # Query handling
    # ------------------------------------------------------------------ #
    def handle_packet(self, data: bytes, addr, transport) -> None:
        if self._closed or transport is None:
            return
        try:
            message = parse_message(data)
        except DnsFormatError:
            header = header_from_bytes(data)
            if header is not None:
                msg_id, flags = header
                if not (flags & QR_MASK):
                    transport.sendto(
                        build_error_response(msg_id, flags, (), RCODE_FORMERR),
                        addr)
            return

        if message.qr:
            return
        if message.opcode != 0:
            transport.sendto(build_error_response(
                message.msg_id, message.flags, message.questions[:1],
                RCODE_NOTIMP), addr)
            return
        if len(message.questions) != 1:
            transport.sendto(build_error_response(
                message.msg_id, message.flags, message.questions[:1],
                RCODE_FORMERR), addr)
            return
        question = message.questions[0]
        if question.qtype != TYPE_A or question.qclass != CLASS_IN \
                or message.additionals:
            transport.sendto(build_error_response(
                message.msg_id, message.flags, [question], RCODE_NOTIMP), addr)
            return

        self.query_count += 1
        self.queries.append({
            "id": message.msg_id,
            "name": question.name,
            "addr": (addr[0], addr[1]),
            "time": self._loop.time() if self._loop else 0.0,
        })
        self.sent_ids.append(message.msg_id)

        ttl = self._ttl_for(question)
        ip = _answer_ip(question.name)

        tokens = [label.casefold() for label in question.labels]
        if self.config.mode.casefold() != "normal":
            tokens.append(self.config.mode.casefold())

        def starts(prefix: str) -> bool:
            return any(token == prefix or token.startswith(prefix + "-")
                       or token.startswith(prefix + "_")
                       or token.startswith(prefix + ".")
                       or (token.startswith(prefix) and token[len(prefix):].isdigit())
                       for token in tokens)

        # Unambiguous scenario tokens.
        wrongqr = any(t.startswith("wrongqr") for t in tokens)
        wrongsrc = any(t.startswith("wrongsrc") for t in tokens)
        wrongq = any(t.startswith("wrongq") and not t.startswith("wrongqr")
                     and not t.startswith("wrongsrc") for t in tokens)
        drop = starts("drop")
        delay = starts("delay") or starts("slow")
        ooo = starts("ooo") or starts("reverse")
        cname = starts("cname")
        mixed = starts("mixed")
        multi = starts("multi")
        trunc = starts("trunc")
        nxdomain = starts("nxdomain") or starts("nx")

        if drop:
            LOG.info("scenario drop: %s", question.name)
            return

        if nxdomain:
            response = build_message(
                message.msg_id,
                self._response_flags(message.flags, RCODE_NXDOMAIN),
                [question])
            self._send(response, addr)
            return

        if trunc:
            answers = [make_a_rr(question.labels, ttl, ip)]
            response = build_message(
                message.msg_id,
                self._response_flags(message.flags, 0) | TC_MASK,
                [question], answers)
            self._send(response, addr)
            return

        if cname:
            target = ("target",) + question.labels
            answers = [
                make_cname_rr(question.labels, ttl, target),
                make_a_rr(target, ttl, ip),
            ]
            response = build_message(
                message.msg_id, self._response_flags(message.flags, 0),
                [question], answers)
            self._send(response, addr)
            return

        if mixed:
            other = ("other",) + question.labels
            answers = [
                make_a_rr(question.labels, ttl, ip),
                make_a_rr(other, ttl + 5, _answer_ip(".".join(other) + ".")),
            ]
            response = build_message(
                message.msg_id, self._response_flags(message.flags, 0),
                [question], answers)
            self._send(response, addr)
            return

        if multi:
            answers = [
                make_a_rr(question.labels, ttl, ip),
                make_a_rr(question.labels, ttl + 7, _answer_ip(question.name, 1)),
            ]
            response = build_message(
                message.msg_id, self._response_flags(message.flags, 0),
                [question], answers)
            self._send(response, addr)
            return

        correct = self._correct_response(message, question, ttl, ip)

        if wrongqr:
            forged = build_message(
                message.msg_id,
                (self._response_flags(message.flags, 0) & ~QR_MASK),
                [question],
                [make_a_rr(question.labels, 300, FORGED_IP_2)])
            self._spawn(self._poison_then_correct(forged, correct, addr,
                                                 question.name, "wrongqr"))
            return

        if wrongsrc:
            forged = build_message(
                message.msg_id, self._response_flags(message.flags, 0),
                [question], [make_a_rr(question.labels, 300, FORGED_IP_2)])
            self._spawn(self._wrong_source_then_correct(
                forged, correct, addr, question.name))
            return

        if wrongq:
            forged_question = make_question(FORGED_WRONG_QNAME)
            forged = build_message(
                message.msg_id, self._response_flags(message.flags, 0),
                [forged_question],
                [make_a_rr(FORGED_WRONG_QNAME, 300, FORGED_IP)])
            self._spawn(self._poison_then_correct(forged, correct, addr,
                                                 question.name, "wrongq"))
            return

        if delay:
            LOG.info("scenario delay %.2fs: %s", self.config.delay_seconds,
                     question.name)
            self._spawn(self._deliver_later(
                correct, addr, self.config.delay_seconds))
            return

        if ooo:
            LOG.info("scenario out-of-order queue: %s", question.name)
            self._ooo_seq += 1
            self._ooo_queue.append((self._ooo_seq, (addr[0], addr[1]), correct))
            if self._ooo_handle is None:
                self._ooo_handle = self._loop.call_later(
                    self.config.ooo_window, self._flush_ooo)
            return

        self._send(correct, addr)

    def _correct_response(self, message, question: Question, ttl: int,
                          ip: str) -> bytes:
        return build_message(
            message.msg_id, self._response_flags(message.flags, 0),
            [question], [make_a_rr(question.labels, ttl, ip)])

    @staticmethod
    def _response_flags(request_flags: int, rcode: int) -> int:
        return (QR_MASK
                | (request_flags & 0x7800)   # echo opcode
                | (request_flags & 0x0100)   # echo RD
                | 0x0080                    # RA
                | (rcode & 0x000F))

    def _ttl_for(self, question: Question) -> int:
        for label in question.labels:
            match = re.search(r"ttl([0-9]+)", label.casefold())
            if match:
                return int(match.group(1))
        return self.config.default_ttl

    # ------------------------------------------------------------------ #
    # Scenario helpers
    # ------------------------------------------------------------------ #
    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _deliver_later(self, response: bytes, addr, delay: float) -> None:
        await asyncio.sleep(delay)
        if not self._closed:
            self._send(response, addr)

    async def _poison_then_correct(self, forged: bytes, correct: bytes, addr,
                                   name: str, kind: str) -> None:
        LOG.info("scenario %s: sending forged packet first for %s", kind, name)
        if not self._closed:
            self._send(forged, addr)
        await asyncio.sleep(self.config.wrongq_delay)
        if not self._closed:
            self._send(correct, addr)

    async def _wrong_source_then_correct(self, forged: bytes, correct: bytes,
                                         addr, name: str) -> None:
        LOG.info("scenario wrongsrc: forged packet from another port for %s",
                 name)
        loop = asyncio.get_running_loop()
        wrong, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            local_addr=("0.0.0.0", 0),
            family=socket.AF_INET,
        )
        try:
            wrong.sendto(forged, addr)
            # Give the forwarder time to see (and ignore) the wrong-source
            # packet before the genuine one arrives.
            await asyncio.sleep(self.config.wrongq_delay)
        finally:
            wrong.close()
        if not self._closed:
            self._send(correct, addr)

    def _flush_ooo(self) -> None:
        self._ooo_handle = None
        queued = self._ooo_queue
        self._ooo_queue = []
        # Reverse arrival order, deliberately answering later questions first.
        for _seq, addr, response in sorted(queued, key=lambda item: item[0],
                                           reverse=True):
            if not self._closed:
                self._send(response, addr)

    def _send(self, data: bytes, addr) -> None:
        if self.transport is not None and not self._closed:
            self.transport.sendto(data, addr)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scriptable local UDP DNS upstream for the forwarder demo.")
    parser.add_argument("--listen-host", default=None)
    parser.add_argument("--listen-port", type=int, default=None)
    parser.add_argument("--ttl", type=int, default=None)
    parser.add_argument("--delay", type=float, default=None)
    parser.add_argument("--ooo-window", type=float, default=None)
    parser.add_argument("--mode", default=None,
                        help="global scenario (normal/drop/wrongq/wrongqr/"
                             "wrongsrc/delay/ooo/cname/mixed/multi/trunc/"
                             "nxdomain)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args(argv)


async def _run(config: UpstreamConfig) -> None:
    server = TestUpstreamServer(config)
    await server.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # pragma: no cover
            pass
    await stop.wait()
    await server.close()


def main(argv=None) -> None:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = UpstreamConfig.from_env()
    if args.listen_host is not None:
        config.listen_host = args.listen_host
    if args.listen_port is not None:
        config.listen_port = args.listen_port
    if args.ttl is not None:
        config.default_ttl = args.ttl
    if args.delay is not None:
        config.delay_seconds = args.delay
    if args.ooo_window is not None:
        config.ooo_window = args.ooo_window
    if args.mode is not None:
        config.mode = args.mode
    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:  # pragma: no cover
        pass


if __name__ == "__main__":  # pragma: no cover
    main()
