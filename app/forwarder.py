"""
Single-process UDP DNS forwarding service.

Security / correctness properties implemented here:

* The upstream IPv4 endpoint is resolved once at startup and never changes.
* Only single-question A/IN queries without EDNS are accepted.
* Every in-flight client query gets its own random upstream transaction ID,
  unique among all pending queries.  The pending table is indexed by that ID
  and stores the client endpoint plus the client's original ID, so two clients
  that happen to use the same DNS ID are demultiplexed independently.
* An upstream packet is accepted only when its source is exactly the configured
  IPv4 endpoint, QR=1, and the complete question (QNAME/QTYPE/QCLASS, name case
  insensitive) matches the pending query.  Anything else is ignored and the
  query keeps waiting.
* On timeout (2 seconds by default) the client receives SERVFAIL.
* Responses are cached only after full validation and only when they are
  NOERROR, untruncated, and contain a non-empty answer set consisting solely of
  IN/A records owned by the queried name.  Cache lifetime is the smallest TTL
  in that answer set; hits restore the client's ID and subtract the entry's
  age from every TTL without touching the stored entry.

All of this runs in one asyncio event loop; there are no worker processes and
no shared mutable state touched from threads.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import secrets
import signal
import socket
import struct
from dataclasses import dataclass
from typing import Optional

from .cache import DnsCache
from .dns import (
    CLASS_IN,
    QR_MASK,
    RCODE_FORMERR,
    RCODE_NOTIMP,
    RCODE_NOERROR,
    RCODE_SERVFAIL,
    TYPE_A,
    DnsFormatError,
    Question,
    build_cached_response,
    build_error_response,
    build_query,
    canonical_name,
    header_from_bytes,
    parse_message,
)

LOG = logging.getLogger("dns.forwarder")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def _env_first(*names: str, default: Optional[str] = None) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return default


def _env_int(*names: str, default: int) -> int:
    value = _env_first(*names)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"环境变量 {names[0]} 必须是整数，当前为 {value!r}") from exc


def _env_float(*names: str, default: float) -> float:
    value = _env_first(*names)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"环境变量 {names[0]} 必须是数字，当前为 {value!r}") from exc


def resolve_ipv4(host: str) -> str:
    """
    Return a numeric IPv4 address for ``host``.

    An IPv4 literal is used as-is.  A hostname (e.g. a Docker Compose service
    name) is resolved exactly once, at startup, so the upstream endpoint is
    fixed for the lifetime of the process.
    """
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, 0, family=socket.AF_INET,
                                   type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise ValueError(f"无法把上游地址 {host!r} 解析为 IPv4 地址") from exc
    if not infos:
        raise ValueError(f"上游地址 {host!r} 没有 IPv4 地址")
    return infos[0][4][0]


def _split_endpoint(value: str, default_port: int) -> tuple[str, int]:
    """Parse ``host`` or ``host:port`` (an IPv4 address is expected)."""
    text = value.strip()
    if ":" not in text:
        return text, default_port
    host, raw_port = text.rsplit(":", 1)
    if not host or not raw_port.isdigit():
        raise ValueError(f"无法解析地址 {value!r}，应形如 192.0.2.10:53")
    return host.strip(), int(raw_port)


@dataclass
class ForwarderConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 25353
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 25354
    timeout: float = 2.0
    cache_size: int = 1024

    @classmethod
    def from_env(cls) -> "ForwarderConfig":
        listen_host = _env_first("DNS_LISTEN_HOST", "LISTEN_HOST",
                                 default=cls.listen_host) or cls.listen_host
        listen_port = _env_int("DNS_LISTEN_PORT", "LISTEN_PORT",
                               default=cls.listen_port)
        combined_listen = _env_first("DNS_LISTEN_ADDR", "LISTEN_ADDR")
        if combined_listen:
            listen_host, listen_port = _split_endpoint(combined_listen,
                                                       listen_port)

        upstream_host = (_env_first("DNS_UPSTREAM_HOST", "DNS_UPSTREAM_IP",
                                    "UPSTREAM_HOST", "UPSTREAM_IP",
                                    default=cls.upstream_host)
                         or cls.upstream_host)
        upstream_port = _env_int("DNS_UPSTREAM_PORT", "UPSTREAM_PORT",
                                 default=cls.upstream_port)
        combined_upstream = _env_first("DNS_UPSTREAM_ADDR", "UPSTREAM_ADDR",
                                       "UPSTREAM")
        if combined_upstream:
            upstream_host, upstream_port = _split_endpoint(combined_upstream,
                                                           upstream_port)

        return cls(
            listen_host=listen_host,
            listen_port=listen_port,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            timeout=_env_float("DNS_TIMEOUT_SECONDS", "DNS_TIMEOUT",
                               "UPSTREAM_TIMEOUT", default=cls.timeout),
            cache_size=_env_int("DNS_CACHE_SIZE", "CACHE_SIZE",
                                default=cls.cache_size),
        )

    def validate(self) -> None:
        # port 0 is allowed for the listen socket (ephemeral port, tests).
        if not 0 <= self.listen_port <= 65535:
            raise ValueError("监听端口必须在 0..65535 之间（0 表示随机端口）")
        if not 1 <= self.upstream_port <= 65535:
            raise ValueError("上游端口必须在 1..65535 之间")
        if self.timeout <= 0:
            raise ValueError("超时时间必须大于 0 秒")
        if self.cache_size < 0:
            raise ValueError("缓存条数不能为负数")


@dataclass
class _Pending:
    upstream_id: int
    client_addr: tuple[str, int]
    client_id: int
    question: Question
    client_flags: int
    client_transport: asyncio.DatagramTransport
    future: asyncio.Future


class _ClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: "DnsForwarder") -> None:
        self.service = service
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if self.transport is not None:
            self.service.handle_client_packet(data, addr, self.transport)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        LOG.warning("client socket error: %s", exc)


class _UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: "DnsForwarder") -> None:
        self.service = service
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.service.handle_upstream_packet(data, addr)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        LOG.warning("upstream socket error: %s", exc)


class DnsForwarder:
    """A single-process, asyncio-based DNS forwarder with a validated TTL cache."""

    RETIRE_SECONDS = 5.0

    def __init__(self, config: ForwarderConfig) -> None:
        config.validate()
        self.config = config
        self.cache = DnsCache(max_entries=config.cache_size)
        self._pending: dict[int, _Pending] = {}
        self._retired: dict[int, float] = {}
        self._tasks: set[asyncio.Task] = set()
        self.client_transport: Optional[asyncio.DatagramTransport] = None
        self.upstream_transport: Optional[asyncio.DatagramTransport] = None
        self.upstream_ip: Optional[str] = None
        self.listen_address: Optional[tuple[str, int]] = None
        self.upstream_local_address: Optional[tuple[str, int]] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._closed = False

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self.upstream_ip = resolve_ipv4(self.config.upstream_host)

        self.upstream_transport, _ = await self._loop.create_datagram_endpoint(
            lambda: _UpstreamProtocol(self),
            local_addr=("0.0.0.0", 0),
            family=socket.AF_INET,
        )
        self.upstream_local_address = self.upstream_transport.get_extra_info(
            "sockname")[:2]

        self.client_transport, _ = await self._loop.create_datagram_endpoint(
            lambda: _ClientProtocol(self),
            local_addr=(self.config.listen_host, self.config.listen_port),
            family=socket.AF_INET,
        )
        self.listen_address = self.client_transport.get_extra_info("sockname")[:2]
        LOG.info(
            "DNS forwarder listening on %s:%s -> upstream %s:%s "
            "(timeout=%.1fs, cache=%s entries, single process)",
            self.listen_address[0], self.listen_address[1],
            self.upstream_ip, self.config.upstream_port,
            self.config.timeout, self.config.cache_size,
        )

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for pending in list(self._pending.values()):
            if not pending.future.done():
                pending.future.cancel()
        self._pending.clear()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self.client_transport is not None:
            self.client_transport.close()
            self.client_transport = None
        if self.upstream_transport is not None:
            self.upstream_transport.close()
            self.upstream_transport = None

    @property
    def listen_port(self) -> int:
        if self.listen_address is None:  # pragma: no cover - not started
            raise RuntimeError("forwarder has not been started")
        return int(self.listen_address[1])

    # ------------------------------------------------------------------ #
    # Client side
    # ------------------------------------------------------------------ #
    def handle_client_packet(self, data: bytes, addr, transport) -> None:
        if self._closed or transport is None:
            return
        try:
            message = parse_message(data)
        except DnsFormatError:
            header = header_from_bytes(data)
            if header is not None:
                msg_id, flags = header
                if not (flags & QR_MASK):
                    self._send_error(transport, addr, msg_id, flags, (),
                                     RCODE_FORMERR)
            return

        # Never answer a response; it could create a reflection loop.
        if message.qr:
            return

        if message.opcode != 0:
            self._send_error(transport, addr, message.msg_id, message.flags,
                             message.questions[:1], RCODE_NOTIMP)
            return

        if len(message.questions) != 1:
            self._send_error(transport, addr, message.msg_id, message.flags,
                             message.questions[:1], RCODE_FORMERR)
            return

        question = message.questions[0]

        # A query has no answer/authority records.  Additional records are
        # unsupported (EDNS is carried as an OPT pseudo-record there).
        if message.answers or message.authorities:
            self._send_error(transport, addr, message.msg_id, message.flags,
                             [question], RCODE_FORMERR)
            return
        if message.additionals:
            self._send_error(transport, addr, message.msg_id, message.flags,
                             [question], RCODE_NOTIMP)
            return

        if question.qtype != TYPE_A or question.qclass != CLASS_IN:
            self._send_error(transport, addr, message.msg_id, message.flags,
                             [question], RCODE_NOTIMP)
            return

        key = canonical_name(question.labels)

        # Cache lookup happens before allocating an upstream ID.  A hit never
        # contacts the upstream and never refreshes the entry.
        hit = self.cache.get(key)
        if hit is not None:
            entry, age = hit
            response = build_cached_response(
                message.msg_id, message.flags, question, entry.flags,
                entry.answers, age)
            transport.sendto(response, addr)
            LOG.info("cache hit %s qid=%04x age=%ss min_ttl=%s",
                     question.name, message.msg_id, age, entry.min_ttl)
            return

        upstream_id = self._allocate_upstream_id(exclude=message.msg_id)
        if upstream_id is None:  # pragma: no cover - 65536 concurrent queries
            self._send_error(transport, addr, message.msg_id, message.flags,
                             [question], RCODE_SERVFAIL)
            return

        pending = _Pending(
            upstream_id=upstream_id,
            client_addr=(addr[0], addr[1]),
            client_id=message.msg_id,
            question=question,
            client_flags=message.flags,
            client_transport=transport,
            future=self._loop.create_future(),  # type: ignore[union-attr]
        )
        self._pending[upstream_id] = pending
        upstream_query = build_query(upstream_id, question.labels,
                                     question.qtype, question.qclass, rd=True)
        self.upstream_transport.sendto(
            upstream_query,
            (self.upstream_ip, self.config.upstream_port))  # type: ignore[union-attr]
        LOG.info("forward %s qid=%04x -> upstream id=%04x client=%s:%s",
                 question.name, message.msg_id, upstream_id, addr[0], addr[1])

        task = asyncio.create_task(
            self._await_upstream(pending, transport),
            name=f"dns-wait-{upstream_id:04x}",
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _send_error(self, transport, addr, msg_id: int, request_flags: int,
                    questions, rcode: int) -> None:
        if self._closed:
            return
        response = build_error_response(msg_id, request_flags, questions, rcode)
        transport.sendto(response, addr)

    async def _await_upstream(self, pending: _Pending, client_transport) -> None:
        try:
            response = await asyncio.wait_for(pending.future,
                                              timeout=self.config.timeout)
        except asyncio.TimeoutError:
            current = self._pending.get(pending.upstream_id)
            if current is not pending:
                # A validated response won the race; it will be sent below.
                return
            self._pending.pop(pending.upstream_id, None)
            self._retire(pending.upstream_id)
            if not self._closed:
                servfail = build_error_response(
                    pending.client_id, pending.client_flags,
                    [pending.question], RCODE_SERVFAIL)
                try:
                    client_transport.sendto(servfail, pending.client_addr)
                except Exception as exc:  # pragma: no cover
                    LOG.warning("failed to send SERVFAIL to %s: %s",
                                pending.client_addr, exc)
            LOG.warning("timeout %s after %.1fs -> SERVFAIL",
                        pending.question.name, self.config.timeout)
        except asyncio.CancelledError:
            if self._pending.get(pending.upstream_id) is pending:
                self._pending.pop(pending.upstream_id, None)
                self._retire(pending.upstream_id)
            raise
        else:
            if not self._closed:
                try:
                    client_transport.sendto(response, pending.client_addr)
                except Exception as exc:  # pragma: no cover
                    LOG.warning("failed to send answer to %s: %s",
                                pending.client_addr, exc)

    # ------------------------------------------------------------------ #
    # Upstream side
    # ------------------------------------------------------------------ #
    def handle_upstream_packet(self, data: bytes, addr) -> None:
        if self._closed:
            return

        # 1) Exact source endpoint.
        if (addr[0], addr[1]) != (self.upstream_ip, self.config.upstream_port):
            LOG.warning("ignored upstream packet from unexpected source %s:%s",
                        addr[0], addr[1])
            return

        try:
            message = parse_message(data)
        except DnsFormatError as exc:
            LOG.warning("ignored malformed upstream packet: %s", exc)
            return

        # 2) It must be a response.
        if not message.qr:
            LOG.warning("ignored upstream packet without QR bit")
            return
        if message.opcode != 0:
            LOG.warning("ignored upstream packet with non-QUERY opcode")
            return

        # 3) Transaction ID must map to exactly one pending query.
        pending = self._pending.get(message.msg_id)
        if pending is None:
            LOG.debug("ignored upstream packet with unknown id=%04x",
                      message.msg_id)
            return

        # 4) The complete question must echo the pending query.
        if len(message.questions) != 1:
            LOG.warning("ignored upstream packet with %d questions",
                        len(message.questions))
            return
        if not message.questions[0].same_question(pending.question):
            LOG.warning("ignored upstream packet with mismatched question "
                        "%s -> %s (pending %s)",
                        pending.question.name, message.questions[0].name,
                        pending.question.name)
            return

        # Fully validated.  It is now safe to retire the pending entry, maybe
        # cache the answer set, and deliver the response to its own client.
        del self._pending[message.msg_id]
        self._retire(message.msg_id)

        if self._is_cacheable(message):
            try:
                self.cache.put(canonical_name(pending.question.labels),
                               message.answers, message.flags)
                LOG.info("cache store %s ttl=%s", pending.question.name,
                         min(rr.ttl for rr in message.answers))
            except Exception:  # pragma: no cover - defensive
                LOG.exception("failed to cache answer for %s",
                              pending.question.name)

        patched = bytearray(data)
        struct.pack_into("!H", patched, 0, pending.client_id)
        response = bytes(patched)
        if pending.future.done():
            # The 2s timer may have cancelled the future in the same loop
            # iteration in which this valid response arrived.  In that case
            # the waiter will not send anything, so deliver it here instead of
            # silently dropping a fully validated answer.
            if pending.future.cancelled() and not self._closed:
                try:
                    pending.client_transport.sendto(response,
                                                    pending.client_addr)
                    LOG.warning(
                        "delivered %s after timeout race for qid=%04x",
                        pending.question.name, pending.client_id)
                except Exception as exc:  # pragma: no cover
                    LOG.warning("failed to deliver timeout-race answer: %s",
                                exc)
        else:
            pending.future.set_result(response)

    def _is_cacheable(self, message) -> bool:
        if message.tc:
            return False
        if message.rcode != RCODE_NOERROR:
            return False
        if not message.answers:
            return False

        queried = canonical_name(message.questions[0].labels)
        for rr in message.answers:
            if rr.rtype != TYPE_A or rr.rclass != CLASS_IN:
                return False
            if canonical_name(rr.labels) != queried:
                return False
            if len(rr.rdata) != 4:
                return False
        return True

    # ------------------------------------------------------------------ #
    # Transaction IDs
    # ------------------------------------------------------------------ #
    def _retire(self, upstream_id: int) -> None:
        if self._loop is None:  # pragma: no cover
            return
        self._retired[upstream_id] = self._loop.time()

    def _allocate_upstream_id(self, exclude: Optional[int] = None
                              ) -> Optional[int]:
        if len(self._pending) >= 65536:
            return None
        assert self._loop is not None
        now = self._loop.time()
        for old_id, when in list(self._retired.items()):
            if now - when > self.RETIRE_SECONDS:
                del self._retired[old_id]

        # Random, and unique among pending queries (also avoiding very recent
        # IDs so a late duplicate cannot be mistaken for a new query).  The
        # client's own ID is excluded as well, making the two namespaces easy
        # to tell apart in logs and tests.
        for _ in range(256):
            candidate = secrets.randbelow(65536)
            if (candidate != exclude
                    and candidate not in self._pending
                    and candidate not in self._retired):
                return candidate
        for candidate in range(65536):
            if (candidate != exclude
                    and candidate not in self._pending
                    and candidate not in self._retired):
                return candidate
        return None  # pragma: no cover


# --------------------------------------------------------------------------- #
# CLI / process entry point
# --------------------------------------------------------------------------- #
def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Single-process UDP DNS forwarder (A/IN only, no EDNS).")
    parser.add_argument("--listen-host", default=None,
                        help="IPv4 address to bind (env DNS_LISTEN_HOST)")
    parser.add_argument("--listen-port", type=int, default=None,
                        help="UDP port to bind (env DNS_LISTEN_PORT)")
    parser.add_argument("--listen", "--listen-addr", dest="listen_addr",
                        default=None,
                        help="combined listen endpoint host:port")
    parser.add_argument("--upstream-host", "--upstream-ip", dest="upstream_host",
                        default=None,
                        help="upstream IPv4 address or hostname resolved at "
                             "startup (env DNS_UPSTREAM_HOST)")
    parser.add_argument("--upstream-port", type=int, default=None,
                        help="upstream UDP port (env DNS_UPSTREAM_PORT)")
    parser.add_argument("--upstream", "--upstream-addr", dest="upstream_addr",
                        default=None,
                        help="combined upstream endpoint host:port")
    parser.add_argument("--timeout", type=float, default=None,
                        help="upstream timeout in seconds, default 2 "
                             "(env DNS_TIMEOUT_SECONDS)")
    parser.add_argument("--cache-size", type=int, default=None,
                        help="maximum cached names (env DNS_CACHE_SIZE)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args(argv)


def _config_from_args(args: argparse.Namespace) -> ForwarderConfig:
    config = ForwarderConfig.from_env()
    if args.listen_addr is not None:
        config.listen_host, config.listen_port = _split_endpoint(
            args.listen_addr, config.listen_port)
    if args.upstream_addr is not None:
        config.upstream_host, config.upstream_port = _split_endpoint(
            args.upstream_addr, config.upstream_port)
    if args.listen_host is not None:
        config.listen_host = args.listen_host
    if args.listen_port is not None:
        config.listen_port = args.listen_port
    if args.upstream_host is not None:
        config.upstream_host = args.upstream_host
    if args.upstream_port is not None:
        config.upstream_port = args.upstream_port
    if args.timeout is not None:
        config.timeout = args.timeout
    if args.cache_size is not None:
        config.cache_size = args.cache_size
    return config


async def _run(config: ForwarderConfig) -> None:
    forwarder = DnsForwarder(config)
    await forwarder.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # pragma: no cover
            pass
    await stop.wait()
    await forwarder.close()


def main(argv=None) -> None:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = _config_from_args(args)
    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:  # pragma: no cover
        pass


if __name__ == "__main__":  # pragma: no cover
    main()
