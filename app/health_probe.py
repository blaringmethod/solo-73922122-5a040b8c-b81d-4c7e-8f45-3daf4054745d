"""Tiny UDP health probe used by the Docker healthcheck.

Sends a real A/IN query to the forwarding service and exits 0 as soon as any
well-formed DNS response comes back (including SERVFAIL: that still proves the
forwarder itself is alive).  Exits 1 on timeout or communication error.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
import sys

from .dns import DnsFormatError, build_query, parse_message, text_to_labels


def _env_port() -> int:
    for name in ("DNS_PROBE_PORT", "DNS_LISTEN_PORT", "LISTEN_PORT"):
        value = os.environ.get(name)
        if value:
            try:
                return int(value)
            except ValueError:
                pass
    return 25353


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.future: asyncio.Future = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        if not self.future.done():
            self.future.set_exception(exc)


async def main() -> int:
    host = os.environ.get("DNS_PROBE_HOST") or "127.0.0.1"
    port = _env_port()
    qid = secrets.randbelow(65536)
    labels = text_to_labels("health.probe.test")
    packet = build_query(qid, labels)

    loop = asyncio.get_running_loop()
    protocol = _Protocol()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            remote_addr=(host, port),
            family=socket.AF_INET,
        )
    except OSError as exc:
        print(f"health probe: cannot create socket: {exc}", file=sys.stderr)
        return 1

    try:
        transport.sendto(packet)
        raw = await asyncio.wait_for(protocol.future, timeout=2.5)
    except (asyncio.TimeoutError, TimeoutError):
        print(f"health probe: timeout talking to {host}:{port}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"health probe: {exc}", file=sys.stderr)
        return 1
    finally:
        transport.close()

    try:
        message = parse_message(raw)
    except DnsFormatError as exc:
        print(f"health probe: malformed response: {exc}", file=sys.stderr)
        return 1
    if message.msg_id != qid:
        print("health probe: response id mismatch", file=sys.stderr)
        return 1
    print(f"health probe: OK rcode={message.rcode_name} "
          f"answers={len(message.answers)}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(asyncio.run(main()))
