"""Integration tests for the forwarding service (standard library only).

Each test runs a real scriptable upstream and a real forwarder on ephemeral
UDP ports, then talks to the forwarder exactly like any other DNS client.
"""

import asyncio
import ipaddress
import socket
import struct
import time
import unittest

from app.dns import (
    CLASS_IN,
    RCODE_FORMERR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    TYPE_A,
    TYPE_AAAA,
    build_query,
    encode_name,
    parse_message,
    text_to_labels,
)
from app.forwarder import DnsForwarder, ForwarderConfig
from app.test_upstream import (
    FORGED_IP,
    TestUpstreamServer,
    UpstreamConfig,
    _answer_ip,
)


class _QueryProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.future: asyncio.Future = asyncio.get_running_loop().create_future()

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.future.done():
            self.future.set_result(data)


async def udp_query(port: int, name: str, qid: int, *, timeout: float = 2.0,
                    packet: bytes = None):
    """Send one query on a fresh ephemeral source port and parse the reply."""
    labels = text_to_labels(name)
    if packet is None:
        packet = build_query(qid, labels)
    loop = asyncio.get_running_loop()
    protocol = _QueryProtocol()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        remote_addr=("127.0.0.1", port),
        family=socket.AF_INET,
    )
    try:
        transport.sendto(packet)
        raw = await asyncio.wait_for(protocol.future, timeout)
    finally:
        transport.close()
    return parse_message(raw)


def edns_query(qid: int, labels) -> bytes:
    """A/IN query carrying an OPT pseudo-record (EDNS)."""
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1)
        + encode_name(labels)
        + struct.pack("!HH", TYPE_A, CLASS_IN)
        + b"\x00"
        + struct.pack("!HHIH", 41, 4096, 0, 0)
    )


class ForwarderTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.upstream = TestUpstreamServer(UpstreamConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            default_ttl=5,
            delay_seconds=0.2,
            wrongq_delay=0.02,
            ooo_window=0.12,
        ))
        await self.upstream.start()
        self.forwarder = DnsForwarder(ForwarderConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            upstream_host="127.0.0.1",
            upstream_port=self.upstream.port,
            timeout=0.6,
            cache_size=200,
        ))
        await self.forwarder.start()
        self.port = self.forwarder.listen_port

    async def asyncTearDown(self) -> None:
        await self.forwarder.close()
        await self.upstream.close()

    # ------------------------------------------------------------------ #
    # Normal forwarding and cache
    # ------------------------------------------------------------------ #
    async def test_forward_and_cache_with_ttl_decrement_and_expiry(self):
        first = await udp_query(self.port, "ttl2-cache.example.test", 0x1234)
        self.assertEqual(first.msg_id, 0x1234)
        self.assertEqual(first.rcode, 0)
        self.assertEqual(len(first.answers), 1)
        self.assertEqual(first.answers[0].ttl, 2)
        self.assertEqual(first.answers[0].rdata,
                         ipaddress.IPv4Address(
                             _answer_ip(first.questions[0].name)).packed)

        count = self.upstream.query_count
        await asyncio.sleep(1.05)
        second = await udp_query(self.port,
                                 "TTL2-CACHE.Example.TEST", 0x4321)
        self.assertEqual(second.msg_id, 0x4321)          # client ID restored
        self.assertEqual(self.upstream.query_count, count)  # cache hit
        self.assertEqual(second.answers[0].ttl, 1)       # age subtracted
        self.assertEqual(second.questions[0].labels,
                         ("TTL2-CACHE", "Example", "TEST"))  # client's case

        # Total age now > smallest TTL: the entry must be gone, even though it
        # was hit once.  A hit cannot extend the entry's lifetime.
        await asyncio.sleep(1.05)
        third = await udp_query(self.port, "ttl2-cache.example.test", 0x9999)
        self.assertEqual(self.upstream.query_count, count + 1)
        self.assertEqual(third.answers[0].ttl, 2)       # fresh upstream answer

    async def test_different_clients_same_query_id_do_not_cross_answers(self):
        names = ["sameid-1.example.test", "sameid-2.example.test"]
        qid = 0x7777
        replies = await asyncio.gather(
            *(udp_query(self.port, name, qid) for name in names))
        answers = []
        for name, reply in zip(names, replies):
            self.assertEqual(reply.msg_id, qid)
            self.assertEqual(reply.questions[0].labels,
                             text_to_labels(name))
            expected = _answer_ip(reply.questions[0].name)
            self.assertEqual(
                ipaddress.IPv4Address(reply.answers[0].rdata),
                ipaddress.IPv4Address(expected))
            answers.append(reply.answers[0].rdata)
        self.assertNotEqual(answers[0], answers[1])

        # The forwarder allocated a distinct random upstream ID per pending
        # query, even though both clients used 0x7777.
        recent = self.upstream.sent_ids[-len(names):]
        self.assertEqual(len(recent), 2)
        self.assertNotEqual(recent[0], recent[1])
        self.assertNotEqual(recent[0], qid)
        self.assertNotEqual(recent[1], qid)

    # ------------------------------------------------------------------ #
    # Poisoned / forged packet handling
    # ------------------------------------------------------------------ #
    async def test_wrong_question_packet_is_ignored_and_not_cached(self):
        reply = await udp_query(self.port, "wrongq-x.example.test", 0x3333)
        self.assertEqual(reply.rcode, 0)
        expected = _answer_ip(reply.questions[0].name)
        self.assertEqual(
            ipaddress.IPv4Address(reply.answers[0].rdata),
            ipaddress.IPv4Address(expected))
        self.assertNotEqual(expected, FORGED_IP)

        # The forged packet's question must never become a cache entry, and
        # the cached correct answer must be the genuine one.
        self.assertNotIn("poison.invalid", self.forwarder.cache.keys())
        entry = self.forwarder.cache.get("wrongq-x.example.test")
        self.assertIsNotNone(entry)
        self.assertEqual(
            ipaddress.IPv4Address(entry[0].answers[0].rdata),
            ipaddress.IPv4Address(expected))

    async def test_wrong_qr_and_wrong_source_packets_are_ignored(self):
        for name in ("wrongqr-x.example.test", "wrongsrc-x.example.test"):
            reply = await udp_query(self.port, name, 0x3434)
            self.assertEqual(reply.rcode, 0)
            expected = _answer_ip(reply.questions[0].name)
            self.assertEqual(
                ipaddress.IPv4Address(reply.answers[0].rdata),
                ipaddress.IPv4Address(expected))

    async def test_timeout_returns_servfail(self):
        started = time.perf_counter()
        reply = await udp_query(self.port, "drop-x.example.test", 0x5555,
                                timeout=1.5)
        elapsed = time.perf_counter() - started
        self.assertEqual(reply.msg_id, 0x5555)
        self.assertEqual(reply.rcode, RCODE_SERVFAIL)
        self.assertEqual(reply.questions[0].labels,
                         ("drop-x", "example", "test"))
        self.assertGreaterEqual(elapsed, 0.45)
        self.assertLess(elapsed, 1.3)

    # ------------------------------------------------------------------ #
    # Cache eligibility
    # ------------------------------------------------------------------ #
    async def test_non_cacheable_answers_are_forwarded_every_time(self):
        for name in ("cname-x.example.test", "mixed-x.example.test",
                     "trunc-x.example.test", "nxdomain-x.example.test"):
            count = self.upstream.query_count
            first = await udp_query(self.port, name, 0x6001)
            self.assertEqual(self.upstream.query_count, count + 1)
            await udp_query(self.port, name, 0x6002)
            self.assertEqual(self.upstream.query_count, count + 2,
                             f"{name} should not have been cached")
            if "nxdomain" in name:
                self.assertEqual(first.rcode, RCODE_NXDOMAIN)
                self.assertEqual(len(first.answers), 0)
            elif "trunc" in name:
                self.assertTrue(first.tc)

    async def test_multi_answer_cache_lifetime_uses_smallest_ttl(self):
        first = await udp_query(self.port, "multi-ttl2.example.test", 0x6101)
        self.assertEqual([rr.ttl for rr in first.answers], [2, 9])
        count = self.upstream.query_count

        await asyncio.sleep(1.05)
        second = await udp_query(self.port, "multi-ttl2.example.test", 0x6102)
        self.assertEqual(self.upstream.query_count, count)
        self.assertEqual([rr.ttl for rr in second.answers], [1, 8])

        await asyncio.sleep(1.05)
        third = await udp_query(self.port, "multi-ttl2.example.test", 0x6103)
        self.assertEqual(self.upstream.query_count, count + 1)
        self.assertEqual([rr.ttl for rr in third.answers], [2, 9])

    # ------------------------------------------------------------------ #
    # Out-of-order replies
    # ------------------------------------------------------------------ #
    async def test_out_of_order_replies_still_map_to_the_right_client(self):
        names = ["ooo-1.example.test", "ooo-2.example.test",
                 "ooo-3.example.test"]
        qids = [0x9001, 0x9002, 0x9003]
        replies = await asyncio.gather(
            *(udp_query(self.port, name, qid)
              for name, qid in zip(names, qids)))
        for name, qid, reply in zip(names, qids, replies):
            self.assertEqual(reply.msg_id, qid)
            self.assertEqual(reply.questions[0].labels,
                             text_to_labels(name))
            self.assertEqual(
                ipaddress.IPv4Address(reply.answers[0].rdata),
                ipaddress.IPv4Address(_answer_ip(reply.questions[0].name)))

    # ------------------------------------------------------------------ #
    # Unsupported client queries
    # ------------------------------------------------------------------ #
    async def test_unsupported_qtype_and_edns_are_rejected_without_forwarding(self):
        count = self.upstream.query_count

        reply = await udp_query(self.port, "aaaa.example.test", 0xA1A1,
                                packet=build_query(0xA1A1,
                                                   text_to_labels("aaaa.example.test"),
                                                   qtype=TYPE_AAAA))
        self.assertEqual(reply.rcode, 4)  # NOTIMP

        reply = await udp_query(self.port, "edns.example.test", 0xE1E1,
                                packet=edns_query(0xE1E1,
                                                  text_to_labels("edns.example.test")))
        self.assertEqual(reply.rcode, 4)  # NOTIMP

        header = struct.pack("!HHHHHH", 0x2222, 0x0100, 2, 0, 0, 0)
        q1 = (encode_name(("multi-q", "example", "test"))
              + struct.pack("!HH", TYPE_A, CLASS_IN))
        q2 = (encode_name(("second", "example", "test"))
              + struct.pack("!HH", TYPE_A, CLASS_IN))
        reply = await udp_query(self.port, "multi-q.example.test", 0x2222,
                                packet=header + q1 + q2)
        self.assertEqual(reply.rcode, RCODE_FORMERR)

        self.assertEqual(self.upstream.query_count, count)


if __name__ == "__main__":
    unittest.main()
