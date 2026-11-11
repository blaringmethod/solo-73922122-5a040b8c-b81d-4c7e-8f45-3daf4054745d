"""Wire-format and cache unit tests (standard library only).

These tests can be run with either ``pytest`` or ``python -m unittest``.
"""

import struct
import unittest

from app.cache import DnsCache
from app.dns import (
    CLASS_IN,
    QR_MASK,
    RCODE_FORMERR,
    RCODE_NOERROR,
    RCODE_SERVFAIL,
    TYPE_A,
    TYPE_AAAA,
    DnsFormatError,
    ResourceRecord,
    build_cached_response,
    build_error_response,
    build_query,
    canonical_name,
    encode_name,
    make_question,
    parse_message,
    parse_name,
    text_to_labels,
)


class DnsCodecTests(unittest.TestCase):
    def test_text_to_labels(self):
        self.assertEqual(text_to_labels("www.Example.TEST."),
                         ("www", "Example", "TEST"))
        self.assertEqual(text_to_labels("example.test"), ("example", "test"))
        self.assertEqual(text_to_labels("."), ())
        with self.assertRaises(ValueError):
            text_to_labels("a..b")
        with self.assertRaises(ValueError):
            text_to_labels("x" * 64)

    def test_query_roundtrip(self):
        packet = build_query(0xBEEF, ("www", "example", "test"))
        message = parse_message(packet)
        self.assertEqual(message.msg_id, 0xBEEF)
        self.assertFalse(message.qr)
        self.assertTrue(message.rd)
        self.assertEqual(len(message.questions), 1)
        self.assertEqual(message.questions[0].labels, ("www", "example", "test"))
        self.assertEqual(message.questions[0].qtype, TYPE_A)
        self.assertEqual(message.questions[0].qclass, CLASS_IN)
        self.assertEqual(message.questions[0].raw,
                         encode_name(("www", "example", "test"))
                         + struct.pack("!HH", TYPE_A, CLASS_IN))

    def test_name_compression_in_response(self):
        # Header: response, 1 question, 1 answer.
        header = struct.pack("!HHHHHH", 0x0102, 0x8180, 1, 1, 0, 0)
        question = (encode_name(("example", "test"))
                    + struct.pack("!HH", TYPE_A, CLASS_IN))
        # Owner name is a pointer to the question name at offset 12.
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", TYPE_A, CLASS_IN, 42, 4)
                  + b"\x0a\x00\x00\x01")
        message = parse_message(header + question + answer)
        self.assertTrue(message.qr)
        self.assertEqual(message.answers[0].labels, ("example", "test"))
        self.assertEqual(message.answers[0].ttl, 42)
        self.assertEqual(message.answers[0].rdata, b"\x0a\x00\x00\x01")

    def test_compression_loop_rejected(self):
        # Pointer at offset 12 points to itself.
        with self.assertRaises(DnsFormatError):
            parse_name(b"\xc0\x0c", 0)

    def test_trailing_garbage_rejected(self):
        packet = build_query(1, ("a", "test")) + b"\x00"
        with self.assertRaises(DnsFormatError):
            parse_message(packet)

    def test_truncated_sections_rejected(self):
        header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        with self.assertRaises(DnsFormatError):
            parse_message(header + b"\x03abc")

    def test_error_response_echoes_id_and_question(self):
        request = build_query(0x1234, ("x", "test"))
        message = parse_message(request)
        response = build_error_response(0x1234, message.flags,
                                        [message.questions[0]], RCODE_SERVFAIL)
        reply = parse_message(response)
        self.assertTrue(reply.qr)
        self.assertEqual(reply.msg_id, 0x1234)
        self.assertEqual(reply.rcode, RCODE_SERVFAIL)
        self.assertTrue(reply.ra)
        self.assertEqual(reply.questions[0].labels, ("x", "test"))

    def test_notimp_for_aaaa_question(self):
        q = make_question(("x", "test"), qtype=TYPE_AAAA)
        response = build_error_response(7, 0x0100, [q], RCODE_FORMERR)
        reply = parse_message(response)
        self.assertEqual(reply.questions[0].qtype, TYPE_AAAA)
        self.assertEqual(reply.rcode, RCODE_FORMERR)

    def test_cached_response_restores_client_id_and_case(self):
        cached_answers = (
            ResourceRecord(("Example", "TEST"), TYPE_A, CLASS_IN, 10,
                           b"\x01\x02\x03\x04"),
            ResourceRecord(("example", "test"), TYPE_A, CLASS_IN, 4,
                           b"\x05\x06\x07\x08"),
        )
        question = make_question(("EXAMPLE", "TeSt"))
        flags = QR_MASK | 0x0180 | RCODE_NOERROR
        response = build_cached_response(0xABCD, 0x0100, question, flags,
                                         cached_answers, 2)
        reply = parse_message(response)
        self.assertEqual(reply.msg_id, 0xABCD)
        self.assertEqual(reply.questions[0].labels, ("EXAMPLE", "TeSt"))
        self.assertEqual([rr.ttl for rr in reply.answers], [8, 2])
        self.assertEqual([rr.labels for rr in reply.answers],
                         [("EXAMPLE", "TeSt"), ("EXAMPLE", "TeSt")])
        self.assertFalse(reply.tc)


class CacheTests(unittest.TestCase):
    def _answers(self):
        return [
            ResourceRecord(("a", "test"), TYPE_A, CLASS_IN, 10,
                           b"\x01\x01\x01\x01"),
            ResourceRecord(("a", "test"), TYPE_A, CLASS_IN, 5,
                           b"\x02\x02\x02\x02"),
        ]

    def test_min_ttl_expiry_and_age(self):
        cache = DnsCache(max_entries=4)
        entry = cache.put("a.test", self._answers(), 0x8180, now=100.0)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.min_ttl, 5)

        hit = cache.get("a.test", now=100.0)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[1], 0)

        hit = cache.get("a.test", now=103.9)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[1], 3)

        # Lifetime is governed by the smallest TTL, exactly.
        self.assertIsNone(cache.get("a.test", now=105.0))

    def test_hits_do_not_extend_lifetime(self):
        cache = DnsCache(max_entries=4)
        cache.put("a.test", self._answers(), 0, now=0.0)
        for at in (1.0, 2.0, 3.0, 4.0):
            self.assertIsNotNone(cache.get("a.test", now=at))
        self.assertIsNone(cache.get("a.test", now=5.0))

    def test_zero_ttl_not_cached(self):
        cache = DnsCache(max_entries=4)
        answers = [ResourceRecord(("a", "test"), TYPE_A, CLASS_IN, 0,
                                  b"\x01\x01\x01\x01")]
        self.assertIsNone(cache.put("a.test", answers, 0, now=0.0))
        self.assertIsNone(cache.get("a.test", now=0.0))

    def test_lru_eviction(self):
        cache = DnsCache(max_entries=2)
        cache.put("a", self._answers(), 0, now=0.0)
        cache.put("b", self._answers(), 0, now=0.0)
        self.assertIsNotNone(cache.get("a", now=0.0))  # a becomes most recent
        cache.put("c", self._answers(), 0, now=0.0)
        self.assertIsNone(cache.get("b", now=0.0))
        self.assertIsNotNone(cache.get("a", now=0.0))
        self.assertIsNotNone(cache.get("c", now=0.0))

    def test_canonical_key_is_case_insensitive(self):
        self.assertEqual(canonical_name(("Example", "TEST")), "example.test")
        self.assertEqual(canonical_name(("EXAMPLE", "test")), "example.test")


if __name__ == "__main__":
    unittest.main()
