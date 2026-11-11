"""
Minimal DNS wire-format codec (RFC 1035), standard library only.

The forwarding service only needs a small, strict subset of DNS:

* one question, QTYPE=A, QCLASS=IN, no EDNS;
* answers are A records (plus whatever the upstream sends, which is parsed so
  the response can be validated and selectively cached).

Everything here is deliberately strict: truncated packets, bad compression
pointers, trailing garbage and malformed section counts are rejected with
``DnsFormatError``.  The forwarder treats such packets as forged/invalid and
ignores them.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import Optional, Sequence, Union

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_OPT = 41

CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

QR_MASK = 0x8000
OPCODE_MASK = 0x7800
AA_MASK = 0x0400
TC_MASK = 0x0200
RD_MASK = 0x0100
RA_MASK = 0x0080
RCODE_MASK = 0x000F

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 16: "TXT",
    28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}
CLASS_NAMES = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}

MAX_NAME_WIRE = 255
MAX_LABEL = 63
MAX_PACKET = 65535


class DnsFormatError(ValueError):
    """Packet is not a well-formed DNS message."""


# --------------------------------------------------------------------------- #
# Names
# --------------------------------------------------------------------------- #
def labels_to_text(labels: Sequence[str]) -> str:
    """Canonical presentation form with a trailing root dot."""
    if not labels:
        return "."
    return ".".join(labels) + "."


def canonical_labels(labels: Sequence[str]) -> tuple[str, ...]:
    """Case-folded labels used for DNS name comparison and cache keys."""
    return tuple(label.casefold() for label in labels)


def canonical_name(labels: Sequence[str]) -> str:
    """Case-insensitive cache key (no trailing dot; root is the empty string)."""
    return ".".join(canonical_labels(labels))


def parse_name(data: bytes, offset: int) -> tuple[tuple[str, ...], int]:
    """
    Decode a DNS name starting at ``offset``.

    Compression pointers are followed with a loop guard.  Returns the decoded
    labels (original case preserved) and the offset of the first byte after the
    name in the *original* position (which is the byte after a pointer, not the
    pointer target).
    """
    labels: list[str] = []
    pos = offset
    after: Optional[int] = None
    visited: set[int] = set()
    wire_len = 1  # terminating zero byte

    while True:
        if pos >= len(data):
            raise DnsFormatError("truncated domain name")
        length = data[pos]

        if length == 0:
            pos += 1
            if after is None:
                after = pos
            break

        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DnsFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if after is None:
                after = pos + 2
            if pointer >= len(data):
                raise DnsFormatError("compression pointer out of range")
            if pointer in visited:
                raise DnsFormatError("compression pointer loop")
            visited.add(pointer)
            if len(visited) > 64:
                raise DnsFormatError("too many compression pointers")
            pos = pointer
            continue

        if length & 0xC0:
            raise DnsFormatError("reserved label length")
        if length > MAX_LABEL:
            raise DnsFormatError("label too long")
        if pos + 1 + length > len(data):
            raise DnsFormatError("truncated label")
        raw_label = data[pos + 1:pos + 1 + length]
        try:
            label = raw_label.decode("ascii")
        except UnicodeDecodeError as exc:
            raise DnsFormatError("non-ASCII label") from exc
        labels.append(label)
        wire_len += length + 1
        if wire_len > MAX_NAME_WIRE:
            raise DnsFormatError("domain name too long")
        pos += 1 + length

    return tuple(labels), after


def encode_name(labels: Sequence[str]) -> bytes:
    """Encode labels as an uncompressed wire-format name."""
    out = bytearray()
    for label in labels:
        if not isinstance(label, str):
            raise DnsFormatError("label must be a string")
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= MAX_LABEL:
            raise DnsFormatError(f"label length {len(raw)} is outside 1..63")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    if len(out) > MAX_NAME_WIRE:
        raise DnsFormatError("domain name too long")
    return bytes(out)


def text_to_labels(name: str) -> tuple[str, ...]:
    """
    Convert a human supplied domain name to wire labels.

    A trailing dot is accepted.  ASCII labels are kept verbatim (case is
    preserved); non-ASCII labels are converted to IDNA/punycode.
    """
    if not isinstance(name, str):
        raise ValueError("域名必须是字符串")
    text = name.strip()
    if text in ("", "."):
        return ()
    if text.endswith("."):
        text = text[:-1]
    if not text:
        return ()

    labels: list[str] = []
    for part in text.split("."):
        if not part:
            raise ValueError("域名中含有空标签")
        try:
            part.encode("ascii")
            ascii_part = part
        except UnicodeEncodeError:
            try:
                ascii_part = part.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError(f"无法转换为 IDNA 的标签：{part!r}") from exc
        if len(ascii_part.encode("ascii")) > MAX_LABEL:
            raise ValueError(f"标签过长（最多 {MAX_LABEL} 字节）：{part!r}")
        labels.append(ascii_part)

    if len(encode_name(tuple(labels))) > MAX_NAME_WIRE:
        raise ValueError("域名过长（最多 255 字节）")
    return tuple(labels)


# --------------------------------------------------------------------------- #
# Questions and resource records
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Question:
    labels: tuple[str, ...]
    qtype: int
    qclass: int
    raw: bytes = b""

    @property
    def name(self) -> str:
        return labels_to_text(self.labels)

    @property
    def key(self) -> tuple[tuple[str, ...], int, int]:
        return canonical_labels(self.labels), self.qtype, self.qclass

    def same_question(self, other: "Question") -> bool:
        """Case-insensitive full-question comparison (QNAME, QTYPE, QCLASS)."""
        return self.key == other.key


@dataclass(frozen=True)
class ResourceRecord:
    labels: tuple[str, ...]
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes

    @property
    def name(self) -> str:
        return labels_to_text(self.labels)

    @property
    def cache_name(self) -> str:
        return canonical_name(self.labels)

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")

    @property
    def class_name(self) -> str:
        return CLASS_NAMES.get(self.rclass, f"CLASS{self.rclass}")


@dataclass(frozen=True)
class Message:
    msg_id: int
    flags: int
    questions: tuple[Question, ...]
    answers: tuple[ResourceRecord, ...]
    authorities: tuple[ResourceRecord, ...]
    additionals: tuple[ResourceRecord, ...]

    @property
    def qr(self) -> bool:
        return bool(self.flags & QR_MASK)

    @property
    def opcode(self) -> int:
        return (self.flags & OPCODE_MASK) >> 11

    @property
    def aa(self) -> bool:
        return bool(self.flags & AA_MASK)

    @property
    def tc(self) -> bool:
        return bool(self.flags & TC_MASK)

    @property
    def rd(self) -> bool:
        return bool(self.flags & RD_MASK)

    @property
    def ra(self) -> bool:
        return bool(self.flags & RA_MASK)

    @property
    def rcode(self) -> int:
        return self.flags & RCODE_MASK

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def parse_question(data: bytes, offset: int) -> tuple[Question, int]:
    labels, next_offset = parse_name(data, offset)
    if next_offset + 4 > len(data):
        raise DnsFormatError("truncated question")
    qtype, qclass = struct.unpack_from("!HH", data, next_offset)
    end = next_offset + 4
    raw = encode_name(labels) + struct.pack("!HH", qtype, qclass)
    return Question(labels=labels, qtype=qtype, qclass=qclass, raw=raw), end


def parse_rr(data: bytes, offset: int) -> tuple[ResourceRecord, int]:
    labels, next_offset = parse_name(data, offset)
    if next_offset + 10 > len(data):
        raise DnsFormatError("truncated resource record")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, next_offset)
    rdata_start = next_offset + 10
    rdata_end = rdata_start + rdlength
    if rdata_end > len(data):
        raise DnsFormatError("truncated record data")
    return (
        ResourceRecord(labels=labels, rtype=rtype, rclass=rclass, ttl=ttl,
                       rdata=data[rdata_start:rdata_end]),
        rdata_end,
    )


def parse_message(data: bytes) -> Message:
    """Strictly parse a complete DNS message (no trailing bytes allowed)."""
    if len(data) < 12:
        raise DnsFormatError("packet shorter than the DNS header")
    if len(data) > MAX_PACKET:
        raise DnsFormatError("packet too large")
    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", data, 0)
    offset = 12

    questions: list[Question] = []
    for _ in range(qdcount):
        question, offset = parse_question(data, offset)
        questions.append(question)

    answers: list[ResourceRecord] = []
    for _ in range(ancount):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)

    authorities: list[ResourceRecord] = []
    for _ in range(nscount):
        rr, offset = parse_rr(data, offset)
        authorities.append(rr)

    additionals: list[ResourceRecord] = []
    for _ in range(arcount):
        rr, offset = parse_rr(data, offset)
        additionals.append(rr)

    if offset != len(data):
        raise DnsFormatError("trailing bytes after DNS message")
    return Message(
        msg_id=msg_id,
        flags=flags,
        questions=tuple(questions),
        answers=tuple(answers),
        authorities=tuple(authorities),
        additionals=tuple(additionals),
    )


def header_from_bytes(data: bytes) -> Optional[tuple[int, int]]:
    """Best effort (id, flags) extraction for FORMERR replies to broken packets."""
    if len(data) < 12:
        return None
    try:
        msg_id, flags = struct.unpack_from("!HH", data, 0)
    except struct.error:  # pragma: no cover - len checked above
        return None
    return msg_id, flags


# --------------------------------------------------------------------------- #
# Building
# --------------------------------------------------------------------------- #
def encode_rr(rr: ResourceRecord,
              owner_labels: Optional[Sequence[str]] = None) -> bytes:
    """Encode a record with an uncompressed owner name and raw RDATA."""
    labels = rr.labels if owner_labels is None else tuple(owner_labels)
    return (
        encode_name(labels)
        + struct.pack("!HHIH", rr.rtype, rr.rclass, rr.ttl & 0xFFFFFFFF,
                      len(rr.rdata))
        + rr.rdata
    )


def build_query(msg_id: int, labels: Sequence[str], qtype: int = TYPE_A,
                qclass: int = CLASS_IN, rd: bool = True) -> bytes:
    """Build a single-question query; never emits EDNS."""
    flags = RD_MASK if rd else 0
    return (
        struct.pack("!HHHHHH", msg_id & 0xFFFF, flags, 1, 0, 0, 0)
        + encode_name(labels)
        + struct.pack("!HH", qtype, qclass)
    )


def make_question(labels: Sequence[str], qtype: int = TYPE_A,
                  qclass: int = CLASS_IN) -> Question:
    raw = encode_name(tuple(labels)) + struct.pack("!HH", qtype, qclass)
    return Question(tuple(labels), qtype, qclass, raw)


def _question_raw(value: Union[Question, bytes]) -> bytes:
    return value.raw if isinstance(value, Question) else bytes(value)


def build_message(msg_id: int, flags: int,
                  questions: Sequence[Union[Question, bytes]],
                  answers: Sequence[ResourceRecord] = (),
                  authorities: Sequence[ResourceRecord] = (),
                  additionals: Sequence[ResourceRecord] = ()) -> bytes:
    """Build a message from prepared flags/questions/records (uncompressed)."""
    qraw = b"".join(_question_raw(q) for q in questions)
    body = bytearray()
    body.extend(qraw)
    for rr in answers:
        body.extend(encode_rr(rr))
    for rr in authorities:
        body.extend(encode_rr(rr))
    for rr in additionals:
        body.extend(encode_rr(rr))
    header = struct.pack(
        "!HHHHHH", msg_id & 0xFFFF, flags & 0xFFFF,
        len(questions), len(answers), len(authorities), len(additionals))
    return header + bytes(body)


def error_response_flags(request_flags: int, rcode: int) -> int:
    """QR=1, echo opcode/RD, RA=1, requested RCODE, no AA/TC."""
    return (QR_MASK
            | (request_flags & OPCODE_MASK)
            | (request_flags & RD_MASK)
            | RA_MASK
            | (rcode & RCODE_MASK))


def build_error_response(msg_id: int, request_flags: int,
                         questions: Sequence[Union[Question, bytes]],
                         rcode: int) -> bytes:
    return build_message(msg_id, error_response_flags(request_flags, rcode),
                         questions)


def build_cached_response(msg_id: int, client_flags: int, question: Question,
                          cached_flags: int,
                          answers: Sequence[ResourceRecord],
                          elapsed_seconds: int) -> bytes:
    """
    Rebuild a cached answer for a new client.

    The client's original ID and question bytes are restored.  Every TTL is
    reduced by the (whole-second) age of the cache entry.  The stored entry is
    not modified, so a hit can never extend its lifetime.
    """
    flags = (cached_flags | QR_MASK | RA_MASK) & ~TC_MASK
    flags = (flags & ~RD_MASK) | (client_flags & RD_MASK)
    adjusted: list[ResourceRecord] = []
    shift = max(0, int(elapsed_seconds))
    for rr in answers:
        # The cache only contains A answers for the queried name.  Rewriting
        # the owner from the client's question preserves the client's letter
        # case and is still the same DNS name.
        adjusted.append(ResourceRecord(
            labels=question.labels,
            rtype=rr.rtype,
            rclass=rr.rclass,
            ttl=max(0, rr.ttl - shift),
            rdata=rr.rdata,
        ))
    return build_message(msg_id, flags, [question], adjusted)


def make_a_rr(labels: Sequence[str], ttl: int, address: str) -> ResourceRecord:
    packed = ipaddress.IPv4Address(address).packed
    return ResourceRecord(tuple(labels), TYPE_A, CLASS_IN, int(ttl), packed)


def make_cname_rr(labels: Sequence[str], ttl: int,
                  target_labels: Sequence[str]) -> ResourceRecord:
    rdata = encode_name(tuple(target_labels))
    return ResourceRecord(tuple(labels), TYPE_CNAME, CLASS_IN, int(ttl), rdata)


def a_rdata_to_text(rdata: bytes) -> Optional[str]:
    if len(rdata) != 4:
        return None
    return str(ipaddress.IPv4Address(rdata))


def rdata_to_text(rr: ResourceRecord) -> str:
    """Human-readable RDATA for the UI; falls back to hex for unknown types."""
    if rr.rtype == TYPE_A:
        text = a_rdata_to_text(rr.rdata)
        if text is not None:
            return text
    if rr.rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        try:
            labels, end = parse_name(rr.rdata, 0)
            if end == len(rr.rdata):
                return labels_to_text(labels)
        except DnsFormatError:
            pass
    return rr.rdata.hex()
