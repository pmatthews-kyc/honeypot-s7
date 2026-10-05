"""
ber.py
------
Minimal BER/ASN.1 encoder+decoder covering exactly what SNMP v1/v2c
GET/GETNEXT request/response needs: INTEGER, OCTET STRING, NULL, OBJECT
IDENTIFIER, SEQUENCE, and the SNMP PDU context tags (GetRequest 0xA0,
GetNextRequest 0xA1, GetResponse 0xA2).

Hand-rolled deliberately, same reasoning as s7_precheck.py: a full SNMP
library's internals/version API can shift under us, and the honeypot only
needs a small, fixed slice of the protocol. Fewer moving parts, easier to
audit, nothing to break on a `pip install` version bump.

This is NOT a general-purpose ASN.1/BER library -- don't reuse it outside
this project without extending type coverage and edge-case handling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# --- Tag constants -----------------------------------------------------

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_TIMETICKS = 0x43  # SNMP application-specific type, NOT generic INTEGER

PDU_GET_REQUEST = 0xA0
PDU_GET_NEXT_REQUEST = 0xA1
PDU_GET_RESPONSE = 0xA2
PDU_SET_REQUEST = 0xA3


class BERError(Exception):
    pass


# --- Length encoding -----------------------------------------------------

def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    encoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _decode_length(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    num_bytes = first & 0x7F
    length = int.from_bytes(data[pos:pos + num_bytes], "big")
    return length, pos + num_bytes


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


# --- Type encoders -------------------------------------------------------

def encode_integer(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        length = (value.bit_length() // 8) + 1
        body = value.to_bytes(length, "big", signed=True)
        # trim redundant leading 0x00 for positive numbers where possible
        while len(body) > 1 and body[0] == 0x00 and body[1] < 0x80:
            body = body[1:]
    return _encode_tlv(TAG_INTEGER, body)


def encode_octet_string(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _encode_tlv(TAG_OCTET_STRING, value)


def encode_ip_address(dotted: str) -> bytes:
    """
    Encode an IPv4 address as ASN.1 IpAddress (APPLICATION 0, tag 0x40).
    snmpwalk / MIB-aware tools check the tag against the MIB definition;
    using OCTET STRING (0x04) produces 'Wrong Type (should be IpAddress)'.
    """
    value = bytes(int(o) for o in dotted.split("."))
    return _encode_tlv(0x40, value)   # APPLICATION 0 = IpAddress


def encode_null() -> bytes:
    return _encode_tlv(TAG_NULL, b"")
    return _encode_tlv(TAG_NULL, b"")


def encode_timeticks(value: int) -> bytes:
    """SNMP TimeTicks (hundredths of a second since some epoch, e.g. agent
    start). Encoded like a non-negative INTEGER but with the TimeTicks
    application tag -- getting this tag right matters, since a parser
    checking types strictly (rather than just values) would flag a plain
    INTEGER here as wrong for sysUpTime."""
    if value == 0:
        body = b"\x00"
    else:
        length = (value.bit_length() // 8) + 1
        body = value.to_bytes(length, "big", signed=False)
        while len(body) > 1 and body[0] == 0x00 and body[1] < 0x80:
            body = body[1:]
        if body[0] & 0x80:
            body = b"\x00" + body
    return _encode_tlv(TAG_TIMETICKS, body)


def encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise BERError(f"OID too short: {oid}")
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p == 0:
            body += b"\x00"
        else:
            chunk = []
            while p:
                chunk.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(chunk) - 1):
                chunk[i] |= 0x80
            body += bytes(chunk)
    return _encode_tlv(TAG_OID, body)


def encode_sequence(*items: bytes) -> bytes:
    return _encode_tlv(TAG_SEQUENCE, b"".join(items))


def encode_pdu(pdu_tag: int, *items: bytes) -> bytes:
    return _encode_tlv(pdu_tag, b"".join(items))


# --- Decoders --------------------------------------------------------

def decode_oid(data: bytes) -> str:
    if not data:
        return ""
    first = data[0]
    parts = [first // 40, first % 40]
    i = 1
    value = 0
    while i < len(data):
        b = data[i]
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(value)
            value = 0
        i += 1
    return ".".join(str(p) for p in parts)


def decode_integer(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=True)


@dataclass
class TLV:
    tag: int
    value: bytes


def parse_tlvs(data: bytes, pos: int, end: int) -> list[TLV]:
    """Parse a flat sequence of TLVs between pos and end (non-recursive)."""
    items = []
    while pos < end:
        tag = data[pos]
        pos += 1
        length, pos = _decode_length(data, pos)
        value = data[pos:pos + length]
        pos += length
        items.append(TLV(tag, value))
    return items


@dataclass
class SNMPMessage:
    version: int          # 0 = v1, 1 = v2c
    community: str
    pdu_tag: int
    request_id: int
    varbinds: list[tuple[str, Any]]  # list of (oid, value_tlv_or_None)


def parse_snmp_message(data: bytes) -> SNMPMessage:
    """
    Parse a full SNMP v1/v2c message: SEQUENCE { version, community, PDU {
    request-id, error-status, error-index, SEQUENCE OF varbind } }.
    Raises BERError on anything malformed -- callers should treat that as
    "not a real SNMP packet" for the noise filter.
    """
    if len(data) < 2 or data[0] != TAG_SEQUENCE:
        raise BERError("not a BER SEQUENCE")

    pos = 1
    total_len, pos = _decode_length(data, pos)
    end = pos + total_len
    if end > len(data):
        raise BERError("declared length exceeds packet size")

    top = parse_tlvs(data, pos, end)
    if len(top) < 3:
        raise BERError("SNMP message missing version/community/PDU")

    version_tlv, community_tlv, pdu_tlv = top[0], top[1], top[2]
    if version_tlv.tag != TAG_INTEGER:
        raise BERError("version field not INTEGER")
    version = decode_integer(version_tlv.value)

    if community_tlv.tag != TAG_OCTET_STRING:
        raise BERError("community field not OCTET STRING")
    community = community_tlv.value.decode("utf-8", errors="replace")

    if pdu_tlv.tag not in (PDU_GET_REQUEST, PDU_GET_NEXT_REQUEST, PDU_SET_REQUEST):
        raise BERError(f"unsupported/unexpected PDU tag {pdu_tlv.tag:#x}")

    pdu_fields = parse_tlvs(pdu_tlv.value, 0, len(pdu_tlv.value))
    if len(pdu_fields) < 4:
        raise BERError("PDU missing request-id/error-status/error-index/varbinds")

    request_id = decode_integer(pdu_fields[0].value)
    varbind_list_tlv = pdu_fields[3]
    if varbind_list_tlv.tag != TAG_SEQUENCE:
        raise BERError("varbind list not a SEQUENCE")

    varbinds = []
    for vb_tlv in parse_tlvs(varbind_list_tlv.value, 0, len(varbind_list_tlv.value)):
        if vb_tlv.tag != TAG_SEQUENCE:
            raise BERError("varbind entry not a SEQUENCE")
        vb_fields = parse_tlvs(vb_tlv.value, 0, len(vb_tlv.value))
        if len(vb_fields) < 1 or vb_fields[0].tag != TAG_OID:
            raise BERError("varbind missing OID")
        oid = decode_oid(vb_fields[0].value)
        varbinds.append((oid, None))

    return SNMPMessage(version, community, pdu_tlv.tag, request_id, varbinds)


def build_get_response(version: int, community: str, request_id: int,
                        varbinds: list[tuple[str, bytes]]) -> bytes:
    """
    varbinds: list of (oid_string, pre-encoded value TLV bytes e.g. from
    encode_octet_string/encode_integer/encode_oid).
    """
    vb_entries = [
        encode_sequence(encode_oid(oid), value_bytes)
        for oid, value_bytes in varbinds
    ]
    varbind_list = encode_sequence(*vb_entries)

    pdu = encode_pdu(
        PDU_GET_RESPONSE,
        encode_integer(request_id),
        encode_integer(0),   # error-status: noError
        encode_integer(0),   # error-index
        varbind_list,
    )

    return encode_sequence(
        encode_integer(version),
        encode_octet_string(community),
        pdu,
    )
