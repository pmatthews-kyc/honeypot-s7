"""
test_ber_roundtrip.py
----------------------
No SNMP client available in this build environment to test against
live, so this exercises the encoder/decoder against itself: build a
synthetic GetRequest the way a real SNMP client would, parse it with
parse_snmp_message, then build and re-parse a GetResponse. Run this
after any change to ber.py, and ideally also validate for real with
`snmpget -v2c -c <community> <host> 1.3.6.1.2.1.1.1.0` from another
machine once deployed.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import ber


def build_synthetic_get_request(community: str, request_id: int, oid: str) -> bytes:
    varbind = ber.encode_sequence(ber.encode_oid(oid), ber.encode_null())
    varbind_list = ber.encode_sequence(varbind)
    pdu = ber.encode_pdu(
        ber.PDU_GET_REQUEST,
        ber.encode_integer(request_id),
        ber.encode_integer(0),
        ber.encode_integer(0),
        varbind_list,
    )
    return ber.encode_sequence(
        ber.encode_integer(1),  # v2c
        ber.encode_octet_string(community),
        pdu,
    )


def test_get_request_roundtrip():
    raw = build_synthetic_get_request("public", 12345, "1.3.6.1.2.1.1.1.0")
    msg = ber.parse_snmp_message(raw)
    assert msg.version == 1
    assert msg.community == "public"
    assert msg.pdu_tag == ber.PDU_GET_REQUEST
    assert msg.request_id == 12345
    assert msg.varbinds == [("1.3.6.1.2.1.1.1.0", None)]
    print("GetRequest round-trip: OK")


def test_get_response_build_and_reparse():
    varbinds = [
        ("1.3.6.1.2.1.1.1.0", ber.encode_octet_string("SIMATIC 300(1) CPU 315-2 PN/DP")),
        ("1.3.6.1.2.1.1.2.0", ber.encode_oid("1.3.6.1.4.1.4196.1.1.5.2.9")),
    ]
    raw = ber.build_get_response(1, "public", 999, varbinds)

    # Re-parse it as if we were the client -- build_get_response emits a
    # GetResponse (0xA2) PDU, which parse_snmp_message currently only
    # accepts request-side tags for, so decode manually here instead.
    assert raw[0] == ber.TAG_SEQUENCE
    top = ber.parse_tlvs(raw, 2, len(raw))
    assert top[0].tag == ber.TAG_INTEGER
    assert ber.decode_integer(top[0].value) == 1
    assert top[1].value == b"public"
    assert top[2].tag == ber.PDU_GET_RESPONSE

    pdu_fields = ber.parse_tlvs(top[2].value, 0, len(top[2].value))
    assert ber.decode_integer(pdu_fields[0].value) == 999  # request-id echoed
    assert ber.decode_integer(pdu_fields[1].value) == 0    # error-status

    varbind_list = ber.parse_tlvs(pdu_fields[3].value, 0, len(pdu_fields[3].value))
    assert len(varbind_list) == 2

    first_vb = ber.parse_tlvs(varbind_list[0].value, 0, len(varbind_list[0].value))
    assert ber.decode_oid(first_vb[0].value) == "1.3.6.1.2.1.1.1.0"
    assert first_vb[1].value == b"SIMATIC 300(1) CPU 315-2 PN/DP"

    print("GetResponse build+reparse: OK")


def test_oid_roundtrip():
    for oid in ["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.4196.1.1.5.2.9", "1.3.6.1.2.1.4.20.1.1.192.168.1.50"]:
        encoded = ber.encode_oid(oid)
        # encode_oid emits a full TLV (tag+len+value) -- decode_oid expects
        # just the value bytes, so strip the TLV header for this check.
        tag = encoded[0]
        assert tag == ber.TAG_OID
        length, pos = ber._decode_length(encoded, 1)
        value = encoded[pos:pos + length]
        decoded = ber.decode_oid(value)
        assert decoded == oid, f"OID round-trip mismatch: {oid} -> {decoded}"
    print("OID round-trip: OK")


def test_timeticks_type_tag():
    encoded = ber.encode_timeticks(123456)
    assert encoded[0] == ber.TAG_TIMETICKS, "sysUpTime must use TimeTicks tag, not INTEGER"
    print("TimeTicks tag check: OK")


if __name__ == "__main__":
    test_oid_roundtrip()
    test_get_request_roundtrip()
    test_get_response_build_and_reparse()
    test_timeticks_type_tag()
    print("\nAll BER self-tests passed.")
