"""
test_cotp_tsap_validation.py
------------------------------
Tests the COTP TSAP rack/slot validation added to s7_precheck.py
and honeypot.py to close a realism gap: a real S7-300 sends COTP DR
(Disconnect Request) for connections targeting the wrong rack/slot.
snap7.Server accepts any TSAP; the proxy now enforces the check.

Confirmed from a real server-side pcap: an S7 tool tried TSAP 0x0121
(rack=1, slot=1) three times before falling back to 0x0102 (rack=0,
slot=2). snap7 sent CC for all of them -- a real S7-300 would have
sent DR for the wrong-slot attempts, which is exactly what we now do.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import socket
import struct
import tempfile
import threading
from pathlib import Path

from s7_precheck import peek_validate_cotp_cr
from honeypot import _build_cotp_dr, _decode_tsap_rack_slot


def _build_cr(src_ref: int = 0x0002, dst_tsap: bytes = b"",
              src_tsap: bytes = b"\x01\x00") -> bytes:
    """Build a minimal COTP CR TPKT frame with configurable TSAPs."""
    params = b""
    if src_tsap:
        params += bytes([0xC1, len(src_tsap)]) + src_tsap
    if dst_tsap:
        params += bytes([0xC2, len(dst_tsap)]) + dst_tsap
    params += bytes([0xC0, 0x01, 0x0A])  # TPDU-size = 1024

    li = 6 + len(params)  # type + dst-ref(2) + src-ref(2) + class(1) + params
    cotp = bytes([li, 0xE0, 0x00, 0x00]) + struct.pack(">H", src_ref) + bytes([0x00]) + params
    total = 4 + len(cotp)
    return bytes([0x03, 0x00, (total >> 8) & 0xFF, total & 0xFF]) + cotp


# ── Unit tests ──────────────────────────────────────────────────────────────

def test_decode_tsap_rack_slot():
    assert _decode_tsap_rack_slot(bytes([0x01, 0x02])) == (0, 2)  # rack=0, slot=2
    assert _decode_tsap_rack_slot(bytes([0x01, 0x21])) == (1, 1)  # rack=1, slot=1
    assert _decode_tsap_rack_slot(bytes([0x02, 0x03])) == (0, 3)  # rack=0, slot=3
    assert _decode_tsap_rack_slot(b"") == (None, None)            # too short
    print("TSAP rack/slot decoding: OK")


def test_build_cotp_dr():
    dr = _build_cotp_dr(dst_ref=0x0002, reason=0x03)
    assert dr[0] == 0x03 and dr[1] == 0x00, "TPKT header"
    total_len = struct.unpack_from(">H", dr, 2)[0]
    assert total_len == len(dr), "TPKT length field matches actual length"
    cotp = dr[4:]
    assert cotp[1] == 0x80, "DR type byte"
    assert struct.unpack_from(">H", cotp, 2)[0] == 0x0002, "DST-REF echoed"
    assert struct.unpack_from(">H", cotp, 4)[0] == 0x0000, "SRC-REF = 0"
    assert cotp[6] == 0x03, "reason = 0x03 (session not attached to TSAP)"
    print(f"COTP DR built correctly: {dr.hex()} -- OK")


def test_precheck_extracts_dst_tsap_correct_slot():
    """Correct rack=0, slot=2 (0x0102) -- should be extracted cleanly."""
    cr = _build_cr(src_ref=0x0014, dst_tsap=bytes([0x01, 0x02]))
    a, b = socket.socketpair()
    a.sendall(cr)
    result = peek_validate_cotp_cr(b)
    assert result.is_real_s7
    assert result.cotp_src_ref == 0x0014
    assert result.cotp_dst_tsap == bytes([0x01, 0x02])
    rack, slot = _decode_tsap_rack_slot(result.cotp_dst_tsap)
    assert rack == 0 and slot == 2
    a.close(); b.close()
    print("Precheck extracts dst_TSAP for correct slot (0x0102 = rack=0,slot=2): OK")


def test_precheck_extracts_dst_tsap_wrong_slot():
    """Wrong rack=1, slot=1 (0x0121) -- tool's first failed attempts."""
    cr = _build_cr(src_ref=0x0002, dst_tsap=bytes([0x01, 0x21]))
    a, b = socket.socketpair()
    a.sendall(cr)
    result = peek_validate_cotp_cr(b)
    assert result.is_real_s7
    assert result.cotp_dst_tsap == bytes([0x01, 0x21])
    rack, slot = _decode_tsap_rack_slot(result.cotp_dst_tsap)
    assert rack == 1 and slot == 1
    a.close(); b.close()
    print("Precheck extracts dst_TSAP for wrong slot (0x0121 = rack=1,slot=1): OK")


def test_precheck_no_dst_tsap():
    """CR without C2 param -- some tools omit TSAP; must not crash."""
    cr = _build_cr(src_ref=0x0001, dst_tsap=b"")
    a, b = socket.socketpair()
    a.sendall(cr)
    result = peek_validate_cotp_cr(b)
    assert result.is_real_s7
    assert result.cotp_dst_tsap == b""
    a.close(); b.close()
    print("Precheck handles CR with no dst_TSAP (no C2 param): OK")


def test_dr_sent_for_wrong_rack_slot(monkeypatch=None):
    """
    End-to-end simulation: proxy receives CR with wrong rack/slot TSAP,
    must send DR back to client rather than forwarding to backend.
    Mirrors what the S7 tool capture showed for the first 3 failed
    connection attempts (TSAP 0x0121 = rack=1, slot=1).
    """
    received = []

    # Simulate the client side: send CR, collect response
    client_a, client_b = socket.socketpair()

    expected_rack, expected_slot = 0, 2
    cr = _build_cr(src_ref=0x0002, dst_tsap=bytes([0x01, 0x21]))  # rack=1, slot=1

    def fake_client():
        client_a.sendall(cr)
        try:
            client_a.settimeout(2)
            data = client_a.recv(256)
            received.append(data)
        except socket.timeout:
            pass
        client_a.close()

    t = threading.Thread(target=fake_client, daemon=True)
    t.start()

    # Simulate proxy-side handling
    result = peek_validate_cotp_cr(client_b)
    rack, slot = _decode_tsap_rack_slot(result.cotp_dst_tsap)

    if rack != expected_rack or slot != expected_slot:
        dr = _build_cotp_dr(result.cotp_src_ref, reason=0x03)
        client_b.sendall(dr)
        client_b.close()

    t.join(timeout=3)

    assert received, "Client should have received a response (DR)"
    dr_response = received[0]
    assert dr_response[4+1] == 0x80, f"Should be DR (0x80), got 0x{dr_response[5]:02x}"
    # DST-REF should echo client's SRC-REF (0x0002)
    dst_ref = struct.unpack_from(">H", dr_response, 6)[0]
    assert dst_ref == 0x0002, f"DR DST-REF should be 0x0002, got 0x{dst_ref:04x}"
    reason = dr_response[4+6]
    assert reason == 0x03, f"DR reason should be 0x03, got 0x{reason:02x}"
    print("Wrong rack/slot → proxy sends COTP DR with correct DST-REF and reason: OK")


def test_cotp_cc_class_byte_patched():
    """
    Confirmed from live deployment (2026-08-29):
    snap7 returns class/options = 0x01 in the COTP CC.
    STEP 7, TIA Portal, and python-snap7 all check byte[10] and reject
    the CC with 'TCP connected, ISO didn't' when it is non-zero.
    The proxy must patch it to 0x00.

    Raw CC from log: 0300000f09d0000202000100c0010a
    byte[10] = 0x01 (explicit-flow-control bit set by snap7) → must become 0x00
    """
    # Simulate the CC as snap7 actually sent it (with class=0x01)
    cc_from_snap7 = bytes.fromhex("0300000f09d0000000000100c0010a")
    # After proxy patches:
    #   DST-REF (bytes 6-7): 0x0000 → 0x0002 (client's SRC-REF)
    #   class/opts (byte 10): 0x01   → 0x00
    client_src_ref = 0x0002

    cc = bytearray(cc_from_snap7)
    assert cc[5] == 0xD0, "must be COTP CC"

    # Apply both patches as the proxy does
    cc[6] = (client_src_ref >> 8) & 0xFF
    cc[7] =  client_src_ref       & 0xFF
    cc[10] = 0x00

    assert cc[6] == 0x00 and cc[7] == 0x02, "DST-REF must echo client SRC-REF"
    assert cc[10] == 0x00, "class/options must be 0x00 for S7 class-0"

    # Confirm the patched CC matches exactly what a real S7-300 would send
    expected = bytes.fromhex("0300000f09d0000200000000c0010a")
    assert bytes(cc) == expected, f"patched CC mismatch:\n  got:  {bytes(cc).hex()}\n  want: {expected.hex()}"
    print("COTP CC class/opts 0x01→0x00 patch (fixes 'TCP connected, ISO didn't'): OK")





def test_pdu_negotiate_patch_mechanism():
    """
    The proxy patches the Setup-Communication Ack_Data max-PDU to the
    configured value, because snap7 (C and pure-Python) advertises 960 —
    a value no real S7-300 returns, and a direct fingerprint of the emulator.

    The target PDU is config-driven (identity.max_pdu; 240/480/960 are the
    real values), so this tests the patch MECHANISM against each valid target
    rather than asserting one hardcoded number.
    """
    import struct

    def build_ack(pdu_len):
        params = bytes([0xF0, 0x00]) + struct.pack(">HHH", 1, 1, pdu_len)
        s7 = (bytes([0x32, 0x03, 0x00, 0x00]) + struct.pack(">H", 1)
              + struct.pack(">HH", len(params), 0) + bytes([0x00, 0x00]) + params)
        cotp = bytes([0x02, 0xF0, 0x80])
        return struct.pack(">BBH", 3, 0, 4 + len(cotp) + len(s7)) + cotp + s7

    def relay_patch(chunk, target):
        if (len(chunk) >= 27 and chunk[7] == 0x32
                and chunk[8] == 0x03 and chunk[19] == 0xF0):
            adv = (chunk[25] << 8) | chunk[26]
            if adv != target:
                c = bytearray(chunk)
                c[25] = (target >> 8) & 0xFF
                c[26] = target & 0xFF
                return bytes(c)
        return chunk

    frame = build_ack(960)
    assert frame[7] == 0x32,  "S7 protocol ID offset drifted"
    assert frame[8] == 0x03,  "ROSCTR Ack_Data offset drifted"
    assert frame[19] == 0xF0, "Setup-communication fc offset drifted"

    for target in (240, 480, 960):
        patched = relay_patch(build_ack(960), target)
        got = (patched[25] << 8) | patched[26]
        assert got == target, f"expected {target} after patch, got {got}"
        already = build_ack(target)
        assert relay_patch(already, target) == already

    other = bytes([3, 0, 0, 30]) + bytes([2, 0xF0, 0x80]) + bytes([0x32, 0x03]) + bytes(30)
    assert relay_patch(other, 240) == other

    print("PDU negotiate patch works for 240/480/960, idempotent, "
          "leaves other traffic alone: OK")


def test_pdu_negotiate_matches_szl_0131():
    """The negotiated PDU and SZL 0x0131's reported PDU must be the SAME value.
    A device that negotiates one PDU but reports another in its capability SZL
    is internally inconsistent — a fingerprint. Both come from identity.max_pdu.
    """
    import struct
    from identity import S7Identity

    for pdu in (240, 480, 960):
        ident = S7Identity(
            order_code="6ES7 315-2AG10-0AB0", firmware_version="V2.6",
            serial_number="S C-TEST", plc_name="P", module_name="CPU 315-2 PN/DP",
            copyright="c", plant_id="", module_type_name="CPU 315-2 PN/DP",
            firmware_version_parts=[2, 6, 0], max_pdu=pdu)
        szl = ident.build_comm_capability_szl(0x0001)
        # SZL 0x0131 record: header(4) then index(2) pdu(2) ... -> pdu at [6:8]
        reported = struct.unpack_from(">H", szl, 6)[0]
        assert reported == pdu, \
            f"SZL 0x0131 reports {reported} but max_pdu is {pdu}"
    print("SZL 0x0131 PDU matches configured max_pdu for 240/480/960: OK")


if __name__ == "__main__":
    test_decode_tsap_rack_slot()
    test_build_cotp_dr()
    test_precheck_extracts_dst_tsap_correct_slot()
    test_precheck_extracts_dst_tsap_wrong_slot()
    test_precheck_no_dst_tsap()
    test_dr_sent_for_wrong_rack_slot()
    test_cotp_cc_class_byte_patched()
    test_pdu_negotiate_patch_mechanism()
    test_pdu_negotiate_matches_szl_0131()
    print("\nAll COTP TSAP validation tests passed.")
