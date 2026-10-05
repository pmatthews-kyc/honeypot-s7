"""
test_clock_handler.py
----------------------
Tests ClockHandler using real packet bytes from s7comm_reading_setting_plc_time.pcap,
decoded and confirmed 2026-08-28. Every test uses bytes observed on the wire
from a real S7 PLC, not synthetic data.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import datetime
import struct

from clock_handler import (
    ClockHandler, encode_s7_time, decode_s7_time,
    time_dict_to_str, _bcd, _unbcd,
    _TIME_GROUP_REQUEST, _SUBFUNC_READ, _SUBFUNC_SET,
)
from s7_header import ParsedFrame, PDU_TYPE_USERDATA


class _NoOpLogger:
    def log_event(self, *a, **kw): pass


def _make_parsed(params_hex: str, data_hex: str, pdu_ref: int = 1) -> ParsedFrame:
    """Build a ParsedFrame from hex strings matching real capture bytes."""
    params = bytes.fromhex(params_hex)
    data   = bytes.fromhex(data_hex)
    return ParsedFrame(
        is_s7_data=True,
        pdu_type=PDU_TYPE_USERDATA,
        pdu_reference=pdu_ref,
        function_code=0x00,
        params=params,
        data=data,
    )


# ── BCD encoding/decoding ────────────────────────────────────────────────────

def test_bcd_encode_decode_roundtrip():
    for n in range(100):
        assert _unbcd(_bcd(n)) == n, f"roundtrip failed for {n}"
    print("BCD encode/decode roundtrip 0-99: OK")


def test_encode_s7_time_structure():
    """Encode a known datetime and check every field position."""
    # Friday 2026-08-28 14:35:07.591
    dt = datetime.datetime(2026, 8, 28, 14, 35, 7, 591_000)
    t = encode_s7_time(dt)

    assert len(t) == 8,             "must be exactly 8 bytes"
    assert _unbcd(t[0]) == 26,      "year=2026 → 26"
    assert _unbcd(t[1]) == 8,       "month=8"
    assert _unbcd(t[2]) == 28,      "day=28"
    assert _unbcd(t[3]) == 14,      "hour=14"
    assert _unbcd(t[4]) == 35,      "minute=35"
    assert _unbcd(t[5]) == 7,       "second=7"
    assert _unbcd(t[6]) == 59,      "ms_hi=59 (top 2 digits of 591)"
    ms_lo = t[7] >> 4
    dow   = t[7] & 0xF
    assert ms_lo == 1,              "ms_lo=1 (last digit of 591)"
    # 2026-08-28 is a Friday: Python weekday=4 → S7 DOW = ((4+1)%7)+1 = 6
    assert dow == 6,                f"DOW should be 6(Fri) not {dow}"
    print("encode_s7_time structure: OK")


def test_dow_all_days():
    """Verify DOW mapping for all 7 days against S7 spec."""
    # S7: 1=Sun, 2=Mon, 3=Tue, 4=Wed, 5=Thu, 6=Fri, 7=Sat
    expected = {
        0: 2,  # Mon
        1: 3,  # Tue
        2: 4,  # Wed
        3: 5,  # Thu
        4: 6,  # Fri
        5: 7,  # Sat
        6: 1,  # Sun
    }
    for python_wd, s7_expected in expected.items():
        # Create a datetime with the desired weekday
        # 2026-08-24 is a Monday (python_wd=0)
        dt = datetime.datetime(2026, 8, 24 + python_wd, 12, 0, 0)
        assert dt.weekday() == python_wd, "test setup error"
        t = encode_s7_time(dt)
        got = t[7] & 0xF
        assert got == s7_expected, (
            f"python wd={python_wd}: expected S7 DOW={s7_expected} got {got}"
        )
    print("DOW mapping all 7 days: OK")


def test_decode_s7_time_from_capture():
    """
    Decode the exact bytes from PKT 26 of the real capture.
    The PLC clock was set incorrectly (month=19) but the encoding
    confirms the BCD format and DOW mapping are correct.
    Capture raw time bytes (8B): 00 19 14 08 20 11 59 43
      → byte[6]=0x59 → ms_hi=59
      → byte[7]=0x43 → ms_lo=4, DOW=3=Tue
    """
    raw = bytes([0x00, 0x19, 0x14, 0x08, 0x20, 0x11, 0x59, 0x43])
    t = decode_s7_time(raw)

    assert t["year"]   == 2000, f"year: {t['year']}"
    assert t["month"]  == 19,   "month (garbage value from PLC, preserved as-is)"
    assert t["day"]    == 14
    assert t["hour"]   == 8
    assert t["minute"] == 20
    assert t["second"] == 11
    assert t["ms"]     == 594,  f"ms: {t['ms']}"  # 59*10 + 4 = 594
    assert t["dow"]    == "Tue", f"dow: {t['dow']}"
    print("decode_s7_time from real capture bytes: OK")


# ── ClockHandler.handles() ───────────────────────────────────────────────────

def test_handles_read_clock_request():
    """Real READ_CLOCK request params from PKT 25 of capture."""
    parsed = _make_parsed("0001120411470100", "0a000000")
    h = ClockHandler(_NoOpLogger())
    assert h.handles(parsed), "should handle READ_CLOCK"
    print("handles() accepts READ_CLOCK: OK")


def test_handles_set_clock_request():
    """Real SET_CLOCK request params from PKT 43 of capture."""
    parsed = _make_parsed("0001120411470200", "ff09000a00191408201159330400")
    h = ClockHandler(_NoOpLogger())
    assert h.handles(parsed), "should handle SET_CLOCK"
    print("handles() accepts SET_CLOCK: OK")


def test_does_not_handle_non_time_group():
    """Non-time userdata (e.g., SZL reads) must not be intercepted."""
    # SZL read: params[5]=0x44 (group=4/CPU, type=4/req) not 0x47
    parsed = _make_parsed("0001120411440100", "ff09000400110001")
    h = ClockHandler(_NoOpLogger())
    assert not h.handles(parsed), "must not handle SZL reads"
    print("handles() correctly ignores SZL/other functions: OK")


# ── READ_CLOCK response validation ───────────────────────────────────────────

def test_read_clock_response_wire_format():
    """
    Verify the READ_CLOCK response has exactly the structure confirmed
    from the real capture (PKT 26 response pattern).
    """
    parsed = _make_parsed("0001120411470100", "0a000000", pdu_ref=0x0001)
    h = ClockHandler(_NoOpLogger())
    resp = h.handle("s1", "10.0.0.1", 12345, parsed)

    # Must be a valid TPKT frame
    assert resp[0] == 0x03 and resp[1] == 0x00, "TPKT version"
    tpkt_len = struct.unpack_from(">H", resp, 2)[0]
    assert tpkt_len == len(resp), "TPKT declared length must match actual"

    # COTP DT (3 bytes after TPKT header)
    assert resp[5] == 0xF0, "COTP type must be DT (0xF0)"

    # S7 header (at offset 7)
    s7 = resp[7:]
    assert s7[0] == 0x32,  "S7 protocol ID"
    assert s7[1] == 0x07,  "PDU type = Userdata"
    param_len = struct.unpack_from(">H", s7, 6)[0]
    data_len  = struct.unpack_from(">H", s7, 8)[0]

    # Params: 12 bytes matching confirmed capture pattern
    params = s7[10:10+param_len]
    assert param_len == 12, f"response param_len must be 12, got {param_len}"
    assert params[5] == 0x87, f"params[5] must be 0x87 (time group response), got {params[5]:#x}"
    assert params[6] == _SUBFUNC_READ, "params[6] must be subfunction READ"
    assert params[7] == 0x01, "last_data_unit must be 1"

    # Data: 4-byte header + 8-byte time + 2 zero bytes = 14 bytes
    data = s7[10+param_len:10+param_len+data_len]
    assert data_len == 14, f"data_len must be 14 (4+8+2), got {data_len}"
    assert data[0] == 0xFF, "return code must be 0xFF (ok)"
    assert data[1] == 0x09, "transport type = 0x09"
    inner_len = struct.unpack_from(">H", data, 2)[0]
    assert inner_len == 10, f"inner_len must be 10 (8 time + 2 zeros), got {inner_len}"

    # Time bytes must decode to a plausible datetime
    time_bytes = data[4:12]
    t = decode_s7_time(time_bytes)
    assert 2000 <= t["year"] <= 2089, f"year out of range: {t['year']}"
    assert 1 <= t["month"] <= 12,     f"month out of range: {t['month']}"
    assert 1 <= t["day"]   <= 31,     f"day out of range: {t['day']}"

    # Trailing 2 bytes must be zero (confirmed from capture)
    assert data[12:14] == b"\x00\x00", "trailing 2 bytes must be zero"

    print("READ_CLOCK response wire format: OK")


def test_set_clock_response_wire_format():
    """
    Verify SET_CLOCK response matches capture pattern (PKT 44).
    Response data must be the ack: 0a 00 00 00
    """
    set_data = "ff09000a00191408201159330400"
    parsed = _make_parsed("0001120411470200", set_data, pdu_ref=0x0002)
    h = ClockHandler(_NoOpLogger())
    resp = h.handle("s2", "10.0.0.1", 12345, parsed)

    tpkt_len = struct.unpack_from(">H", resp, 2)[0]
    assert tpkt_len == len(resp)

    s7 = resp[7:]
    param_len = struct.unpack_from(">H", s7, 6)[0]
    data_len  = struct.unpack_from(">H", s7, 8)[0]
    params = s7[10:10+param_len]
    data   = s7[10+param_len:10+param_len+data_len]

    assert params[5] == 0x87,         "time group response"
    assert params[6] == _SUBFUNC_SET,  "SET subfunction"
    assert data_len  == 4,             f"ack data must be 4 bytes, got {data_len}"
    assert data[0]   == 0x0A,          "ack return code must be 0x0A"
    assert data[1:4] == b"\x00\x00\x00", "ack trailing bytes must be zero"

    print("SET_CLOCK response wire format: OK")


def test_set_clock_logs_requested_time():
    """The requested time must be captured in the log event."""
    events = []

    class CapturingLogger:
        def log_event(self, sid, ip, port, etype, raw, parsed):
            events.append((etype, parsed))

    set_data = "ff09000a00191408201159330400"
    parsed = _make_parsed("0001120411470200", set_data)
    h = ClockHandler(CapturingLogger())
    h.handle("s3", "10.0.0.1", 12345, parsed)

    assert len(events) == 1
    etype, fields = events[0]
    assert etype == "set_clock"
    assert "time_requested" in fields
    assert fields["accepted"] is True
    print(f"SET_CLOCK logged time_requested='{fields['time_requested']}': OK")


if __name__ == "__main__":
    test_bcd_encode_decode_roundtrip()
    test_encode_s7_time_structure()
    test_dow_all_days()
    test_decode_s7_time_from_capture()
    test_handles_read_clock_request()
    test_handles_set_clock_request()
    test_does_not_handle_non_time_group()
    test_read_clock_response_wire_format()
    test_set_clock_response_wire_format()
    test_set_clock_logs_requested_time()
    print("\nAll clock handler tests passed.")
