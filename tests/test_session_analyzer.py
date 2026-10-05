"""
test_session_analyzer.py
--------------------------
Tests session_analyzer.py classifications against synthetic JSONL data
representing four distinct session patterns. No real log file needed --
we write a temporary JSONL and read it back.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import json
import tempfile
import time
from pathlib import Path

from session_analyzer import load_sessions


def _event(session_id, peer_ip, peer_port, event_type, ts,
           parsed=None, raw_hex="00") -> dict:
    return {
        "ts": ts,
        "session_id": session_id,
        "peer_ip": peer_ip,
        "peer_port": peer_port,
        "event_type": event_type,
        "parsed": parsed or {},
        "raw_hex": raw_hex,
        "raw_len": len(bytes.fromhex(raw_hex)),
    }


def _s7_read(session_id, peer_ip, peer_port, ts, db, address, fn_name="read_var"):
    return _event(session_id, peer_ip, peer_port, "s7_request", ts, parsed={
        "function_name": fn_name,
        "function_code": 0x04,
        "item_count": 1,
        "items": [{"address": address, "db": db, "type": "REAL",
                   "area": "Data Block (DB)", "byte_address": 26,
                   "bit_address": 0, "count": 1}],
    })


def _s7_write(session_id, peer_ip, peer_port, ts, db, address):
    return _event(session_id, peer_ip, peer_port, "s7_request", ts, parsed={
        "function_name": "write_var",
        "function_code": 0x05,
        "item_count": 1,
        "items": [{"address": address, "db": db, "type": "REAL",
                   "area": "Data Block (DB)", "byte_address": 26,
                   "bit_address": 0, "count": 1,
                   "data_hex": "43f6e979", "value": 493.825}],
    })


def _plc_stop(session_id, peer_ip, peer_port, ts):
    return _event(session_id, peer_ip, peer_port, "plc_stop_attempt", ts, parsed={
        "function": "plc_stop", "accepted": True,
        "cpu_state_after": "STOP",
        "state_transition": "RUN → STOP",
    })


def _szl_read(session_id, peer_ip, peer_port, ts):
    return _event(session_id, peer_ip, peer_port, "s7_request", ts, parsed={
        "function_name": "szl_status_read",
        "function_code": 0x00,
    })


def build_test_log(tmp_path: Path) -> Path:
    now = time.time()
    events = []

    # === Session 1: TARGETED ===
    # Specific DB reads, a write, then PLC STOP -- classic attack sequence
    s1, ip1 = "targeted_session_001", "10.10.10.99"
    events.extend([
        _event(s1, ip1, 45001, "connect", now),
        _s7_read(s1, ip1, 45001, now + 1.2, 500, "DB500.DBD26"),
        _s7_read(s1, ip1, 45001, now + 2.8, 500, "DB500.DBW16"),
        _s7_read(s1, ip1, 45001, now + 5.1, 501, "DB501.DBD26"),
        _s7_write(s1, ip1, 45001, now + 8.5, 500, "DB500.DBD26"),
        _plc_stop(s1, ip1, 45001, now + 12.0),
        _event(s1, ip1, 45001, "disconnect", now + 12.5),
    ])

    # === Session 2: FUZZER ===
    # Machine-consistent 50ms intervals, sweeps all function codes
    s2, ip2 = "fuzzer_session_002", "192.168.50.77"
    base = now + 0
    for i, fn in enumerate(["read_var", "write_var", "request_download",
                             "start_upload", "cpu_services", "szl_status_read"]):
        t = base + i * 0.05   # 50ms apart -- very machine-consistent
        events.append(_event(s2, ip2, 31337, "s7_request", t, parsed={
            "function_name": fn, "function_code": [4, 5, 0x1a, 0x1d, 0, 0][i],
        }))
    # Add 20 more rapid reads to bump up rate
    for i in range(20):
        t = base + 6 * 0.05 + i * 0.05
        events.append(_s7_read(s2, ip2, 31337, t, i % 50, f"DB{i % 50}.DBB0"))
    events.append(_event(s2, ip2, 31337, "disconnect", base + 26 * 0.05))

    # === Session 3: SCANNER ===
    # SZL identity reads at human pace, no writes, no critical events
    s3, ip3 = "scanner_session_003", "172.16.0.200"
    events.extend([
        _event(s3, ip3, 55555, "connect", now + 100),
        _szl_read(s3, ip3, 55555, now + 101.2),
        _s7_read(s3, ip3, 55555, now + 102.5, None, None, fn_name="cpu_services"),
        _s7_read(s3, ip3, 55555, now + 104.0, None, None, fn_name="cpu_services"),
        _event(s3, ip3, 55555, "disconnect", now + 105.0),
    ])

    # === Session 4: UNKNOWN ===
    # Very short, just connect + one request + disconnect
    s4, ip4 = "unknown_session_004", "203.0.113.1"
    events.extend([
        _event(s4, ip4, 12345, "connect", now + 200),
        _s7_read(s4, ip4, 12345, now + 200.5, 1, "DB1.DBD0"),
        _event(s4, ip4, 12345, "disconnect", now + 201.0),
    ])

    log_path = tmp_path / "commands.jsonl"
    with log_path.open("w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    return log_path


def test_targeted_session_detected():
    with tempfile.TemporaryDirectory() as d:
        log = build_test_log(Path(d))
        sessions = load_sessions(log, min_requests=1)
        targeted = [s for s in sessions if s.session_id == "targeted_session_001"]
        assert len(targeted) == 1
        s = targeted[0]
        assert s.classification == "targeted", f"Expected targeted, got {s.classification}"
        assert s.has_critical, "Should have detected the PLC STOP as critical"
        assert 500 in s.dbs_written, "DB500 write should be recorded"
        print(f"Targeted session: {s.classification} [{s.confidence}] -- OK")


def test_fuzzer_session_detected():
    with tempfile.TemporaryDirectory() as d:
        log = build_test_log(Path(d))
        sessions = load_sessions(log, min_requests=1)
        fuzzers = [s for s in sessions if s.session_id == "fuzzer_session_002"]
        assert len(fuzzers) == 1
        s = fuzzers[0]
        assert s.classification == "fuzzer", f"Expected fuzzer, got {s.classification}"
        assert s.request_rate > 5.0, f"Rate too low: {s.request_rate:.1f} rps"
        print(f"Fuzzer session: {s.classification} [{s.confidence}] "
              f"rate={s.request_rate:.1f}rps -- OK")


def test_scanner_session_detected():
    with tempfile.TemporaryDirectory() as d:
        log = build_test_log(Path(d))
        sessions = load_sessions(log, min_requests=1)
        scanners = [s for s in sessions if s.session_id == "scanner_session_003"]
        assert len(scanners) == 1
        s = scanners[0]
        assert s.classification == "scanner", f"Expected scanner, got {s.classification}"
        assert not s.has_critical
        assert not s.has_writes
        print(f"Scanner session: {s.classification} [{s.confidence}] -- OK")


def test_priority_order_targeted_first():
    """Targeted sessions must appear first in the sorted output."""
    with tempfile.TemporaryDirectory() as d:
        log = build_test_log(Path(d))
        sessions = load_sessions(log, min_requests=1)
        assert sessions[0].classification == "targeted", \
            "First session in sorted output should always be targeted"
        print("Priority ordering (targeted first): OK")


def test_jsonl_malformed_lines_skipped():
    """A single malformed JSON line must not crash the loader."""
    with tempfile.TemporaryDirectory() as d:
        log_path = Path(d) / "commands.jsonl"
        log_path.write_text(
            '{"session_id":"s1","peer_ip":"1.2.3.4","peer_port":100,'
            '"event_type":"connect","ts":1000.0,"parsed":{},"raw_hex":"00","raw_len":1}\n'
            'NOT VALID JSON\n'
            '{"session_id":"s1","peer_ip":"1.2.3.4","peer_port":100,'
            '"event_type":"disconnect","ts":1001.0,"parsed":{},"raw_hex":"00","raw_len":1}\n'
        )
        import io, sys
        # Should not raise -- malformed lines are warned and skipped
        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        sessions = load_sessions(log_path, min_requests=0)
        sys.stderr = old_stderr
        assert "malformed" in captured.getvalue(), "Should warn about malformed line"
        print("Malformed JSONL lines skipped gracefully: OK")


if __name__ == "__main__":
    test_targeted_session_detected()
    test_fuzzer_session_detected()
    test_scanner_session_detected()
    test_priority_order_targeted_first()
    test_jsonl_malformed_lines_skipped()
    print("\nAll session analyzer tests passed.")
