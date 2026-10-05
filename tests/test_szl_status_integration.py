"""
test_szl_status_integration.py
---------------------------------
The actual scenario this whole fix exists for: send PLC STOP through
block_transfer_handler.py, then issue a completely separate SZL
CPU-status read through szl_status_handler.py, and confirm the second
handler reflects the state the first one set -- proving cpu_state.py's
shared-file mechanism actually closes the gap (STOP accepted but not
reflected elsewhere) rather than just existing in isolation.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import tempfile
from pathlib import Path

import s7_header as sh
from block_transfer_handler import BlockTransferHandler
from ladder_block_store import BlockStore
from szl_status_handler import SZLStatusHandler, is_read_szl_cpu_status_request, SZL_ID_CPU_STATUS
import cpu_state


class _CollectingLogger:
    def __init__(self):
        self.events = []

    def log_event(self, session_id, peer_ip, peer_port, event_type, raw, parsed=None):
        self.events.append((event_type, parsed))


def _job_frame(pdu_ref, function_code, params_tail=b"", data=b""):
    params = bytes([function_code]) + params_tail
    return sh.ParsedFrame(
        is_s7_data=True, pdu_type=sh.PDU_TYPE_JOB_REQUEST,
        pdu_reference=pdu_ref, function_code=function_code, params=params, data=data,
    )


def _userdata_szl_status_request(pdu_ref):
    """Build a synthetic Read-SZL-for-CPU-status Userdata frame matching
    the general shape szl_status_handler.py's permissive matcher looks
    for -- parameter head + SZL ID 0x0424 present somewhere in the
    payload."""
    params = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
    data = bytes([0x00, 0x00, 0x04, 0x02]) + SZL_ID_CPU_STATUS + bytes([0x00, 0x00])
    return sh.ParsedFrame(
        is_s7_data=True, pdu_type=sh.PDU_TYPE_USERDATA,
        pdu_reference=pdu_ref, function_code=params[0], params=params, data=data,
    )


def test_matcher_recognizes_szl_status_request_and_ignores_others():
    real_request = _userdata_szl_status_request(1)
    assert is_read_szl_cpu_status_request(real_request) is True

    unrelated_userdata = sh.ParsedFrame(
        is_s7_data=True, pdu_type=sh.PDU_TYPE_USERDATA, pdu_reference=2,
        function_code=0x00, params=bytes([0x00, 0x01, 0x12, 0x04]), data=b"\x99\x99",
    )
    assert is_read_szl_cpu_status_request(unrelated_userdata) is False

    job_request = _job_frame(3, 0x04)  # ordinary read_var, wrong pdu_type entirely
    assert is_read_szl_cpu_status_request(job_request) is False
    print("SZL-status request matcher: correctly matches target, ignores others -- OK")


def test_stop_then_separate_szl_read_reflects_it():
    shared_state_path = Path(tempfile.mkdtemp()) / "cpu_state.json"

    store = BlockStore()
    logger_a = _CollectingLogger()
    block_handler = BlockTransferHandler(store, logger_a, cpu_state_path=shared_state_path)

    logger_b = _CollectingLogger()
    szl_handler = SZLStatusHandler(logger_b, cpu_state_path=shared_state_path)

    # Before any STOP: SZL read should report RUN.
    resp_before = szl_handler.handle("sB1", "10.0.0.9", 5000, _userdata_szl_status_request(10))
    parsed_before = sh.parse_frame(resp_before)
    assert parsed_before.data[-1] == 0x08, "expected RUN status byte before any STOP"
    print("SZL status read before STOP correctly reports RUN -- OK")

    # A completely separate flow: attacker sends STOP via block_transfer_handler.
    block_handler.handle("sA1", "10.0.0.9", 4999, _job_frame(20, 0x29))

    # Now the SZL handler -- a different object, standing in for a
    # different process/connection -- must reflect the change.
    resp_after = szl_handler.handle("sB2", "10.0.0.9", 5001, _userdata_szl_status_request(11))
    parsed_after = sh.parse_frame(resp_after)
    assert parsed_after.data[-1] == 0x04, "expected STOP status byte after STOP was accepted"
    print("SZL status read after STOP correctly reports STOP -- OK (gap closed)")

    status_events = [e for e in logger_b.events if e[0] == "szl_status_read"]
    assert len(status_events) == 2
    assert status_events[0][1]["reported_state"] == "RUN"
    assert status_events[1][1]["reported_state"] == "STOP"
    print("Both SZL status reads logged with correct reported_state -- OK")


def test_response_round_trips_through_own_parser():
    """Sanity check: the response we build is at least internally
    self-consistent (parses back out cleanly), even though it isn't
    independently verified against a real device's exact byte layout."""
    shared_state_path = Path(tempfile.mkdtemp()) / "cpu_state.json"
    cpu_state.write_cpu_state(cpu_state.STATE_STOP, shared_state_path)

    from szl_status_handler import build_status_response
    response = build_status_response(pdu_reference=99, state_path=shared_state_path)
    parsed = sh.parse_frame(response)

    assert parsed.pdu_type == sh.PDU_TYPE_ACK_DATA
    assert parsed.pdu_reference == 99
    assert SZL_ID_CPU_STATUS in parsed.data
    print("Status response round-trips through own parser correctly -- OK")


if __name__ == "__main__":
    test_matcher_recognizes_szl_status_request_and_ignores_others()
    test_stop_then_separate_szl_read_reflects_it()
    test_response_round_trips_through_own_parser()
    print("\nAll SZL status integration tests passed.")
