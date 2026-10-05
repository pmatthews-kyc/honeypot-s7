"""
test_block_transfer_integration.py
------------------------------------
Simulates a realistic attacker sequence entirely in-memory (no sockets
needed): Request Download -> two Download Block chunks -> Download Ended
-> Start Upload -> repeated Upload calls -> End Upload, confirming that
what gets "written" is exactly what gets served back on a later read.
This is the core behavior the whole block_transfer_handler module exists
for, so it's worth testing end-to-end rather than just unit-by-unit.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import tempfile
from pathlib import Path

import s7_header as sh
from ladder_block_store import BlockStore, BLOCK_TYPE_FC
from block_transfer_handler import BlockTransferHandler
from command_logger import CommandLogger


class _CollectingLogger(CommandLogger):
    """Swap file writes for an in-memory list so the test doesn't touch disk."""
    def __init__(self):
        self.events = []

    def log_event(self, session_id, peer_ip, peer_port, event_type, raw, parsed=None):
        self.events.append((event_type, parsed))


def _job_frame(pdu_ref, function_code, params_tail=b"", data=b""):
    params = bytes([function_code]) + params_tail
    return sh.ParsedFrame(
        is_s7_data=True,
        pdu_type=sh.PDU_TYPE_JOB_REQUEST,
        pdu_reference=pdu_ref,
        function_code=function_code,
        params=params,
        data=data,
    )


def test_full_download_then_upload_sequence():
    store = BlockStore()
    logger = _CollectingLogger()
    cpu_state_path = Path(tempfile.mkdtemp()) / "cpu_state.json"
    handler = BlockTransferHandler(store, logger, cpu_state_path=cpu_state_path)

    session_id = "test-session-1"
    peer = ("10.0.0.99", 55123)

    attacker_payload = b"MALICIOUS_LOGIC_PAYLOAD_" + bytes(range(50))

    # 1. Request Download for FC99
    req = _job_frame(1, 0x1A, params_tail=b"FC99")
    resp = handler.handle(session_id, *peer, req)
    assert sh.parse_frame(resp).pdu_type == sh.PDU_TYPE_ACK_DATA

    # 2. Download Block, in two chunks (simulating PDU-size fragmentation)
    chunk1, chunk2 = attacker_payload[:30], attacker_payload[30:]
    handler.handle(session_id, *peer, _job_frame(2, 0x1B, data=chunk1))
    handler.handle(session_id, *peer, _job_frame(3, 0x1B, data=chunk2))

    # 3. Download Ended -- commits into the block store
    handler.handle(session_id, *peer, _job_frame(4, 0x1C))

    block_type, number = 0x43, 99  # FC99
    stored = store.get_block(block_type, number)
    assert stored is not None, "block should exist after download_ended commit"
    assert stored.content == attacker_payload, "committed content must match exactly what was sent"
    print("Download + commit: content matches exactly what attacker sent -- OK")

    # 4. Now a (possibly different) session reads it back via upload
    session_id_2 = "test-session-2"
    handler.handle(session_id_2, *peer, _job_frame(5, 0x1D, params_tail=b"FC99"))

    collected = b""
    for pdu_ref in range(6, 20):
        resp = handler.handle(session_id_2, *peer, _job_frame(pdu_ref, 0x1E))
        parsed_resp = sh.parse_frame(resp)
        if not parsed_resp.data:
            break
        collected += parsed_resp.data

    handler.handle(session_id_2, *peer, _job_frame(20, 0x1F))

    assert collected == attacker_payload, (
        f"uploaded content must match what was downloaded -- "
        f"got {len(collected)} bytes, want {len(attacker_payload)}"
    )
    print("Upload readback: served content matches exactly what was committed -- OK")

    # Confirm the critical commit event was logged
    critical_events = [e for e in logger.events if e[0] == "block_download_committed"]
    assert len(critical_events) == 1
    assert critical_events[0][1]["total_bytes"] == len(attacker_payload)
    print("block_download_committed event logged with correct size -- OK")


def test_plc_stop_accepted_no_auth():
    store = BlockStore()
    logger = _CollectingLogger()
    cpu_state_path = Path(tempfile.mkdtemp()) / "cpu_state.json"
    handler = BlockTransferHandler(store, logger, cpu_state_path=cpu_state_path)

    assert handler._cpu_state == "RUN", "should default to RUN before any STOP is sent"

    resp = handler.handle("s3", "10.0.0.50", 12345, _job_frame(1, 0x29))
    parsed = sh.parse_frame(resp)
    assert parsed.pdu_type == sh.PDU_TYPE_ACK_DATA

    stop_events = [e for e in logger.events if e[0] == "plc_stop_attempt"]
    assert len(stop_events) == 1
    assert stop_events[0][1]["accepted"] is True
    assert stop_events[0][1]["state_transition"] == "RUN → STOP"
    assert handler._cpu_state == "STOP"
    print("PLC STOP accepted with no auth check, state_transition logged -- OK")


def test_plc_control_start_accepted_and_logged():
    """PLC Control (warm restart) should be logged as plc_start_attempt,
    not the old vague plc_control_attempt, and at CRITICAL level."""
    import struct
    store = BlockStore()
    logger = _CollectingLogger()
    cpu_state_path = Path(tempfile.mkdtemp()) / "cpu_state.json"
    handler = BlockTransferHandler(store, logger, cpu_state_path=cpu_state_path)

    # First put it in STOP state
    handler.handle("s3", "10.0.0.50", 12345, _job_frame(1, 0x29))
    assert handler._cpu_state == "STOP"

    # Now send a warm restart (WDIETIMER PI service)
    service = b"WDIETIMER"
    pi_params = bytes([0x28, 0x00]) + struct.pack(">H", len(service)) + service

    frame = sh.ParsedFrame(
        is_s7_data=True, pdu_type=sh.PDU_TYPE_JOB_REQUEST,
        pdu_reference=99, function_code=0x28,
        params=pi_params, data=b"",
    )
    resp = handler.handle("s3", "10.0.0.50", 12345, frame)
    parsed_resp = sh.parse_frame(resp)
    assert parsed_resp.pdu_type == sh.PDU_TYPE_ACK_DATA

    start_events = [e for e in logger.events if e[0] == "plc_start_attempt"]
    assert len(start_events) == 1, f"Expected plc_start_attempt event, got: {[e[0] for e in logger.events]}"
    detail = start_events[0][1]
    assert detail["pi_service"] == "WDIETIMER"
    assert detail["pi_service_meaning"] == "warm_restart"
    assert detail["state_transition"] == "STOP → RUN"
    assert detail["cpu_state_after"] == "RUN"
    assert handler._cpu_state == "RUN"
    print("PLC Control warm restart logged as plc_start_attempt with STOP→RUN transition -- OK")


def test_cpu_state_visible_across_separate_handler_instances():
    """The whole point of moving cpu_state to a shared file: a SECOND,
    independent BlockTransferHandler instance (standing in for a
    different process, e.g. the web portal or SZL-status handler reading
    the same file) must see the STOP written by the first instance."""
    store = BlockStore()
    logger = _CollectingLogger()
    shared_path = Path(tempfile.mkdtemp()) / "cpu_state.json"

    handler_a = BlockTransferHandler(store, logger, cpu_state_path=shared_path)
    handler_b = BlockTransferHandler(store, logger, cpu_state_path=shared_path)

    assert handler_a._cpu_state == "RUN"
    assert handler_b._cpu_state == "RUN"

    handler_a.handle("s4", "10.0.0.60", 11111, _job_frame(1, 0x29))

    assert handler_a._cpu_state == "STOP"
    assert handler_b._cpu_state == "STOP", "second instance must see the state change via the shared file"
    print("CPU state correctly shared across independent handler instances -- OK")


def test_plc_control_resets_state_to_run():
    store = BlockStore()
    logger = _CollectingLogger()
    shared_path = Path(tempfile.mkdtemp()) / "cpu_state.json"
    handler = BlockTransferHandler(store, logger, cpu_state_path=shared_path)

    handler.handle("s5", "10.0.0.70", 22222, _job_frame(1, 0x29))  # STOP
    assert handler._cpu_state == "STOP"

    handler.handle("s5", "10.0.0.70", 22222, _job_frame(2, 0x28))  # PLC Control
    assert handler._cpu_state == "RUN"

    # New: verify it's logged as plc_start_attempt, not plc_control_attempt
    start_events = [e for e in logger.events if e[0] == "plc_start_attempt"]
    assert len(start_events) == 1, "PLC Control should be logged as plc_start_attempt"
    print("PLC Control correctly resets state to RUN and logs plc_start_attempt -- OK")


if __name__ == "__main__":
    test_full_download_then_upload_sequence()
    test_plc_stop_accepted_no_auth()
    test_plc_control_start_accepted_and_logged()
    test_cpu_state_visible_across_separate_handler_instances()
    test_plc_control_resets_state_to_run()
    print("\nAll block transfer integration tests passed.")
