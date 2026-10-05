"""
command_logger.py
------------------
Structured, append-only JSON-lines logging of every parsed S7 request the
honeypot receives, keyed by session_id so each log line can be cross-
referenced against the matching pcap from capture_manager.py to reconstruct
full payloads later.

This logs the *parsed* view (function code, area, address, SZL ID, etc.)
alongside the raw hex payload -- parsed fields make the log greppable/
queryable, raw hex makes it possible to rebuild anything the parser didn't
fully understand (which matters for reverse-engineering novel/malformed
payloads, i.e. exactly the case you care about).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any


class CommandLogger:
    def __init__(self, jsonl_path: str):
        path = Path(jsonl_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path

    def log_event(
        self,
        session_id: str,
        peer_ip: str,
        peer_port: int,
        event_type: str,
        raw_payload: bytes,
        parsed: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "ts": time.time(),
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session_id": session_id,
            "peer_ip": peer_ip,
            "peer_port": peer_port,
            "event_type": event_type,      # e.g. "connect", "s7_request", "disconnect"
            "parsed": parsed or {},
            "raw_hex": raw_payload.hex(),
            "raw_len": len(raw_payload),
        }
        with self._path.open("a") as f:
            f.write(json.dumps(record) + "\n")

        # Log S7 reads of process data (DB200) to the SQLite diagnostic buffer.
        # Only for s7_request events with function_code 0x04 (read_variable).
        # Rate-limited per (peer_ip, db_number) in diag_log.log_s7_read().
        if event_type == "s7_request" and parsed:
            fc = parsed.get("function_code")
            if fc == 0x04:
                self._log_s7_db_read(peer_ip, parsed)

    def _log_s7_db_read(self, peer_ip: str, parsed: dict) -> None:
        """Log DB200 reads to the diagnostic buffer showing current process values."""
        try:
            import json as _json
            from pathlib import Path as _Path
            # Determine which DB was read from parsed params if available
            db_number = parsed.get("db_number", 200)
            if db_number not in (200, 121, 300):
                return   # only log reads of interesting process DBs

            # Load current process values for context
            from paths import Paths
            state_path = Paths.load().process_state
            snapshot = None
            if state_path.exists():
                try:
                    data = _json.loads(state_path.read_text())
                    tags = data.get("tags", {})
                    snapshot = {
                        "db200_temperature": tags.get("db200_temperature", 0),
                        "db200_flow":        tags.get("db200_flow", 0),
                        "db200_level":       tags.get("db200_level", 0),
                        "cpu_state":         data.get("cpu_state", "RUN"),
                    }
                except Exception:
                    pass

            import diag_log as _dl
            _dl.log_s7_read(peer_ip, db_number, snapshot)
        except Exception:
            pass   # never let diagnostic logging break the command logger


def parse_s7_function(payload: bytes) -> dict[str, Any]:
    """
    DEPRECATED / SUPERSEDED: this fragile fixed-offset parser (guessing
    the S7 header starts at byte 17, which only happens to be right for
    a job-request frame with a 2-byte COTP length indicator) has been
    replaced by s7_header.py's proper TPKT+COTP+S7 frame parser, which
    computes offsets correctly from the actual COTP length-indicator
    field instead of assuming it. honeypot.py now uses s7_header.parse_frame
    directly rather than this function.

    Left in place only for any external scripts that may have imported
    it directly -- new code should use s7_header.parse_frame instead.
    """
    result: dict[str, Any] = {}
    if len(payload) < 2:
        result["note"] = "payload too short to parse S7 header"
        return result

    result["s7_pdu_type"] = payload[1]

    if len(payload) >= 18:
        function_code = payload[17]
        result["function_code"] = function_code
        known = {
            0x04: "read_var",
            0x05: "write_var",
            0x1A: "request_download",
            0x1B: "download_block",
            0x1C: "download_ended",
            0x1D: "start_upload",
            0x1E: "upload",
            0x1F: "end_upload",
            0x28: "plc_control",       # includes STOP
            0x29: "plc_stop",
            0x00: "cpu_services / szl_read (via param sub-function)",
        }
        result["function_name"] = known.get(function_code, "unknown")

    return result
