"""
block_transfer_handler.py
---------------------------
Handles S7 block-transfer and PLC-control function codes with the same
authentication posture a real, unprotected S7-300 has: none. Every
request is accepted -- this is deliberate, not a bug: modeling "S7-300
has no protocol-level auth on program upload/download or STOP" is the
whole point (see conversation -- this is the mechanism Stuxnet used).

Function codes handled:
    0x1A  Request Download
    0x1B  Download Block
    0x1C  Download Ended      -- committed to block store; logged CRITICAL
    0x1D  Start Upload
    0x1E  Upload
    0x1F  End Upload
    0x28  PLC Control (PI Service) -- START/RESTART/MRES; logged CRITICAL
    0x29  PLC Stop             -- logged CRITICAL

PI Service (0x28) parameter parsing (confirmed from Wireshark s7comm
dissector source and public S7comm documentation):
    params[0]   = 0x28 (function code)
    params[1]   = 0x00 (reserved)
    params[2:4] = PI service string length (big-endian)
    params[4..] = PI service string (ASCII)

Known PI service identifiers:
    "WDIETIMER"  warm restart (most common START after STOP)
    "CRST"       cold restart
    "P_PROGRAM"  memory reset (MRES -- wipes user program)
    "_INSE"      insert active module
    "_DELE"      delete object
    "_GARB"      compress user memory

Both STOP (0x29) and PLC Control (0x28) resulting in a state change are
logged at CRITICAL -- START is as significant an event as STOP for a
honeypot recording operational intent. cpu_state.py's shared file is
updated on every state change so the web portal and SZL 0x0424 handler
(when enabled) reflect the current state without further coordination.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from pathlib import Path

import s7_header as sh
from ladder_block_store import BlockStore, BLOCK_TYPE_OB, BLOCK_TYPE_DB, BLOCK_TYPE_FC, BLOCK_TYPE_FB
import cpu_state

log = logging.getLogger("block_transfer")

# S7 block type codes confirmed from real pcap (s7comm_downloading_block_db1.pcap).
# The block filename uses 2-char ASCII hex for the type: '0A' = DB, '08' = OB, etc.
# Format: '_' + hex_type(2) + number(5 digits, zero-padded) + attr(1)
# Example: '_0A00001P' = DB1, passive attribute
#
# Mapping from 2-char ASCII hex type to our internal BLOCK_TYPE_* constants:
_HEX_TYPE_MAP = {
    "08": BLOCK_TYPE_OB,   # OB (Organization Block)
    "0A": BLOCK_TYPE_DB,   # DB (Data Block)
    "0C": BLOCK_TYPE_FC,   # FC (Function)
    "0B": BLOCK_TYPE_DB,   # SDB (System Data Block, treat as DB)
    "0E": BLOCK_TYPE_FB,   # FB (Function Block)
    "0D": BLOCK_TYPE_FC,   # SFC (System Function, treat as FC)
    "0F": BLOCK_TYPE_FB,   # SFB (System Function Block, treat as FB)
    "10": BLOCK_TYPE_DB,   # IDB (Instance Data Block, treat as DB)
}

# Also keep the old ASCII name → type mapping for the fallback regex path
_BLOCK_TYPE_ASCII = {
    b"OB": BLOCK_TYPE_OB,
    b"DB": BLOCK_TYPE_DB,
    b"FC": BLOCK_TYPE_FC,
    b"FB": BLOCK_TYPE_FB,
}

# Filename pattern: _ + 2-char hex type + 5-digit number + attribute char
# Confirmed from capture: '_0A00001P'
_FILENAME_RE = re.compile(rb"_([0-9A-Fa-f]{2})(\d{5})[AP]")

# Fallback: scan for embedded ASCII block type names (older approach, less reliable)
_BLOCK_REF_RE = re.compile(rb"(OB|DB|FC|FB)(\d{1,5})")

UPLOAD_CHUNK_SIZE = 400  # conservative, well under typical negotiated PDU size

FUNCTION_NAMES = {
    0x1A: "request_download",
    0x1B: "download_block",
    0x1C: "download_ended",
    0x1D: "start_upload",
    0x1E: "upload",
    0x1F: "end_upload",
    0x28: "plc_control",
    0x29: "plc_stop",
}

# PI Service identifier strings and their meanings.
# Confirmed from Wireshark s7comm dissector source and public S7comm docs.
PI_SERVICE_NAMES = {
    "WDIETIMER": "warm_restart",
    "CRST":      "cold_restart",
    "P_PROGRAM": "memory_reset",
    "_INSE":     "insert_module",
    "_DELE":     "delete_object",
    "_GARB":     "compress_memory",
    "_MODU":     "module_update",
    "_WAIT":     "wait",
}

# PI services that result in the CPU transitioning to RUN state
PI_SERVICES_STARTING_CPU = {"WDIETIMER", "CRST", "P_PROGRAM"}


def _parse_pi_service(params: bytes) -> dict:
    """
    Extract the PI service string and (for _INSE/_DELE) the block reference
    from PLC Control (0x28) parameters.

    Two layout variants seen in the wild:

    Variant A (restart/memory-reset services -- simple, short):
        [0x28][0x00][len_hi][len_lo][ascii_service_string...]
        e.g. WDIETIMER, CRST, P_PROGRAM

    Variant B (_INSE/_DELE -- includes block reference):
        Confirmed from s7comm_downloading_block_db1.pcap (2026-08-28):
        [0x28][0x00...reserved...][0xfd][fixed 4 bytes]
        [block_name_len=8][block_name: 2-char hex type + 5-digit num + attr]
        [svc_name_len][svc_name: '_INSE' or '_DELE']
        
        Block name: same format as ReqDownload filename without leading '_'
        e.g. '0A00001P' = DB1 passive
    """
    result = {"pi_service": None, "pi_service_meaning": "unknown",
              "pi_block_type": None, "pi_block_number": None}

    if not params:
        return result

    # Try length-prefixed Variant A layout
    for header_len in (2, 4):
        if len(params) < header_len + 2:
            continue
        str_len = (params[header_len] << 8) | params[header_len + 1]
        str_start = header_len + 2
        if 0 < str_len <= 32 and str_start + str_len <= len(params):
            try:
                svc = params[str_start:str_start + str_len].decode("ascii", errors="replace")
                result["pi_service"] = svc
                result["pi_service_meaning"] = PI_SERVICE_NAMES.get(svc, "unknown_pi_service")
                return result
            except Exception:
                pass

    # Try Variant B: _INSE/_DELE with embedded block reference.
    # Confirmed layout from pcap (byte positions, 0-indexed from params[0]=0x28):
    #   params[7]    = 0xFD (marker for this variant)
    #   params[8:12] = 4-byte field (0x00 0x0a 0x01 0x00)
    #   params[12:20]= block name (8 chars, no length prefix)
    #                  e.g. '0A00001P' = DB1 passive
    #   params[20]   = service name length
    #   params[21:]  = service name ('_INSE', '_DELE' etc.)
    if len(params) >= 26 and params[7] == 0xFD:
        try:
            blk_name = params[12:20].decode("ascii", errors="replace")
            svc_len  = params[20]
            svc      = params[21:21 + svc_len].decode("ascii", errors="replace")
            if svc in PI_SERVICE_NAMES and len(blk_name) >= 7:
                result["pi_service"] = svc
                result["pi_service_meaning"] = PI_SERVICE_NAMES.get(svc, "unknown_pi_service")
                hex_type = blk_name[0:2].upper()
                number   = int(blk_name[2:7])
                block_type = _HEX_TYPE_MAP.get(hex_type)
                if block_type is not None:
                    result["pi_block_type"]   = block_type
                    result["pi_block_number"] = number
                    type_names = {BLOCK_TYPE_OB:"OB", BLOCK_TYPE_DB:"DB",
                                  BLOCK_TYPE_FC:"FC", BLOCK_TYPE_FB:"FB"}
                    result["pi_block_type_name"] = type_names.get(block_type, f"0x{hex_type}")
                return result
        except (ValueError, UnicodeDecodeError):
            pass

    # Last resort: scan for any uppercase ASCII run >= 4 chars
    m = re.search(rb"[A-Z_]{4,}", params[1:] if params else b"")
    if m:
        svc = m.group(0).decode("ascii")
        result["pi_service"] = svc
        result["pi_service_meaning"] = PI_SERVICE_NAMES.get(svc, "unknown_pi_service")

    return result


def _extract_block_ref(payload: bytes) -> tuple[int, int] | None:
    """
    Extract (block_type, block_number) from a download request payload.

    Priority 1: S7 filename format '_TTNNNNNX' confirmed from real pcap
    (s7comm_downloading_block_db1.pcap, 2026-08-28):
        '_' + 2-char hex type + 5-digit number + attribute ('A'=active/'P'=passive)
        Example: '_0A00001P' → DB (0x0A), number 1, passive

    Priority 2: fallback regex scan for embedded ASCII 'DB1', 'OB2', etc.
    (less reliable; present for compatibility with older tool variants)
    """
    # Priority 1: structured filename format
    m = _FILENAME_RE.search(payload)
    if m:
        hex_type = m.group(1).decode("ascii").upper()
        number   = int(m.group(2))
        block_type = _HEX_TYPE_MAP.get(hex_type)
        if block_type is not None:
            return block_type, number

    # Priority 2: ASCII type name scan
    m2 = _BLOCK_REF_RE.search(payload)
    if m2:
        block_type = _BLOCK_TYPE_ASCII.get(m2.group(1))
        if block_type is not None:
            return block_type, int(m2.group(2))

    return None


@dataclass
class _DownloadState:
    block_type: int
    number: int
    buffer: bytearray = field(default_factory=bytearray)


@dataclass
class _UploadState:
    block_type: int
    number: int
    offset: int = 0


class BlockTransferHandler:
    def __init__(self, block_store: BlockStore, cmd_logger,
                 cpu_state_path: "Path | None" = None):
        self.block_store = block_store
        self.cmd_logger = cmd_logger
        self._downloads: dict[str, _DownloadState] = {}
        self._uploads: dict[str, _UploadState] = {}
        self._lock = threading.Lock()
        # Injectable path so tests don't touch real /var/lib state; see
        # cpu_state.py for why this lives in a shared file rather than
        # an in-memory attribute (other processes -- the web portal, the
        # SZL-status handler -- need to see the same state).
        self._cpu_state_path = cpu_state_path or cpu_state.STATE_PATH

    @property
    def _cpu_state(self) -> str:
        """Read-through property (not a cached attribute) so this always
        reflects the current shared state, consistent with how
        network_state.json is re-read on every request elsewhere in the
        project rather than cached at startup."""
        return cpu_state.read_cpu_state(self._cpu_state_path)

    def handles(self, function_code: int | None) -> bool:
        return function_code in FUNCTION_NAMES

    def handle(self, session_id: str, peer_ip: str, peer_port: int,
               parsed: sh.ParsedFrame) -> bytes:
        func = parsed.function_code
        handler = {
            0x1A: self._request_download,
            0x1B: self._download_block,
            0x1C: self._download_ended,
            0x1D: self._start_upload,
            0x1E: self._upload,
            0x1F: self._end_upload,
            0x28: self._plc_control,
            0x29: self._plc_stop,
        }[func]
        return handler(session_id, peer_ip, peer_port, parsed)

    def _log(self, session_id, peer_ip, peer_port, event_type, raw, parsed_fields):
        self.cmd_logger.log_event(session_id, peer_ip, peer_port, event_type, raw, parsed_fields)

    # -- Download path (attacker writing a block) --------------------

    def _request_download(self, session_id, peer_ip, peer_port, parsed):
        ref = _extract_block_ref(parsed.params + parsed.data) or (BLOCK_TYPE_OB, 1)
        with self._lock:
            self._downloads[session_id] = _DownloadState(block_type=ref[0], number=ref[1])

        self._log(session_id, peer_ip, peer_port, "block_download_request",
                   parsed.params + parsed.data,
                   {"function": "request_download", "block_type": ref[0], "block_number": ref[1]})
        log.info("Download requested for block type=%#x number=%d from %s",
                  ref[0], ref[1], peer_ip)

        return sh.build_ack_data_response(parsed.pdu_reference)

    def _download_block(self, session_id, peer_ip, peer_port, parsed):
        with self._lock:
            state = self._downloads.get(session_id)
            if state is not None:
                state.buffer.extend(parsed.data)
                chunk_len = len(parsed.data)
                total_so_far = len(state.buffer)
            else:
                chunk_len = len(parsed.data)
                total_so_far = None

        self._log(session_id, peer_ip, peer_port, "block_download_chunk",
                   parsed.data,
                   {"function": "download_block", "chunk_bytes": chunk_len,
                    "total_buffered": total_so_far})

        return sh.build_ack_data_response(parsed.pdu_reference)

    def _download_ended(self, session_id, peer_ip, peer_port, parsed):
        with self._lock:
            state = self._downloads.pop(session_id, None)

        if state is not None:
            content = bytes(state.buffer)
            self.block_store.write_block(state.block_type, state.number, content)
            # CRITICAL: an attacker just successfully wrote content into
            # what this device presents as its program memory. This is
            # the highest-signal event this module produces -- log loud.
            log.critical(
                "Block write COMMITTED: %s%d, %d bytes, from %s:%d (session %s)",
                {BLOCK_TYPE_OB: "OB", BLOCK_TYPE_DB: "DB", BLOCK_TYPE_FC: "FC",
                 BLOCK_TYPE_FB: "FB"}.get(state.block_type, "?"),
                state.number, len(content), peer_ip, peer_port, session_id,
            )
            self._log(session_id, peer_ip, peer_port, "block_download_committed",
                       content,
                       {"function": "download_ended", "block_type": state.block_type,
                        "block_number": state.number, "total_bytes": len(content)})
        else:
            self._log(session_id, peer_ip, peer_port, "block_download_ended_orphan",
                       parsed.params + parsed.data,
                       {"function": "download_ended",
                        "note": "no matching in-progress download for this session"})

        return sh.build_ack_data_response(parsed.pdu_reference)

    # -- Upload path (attacker reading a block) -----------------------

    def _start_upload(self, session_id, peer_ip, peer_port, parsed):
        ref = _extract_block_ref(parsed.params + parsed.data)
        block = self.block_store.get_block(*ref) if ref else None

        if block is None and ref is None:
            # couldn't identify which block -- default to serving OB1,
            # the most commonly-targeted "main program" block, rather
            # than refusing outright (an unprotected real device
            # wouldn't refuse either).
            block = self.block_store.get_block(BLOCK_TYPE_OB, 1)
            ref = (BLOCK_TYPE_OB, 1)

        with self._lock:
            if block is not None:
                self._uploads[session_id] = _UploadState(block_type=ref[0], number=ref[1])

        self._log(session_id, peer_ip, peer_port, "block_upload_request",
                   parsed.params + parsed.data,
                   {"function": "start_upload",
                    "block_type": ref[0] if ref else None,
                    "block_number": ref[1] if ref else None,
                    "block_found": block is not None})
        log.info("Upload (read) requested for block type=%s number=%s from %s -- found=%s",
                  ref[0] if ref else None, ref[1] if ref else None, peer_ip, block is not None)

        return sh.build_ack_data_response(parsed.pdu_reference)

    def _upload(self, session_id, peer_ip, peer_port, parsed):
        with self._lock:
            state = self._uploads.get(session_id)
            if state is None:
                self._log(session_id, peer_ip, peer_port, "block_upload_chunk_orphan",
                           parsed.params + parsed.data,
                           {"function": "upload",
                            "note": "no matching start_upload for this session"})
                return sh.build_ack_data_response(parsed.pdu_reference)

            block = self.block_store.get_block(state.block_type, state.number)
            if block is None:
                return sh.build_ack_data_response(parsed.pdu_reference)

            chunk = block.content[state.offset:state.offset + UPLOAD_CHUNK_SIZE]
            state.offset += len(chunk)

        self._log(session_id, peer_ip, peer_port, "block_upload_chunk",
                   chunk,
                   {"function": "upload", "block_type": state.block_type,
                    "block_number": state.number, "chunk_bytes": len(chunk),
                    "offset_after": state.offset})

        return sh.build_ack_data_response(parsed.pdu_reference, data=chunk)

    def _end_upload(self, session_id, peer_ip, peer_port, parsed):
        with self._lock:
            state = self._uploads.pop(session_id, None)

        self._log(session_id, peer_ip, peer_port, "block_upload_completed",
                   parsed.params + parsed.data,
                   {"function": "end_upload",
                    "block_type": state.block_type if state else None,
                    "block_number": state.number if state else None})

        return sh.build_ack_data_response(parsed.pdu_reference)

    # -- PLC control / STOP -------------------------------------------

    def _plc_control(self, session_id, peer_ip, peer_port, parsed):
        # Parse PI service string to find out WHAT control operation this is.
        # A warm restart (WDIETIMER), cold restart (CRST), or memory reset
        # (P_PROGRAM) all transition the CPU back to RUN. Anything unrecognised
        # is treated conservatively as a restart (RUN) rather than as STOP,
        # since an unrecognised PI service is more likely to be a startup
        # variant than a stop variant (0x29 is the dedicated STOP code).
        pi = _parse_pi_service(parsed.params)
        service = pi.get("pi_service") or "unknown"
        meaning = pi.get("pi_service_meaning", "unknown")

        prev_state = cpu_state.read_cpu_state(self._cpu_state_path)
        cpu_state.write_cpu_state(cpu_state.STATE_RUN, self._cpu_state_path,
                                   peer_ip=peer_ip)

        state_transition = f"{prev_state} → {cpu_state.STATE_RUN}"

        # PLC Control is as significant as STOP -- log at CRITICAL so it
        # surfaces in live journalctl output immediately, not just in JSONL.
        log.critical(
            "PLC CONTROL (%s / %s) received from %s:%d (session %s) -- "
            "accepted with no auth check, cpu_state %s, written to shared "
            "state file so web portal and SZL status handler reflect it.",
            service, meaning, peer_ip, peer_port, session_id, state_transition,
        )
        self._log(
            session_id, peer_ip, peer_port, "plc_start_attempt",
            parsed.params + parsed.data,
            {
                "function": "plc_control",
                "pi_service": service,
                "pi_service_meaning": meaning,
                "state_transition": state_transition,
                "cpu_state_after": cpu_state.STATE_RUN,
                "accepted": True,
            },
        )
        return sh.build_ack_data_response(parsed.pdu_reference)

    def _plc_stop(self, session_id, peer_ip, peer_port, parsed):
        prev_state = cpu_state.read_cpu_state(self._cpu_state_path)
        cpu_state.write_cpu_state(cpu_state.STATE_STOP, self._cpu_state_path,
                                   peer_ip=peer_ip)
        state_transition = f"{prev_state} → {cpu_state.STATE_STOP}"

        log.critical(
            "PLC STOP received from %s:%d (session %s) -- accepted, no auth "
            "gate on this function code, matching real unprotected S7-300 "
            "behavior. cpu_state %s, written to shared state file "
            "(%s) so the SZL-status handler and web portal reflect it too.",
            peer_ip, peer_port, session_id, state_transition, self._cpu_state_path,
        )
        self._log(session_id, peer_ip, peer_port, "plc_stop_attempt",
                   parsed.params + parsed.data,
                   {
                       "function": "plc_stop",
                       "state_transition": state_transition,
                       "cpu_state_after": cpu_state.STATE_STOP,
                       "accepted": True,
                   })
        return sh.build_ack_data_response(parsed.pdu_reference)
