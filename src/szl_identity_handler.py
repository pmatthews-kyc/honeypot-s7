"""
szl_identity_handler.py
------------------------
Intercepts S7 Userdata SZL read requests (group=4, sf=0x01) in the
proxy relay and returns our configured identity data directly, without
forwarding to the snap7 backend at all.

WHY THIS IS NECESSARY
=====================
The original design patched snap7.server.Server._get_szl_data() from
inside backend_server.py.  That method only exists in specific python-snap7
versions (confirmed absent from the version installed on the real Pi --
"Candidate SZL-related attribute found: S7Protocol.build_read_szl_request
-- verify and wire manually").  When the hook is missing, apply_identity_patch()
logs a warning and returns without patching, meaning every SZL query
returns snap7's hardcoded default values -- not our config.yaml identity.

Intercepting at the proxy layer removes the snap7-version dependency
entirely.  The backend never even sees these requests.  All other
Userdata requests (SZLs we don't handle here, block services, etc.)
still pass through to the backend unchanged.

HANDLED SZL IDs
===============
0x0000  SZL list      -- gates which SZLs s7scan queries next
0x0011  Module ID     -- order code, firmware version
0x001C  Component ID  -- PLC name, module name, serial number
0x0037  Ethernet      -- IP, subnet, MAC
0x0232  Protection    -- no-protection record (s7scan reads this)
0x0424  CPU mode      -- RUN/STOP; reads cpu_state.json live
0x0D91  Module status -- 20-byte polling pattern

All other SZL IDs pass through to the backend (snap7 handles them).

WIRE FORMAT
===========
Request (Userdata pdu_type=0x07):
    params[5] = 0x44  (type=4=request, group=4=CPU functions)
    params[6] = 0x01  (subfunction = read SZL)
    data      = ff 09 00 04 [szl_id(2)] [szl_index(2)]

Response (Userdata pdu_type=0x07):
    params[5] = 0x84  (type=8=response, group=4)
    params[6] = 0x01
    data      = ff 09 [inner_len(2)] [szl_id(2)] [szl_index(2)] [szl_data]
"""

from __future__ import annotations

import logging
import struct

import cpu_state
from identity import read_identity
from s7_header import ParsedFrame, PDU_TYPE_USERDATA

log = logging.getLogger("szl_identity")

# Userdata group=4 (CPU functions), subfunction=0x01 (read SZL)
_SZL_REQUEST  = 0x44   # type=4 request, group=4
_SZL_RESPONSE = 0x84   # type=8 response, group=4
_SF_READ_SZL  = 0x01

# SZL IDs we handle; all others pass through to backend
_OUR_SZL_IDS = frozenset([
    # Tier 1 — automated scanner coverage (Tier 1, confirmed from captures)
    0x0000,   # SZL list
    0x0011,   # Module identification (order code, firmware)
    0x001C,   # Component identification (PLC name, serial)
    0x0037,   # Ethernet interface (IP, MAC, subnet)
    0x0232,   # Protection data
    0x0424,   # CPU mode (RUN/STOP)
    0x0D91,   # Module run state
    0x00A0,   # Diagnostic buffer
    # Tier 2 — STEP 7 Module Information (Wireshark dissector + CPU Technical Data)
    0x0013,   # User memory areas (128 KB work mem, 64 KB load mem)
    0x0014,   # System areas (PII/PIQ 128B, 256 timers/counters)
    0x0131,   # Communication capability (max PDU=480, max connections=16)
    0x0132,   # Communication status (key switch, RUN/STOP, connection counts)
])


def _build_szl_response(pdu_ref: int, szl_id: int, szl_index: int,
                         szl_data: bytes) -> bytes:
    """
    Build a complete TPKT+COTP+S7 Userdata response frame for a SZL read.
    The response data section is: ff 09 [inner_len] [szl_id] [szl_idx] [szl_data]
    """
    # Params (12 bytes): standard Userdata response params for SZL read
    resp_params = bytes([
        0x00, 0x01, 0x12, 0x08,   # outer header
        0x12,                      # inner type = 0x12 (response)
        _SZL_RESPONSE,             # 0x84
        _SF_READ_SZL,              # 0x01
        0x01,                      # last_data_unit
        0x00, 0x00, 0x00, 0x00,   # error = none
    ])

    # Data: response wrapper + szl_id + szl_index + szl_data
    inner_body = struct.pack(">HH", szl_id, szl_index) + szl_data
    inner_len  = len(inner_body)
    resp_data  = bytes([0xFF, 0x09]) + struct.pack(">H", inner_len) + inner_body

    plen = len(resp_params)
    dlen = len(resp_data)
    s7_hdr = bytes([0x32, 0x07, 0x00, 0x00]) + \
             struct.pack(">H", pdu_ref) + \
             struct.pack(">HH", plen, dlen)

    body  = s7_hdr + resp_params + resp_data
    cotp  = bytes([0x02, 0xF0, 0x80])
    total = 4 + len(cotp) + len(body)
    tpkt  = bytes([0x03, 0x00]) + struct.pack(">H", total)
    return tpkt + cotp + body


class SZLIdentityHandler:
    """
    Proxy-relay interceptor for SZL identity reads.
    Instantiated once in honeypot.py; handles() and handle() mirror the
    interface of ClockHandler, BlockListHandler, etc.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self._config_path = config_path

    def handles(self, parsed: ParsedFrame) -> bool:
        """True for Userdata group=4 sf=0x01 requests for SZL IDs we own."""
        if not getattr(parsed, "is_s7_data", False):
            return False
        if parsed.pdu_type != PDU_TYPE_USERDATA:
            return False
        params = parsed.params
        if len(params) < 8:
            return False
        if params[5] != _SZL_REQUEST or params[6] != _SF_READ_SZL:
            return False
        # Peek at the requested SZL ID in the data section.
        #
        # The first byte is the "return value" field. Clients differ:
        #   0xFF  used by snap7's C library and several tools
        #   0x0A  used by python-snap7 3.x (build_read_szl_request line 1093)
        #         and by STEP 7 — this is the standard S7 "request" value
        # Accepting only 0xFF meant python-snap7 clients were never
        # intercepted: snap7 answered the SZLs it knows from its own table
        # and returned error 0x8104 for the rest, which surfaces to the
        # client as "Read SZL failed: Unknown error (0x81)".
        data = parsed.data
        if len(data) < 8:
            return False
        if data[0] not in (0xFF, 0x0A):
            return False
        # data[2:4] is the length field (0x0004 = ID + index), so the low
        # byte is 0x04 regardless of which transport-size convention is used.
        if data[3] != 0x04:
            return False
        szl_id = struct.unpack_from(">H", data, 4)[0]
        return szl_id in _OUR_SZL_IDS

    def handle(self, session_id: str, peer_ip: str, peer_port: int,
               parsed: ParsedFrame) -> bytes:
        data     = parsed.data
        szl_id   = struct.unpack_from(">H", data, 4)[0]
        szl_idx  = struct.unpack_from(">H", data, 6)[0]
        ident    = read_identity(self._config_path)

        if szl_id == 0x0000:
            szl_data = ident.build_szl_list()
        elif szl_id == 0x0011:
            szl_data = ident.build_module_identification_szl()
        elif szl_id == 0x001C:
            szl_data = ident.build_szl_001c()
        elif szl_id == 0x0037:
            szl_data = ident.build_network_info_szl()
        elif szl_id == 0x0232:
            szl_data = ident.build_protection_szl()
        elif szl_id == 0x0424:
            szl_data = ident.build_cpu_status_szl(cpu_state.read_cpu_state())
        elif szl_id == 0x0D91:
            szl_data = ident.build_module_status_szl()
        elif szl_id == 0x00A0:
            szl_data = ident.build_diagnostic_buffer_szl()
        # ── Tier 2: from Wireshark dissector + CPU Technical Data ──────────
        elif szl_id == 0x0013:
            szl_data = ident.build_memory_areas_szl()
        elif szl_id == 0x0014:
            szl_data = ident.build_system_areas_szl()
        elif szl_id == 0x0131:
            szl_data = ident.build_comm_capability_szl(szl_index=szl_idx)
        elif szl_id == 0x0132:
            state = cpu_state.read_cpu_state()
            szl_data = ident.build_comm_status_szl(szl_index=szl_idx,
                                                    cpu_state_str=state)
        else:
            return b""   # shouldn't reach here; pass through

        log.debug("SZL 0x%04X idx=0x%04X → %dB (from %s)",
                  szl_id, szl_idx, len(szl_data), peer_ip)
        return _build_szl_response(parsed.pdu_reference, szl_id, szl_idx, szl_data)
