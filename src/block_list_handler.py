"""
block_list_handler.py
----------------------
Handles S7 Userdata block service requests (function group=3).
Intercepts these in the proxy relay so the backend snap7.Server
doesn't need to implement them.

Wire format confirmed from s7comm_program_blocklist_onlineview.pcap
(decoded 2026-08-28).

params[5] encodes method+group:
    0x43 = type=4(request), group=3(block services)  ← what we detect
    0x83 = type=8(response), group=3(block services)

params[6] = subfunction:
    0x01 = LIST   - list all block types with counts
    0x02 = COUNT  - list block numbers for a given type
    0x03 = INFO   - detailed header for a specific block

=== LIST (sf=0x01) ===
Request  data: 0a 00 00 00  (empty)
Response data: ff 09 00 1c  [7 entries × 4 bytes]
    Entry format: [ascii_type_byte1][ascii_type_byte2][count_hi][count_lo]
    Order confirmed from capture: OB, FB, FC, DB, SDB, SFC, SFB
    ASCII type pairs: '08'=OB, '0A'=DB, '0B'=SDB, '0C'=FC,
                      '0D'=SFC, '0E'=FB, '0F'=SFB

=== COUNT (sf=0x02) ===
Request  data: ff 09 00 02 [type_byte1][type_byte2]
    Type bytes are ASCII: 0x30 0x41 = '0A' = DB
Response data: ff 09 00 [len] [start_index_hi][start_index_lo]
    then entries: [type_indicator(1)][version_flag(1)][block_num_hi(1)][block_num_lo(1)]
    type_indicator (confirmed from capture):
        DB  = 0x22   SDB = 0x22   OB  = 0x20 (inferred)
        FC  = 0x24 (inferred)     FB  = 0x41 (inferred)
        SFC = 0x42   SFB = 0x42  (both confirmed from capture)

=== INFO (sf=0x03) ===
Request  data: ff 09 00 08 [block_name_8chars]
    Block name: type(2) + num(5) + attr(1), e.g. '0A00001B' = DB1
Response data: ff 09 00 4e 01 00 00 4a [type_indicator(2)] [74 bytes MC7 header]
    OR: 0a 00 00 00  if block not found
    type_indicator bytes (confirmed):
        DB  = 0x22 0x00
        SFC = 0x42 0x30 (from PKT 134)

SYSTEM BLOCK COUNTS:
    A real S7-315-2 PN/DP has pre-loaded system blocks that are always present.
    These appear in LIST even without any user-downloaded blocks.
    Confirmed counts from capture (real S7-315 IM device):
        SDB = 12  SFC = 71  SFB = 14
    These are used as static "system block" counts in our LIST response.
    User-downloaded blocks (from block_transfer_handler.py) are added on top.
"""

from __future__ import annotations

import logging
import struct

from ladder_block_store import (
    BlockStore,
    BLOCK_TYPE_OB, BLOCK_TYPE_DB, BLOCK_TYPE_FC, BLOCK_TYPE_FB,
)

log = logging.getLogger("block_list")

# Userdata block service detection
_BLOCK_SVC_REQUEST = 0x43   # group=3(blocks), method=4(request)
_SF_LIST  = 0x01
_SF_COUNT = 0x02
_SF_INFO  = 0x03

# ASCII type pairs used in LIST and COUNT requests (2 bytes each)
# ASCII '0' = 0x30, then type hex digit as ASCII
_ASCII_TYPE_PAIRS: list[tuple[bytes, int, str]] = [
    # (2-byte ASCII code, internal BLOCK_TYPE, label)
    # Order matches what the real capture shows in LIST responses
    (b"08", BLOCK_TYPE_OB,  "OB"),
    (b"0E", BLOCK_TYPE_FB,  "FB"),
    (b"0C", BLOCK_TYPE_FC,  "FC"),
    (b"0A", BLOCK_TYPE_DB,  "DB"),
    (b"0B", BLOCK_TYPE_DB,  "SDB"),  # system data block, treated as DB internally
    (b"0D", BLOCK_TYPE_FC,  "SFC"),  # system function, treated as FC internally
    (b"0F", BLOCK_TYPE_FB,  "SFB"),  # system function block, treated as FB internally
]

# Map from ASCII type string → internal type and flag
_ASCII_TO_TYPE = {pair[0].decode(): (pair[1], pair[2]) for pair in _ASCII_TYPE_PAIRS}

# type_indicator byte used in COUNT entries and INFO responses (confirmed from capture)
_TYPE_INDICATOR = {
    "OB":  0x20,
    "DB":  0x22,   # confirmed from PKT 137
    "SDB": 0x22,   # system DBs use same indicator
    "FC":  0x24,
    "SFC": 0x42,   # confirmed from PKT 134
    "FB":  0x41,
    "SFB": 0x42,   # confirmed from PKT 96
}

# System block counts for a real S7-315-2 PN/DP
# Confirmed from capture of the real device: SDB=12, SFC=71, SFB=14
# These are always returned in LIST regardless of user-downloaded blocks
_SYSTEM_COUNTS = {"SDB": 12, "SFC": 71, "SFB": 14}

# Fixed version/flag byte used in COUNT entries (1 = confirmed from most capture entries)
_COUNT_ENTRY_FLAG = 0x01


def _build_userdata_response(pdu_reference: int, subfunc: int,
                              resp_data: bytes) -> bytes:
    """
    Build a complete TPKT + COTP DT + S7 Userdata response frame.
    Response params pattern confirmed from capture:
        000112081283[SF][00|01]00000000  (12 bytes)
    Where [00] for LIST (multi-part available), [01] for COUNT/INFO (last unit)
    """
    last_unit = 0x01 if subfunc != _SF_LIST else 0x00
    resp_params = bytes([
        0x00, 0x01, 0x12, 0x08,       # outer header (fixed)
        0x12,                           # inner type = 0x12 (response)
        _BLOCK_SVC_REQUEST | 0x40,      # 0x83 = response, group 3
        subfunc,                        # subfunction
        last_unit,                      # last_data_unit
        0x00, 0x00, 0x00, 0x00,        # error = none
    ])

    param_len = len(resp_params)
    data_len  = len(resp_data)

    s7_hdr = bytes([0x32, 0x07, 0x00, 0x00]) + \
             struct.pack(">H", pdu_reference) + \
             struct.pack(">HH", param_len, data_len)

    body = s7_hdr + resp_params + resp_data

    cotp = bytes([0x02, 0xF0, 0x80])
    total = 4 + len(cotp) + len(body)
    tpkt  = bytes([0x03, 0x00]) + struct.pack(">H", total)
    return tpkt + cotp + body


class BlockListHandler:
    """
    Handles S7 Userdata block service requests for the online program view.

    The 'online view' in STEP 7 / TIA Portal queries block service (group=3)
    to show which blocks are present in the PLC -- it's the tree of OBs, DBs,
    FCs, FBs visible in the project browser. Intercepting these here means the
    tool sees a realistic block inventory derived from the block store plus
    pre-configured system block counts.
    """

    def __init__(self, block_store: BlockStore):
        self._store = block_store

    def handles(self, parsed) -> bool:
        """True if this is a block service request (group=3, type=request)."""
        if not getattr(parsed, "is_s7_data", False):
            return False
        if parsed.pdu_type != 0x07:     # Userdata only
            return False
        params = parsed.params
        if len(params) < 7:
            return False
        return params[5] == _BLOCK_SVC_REQUEST

    def handle(self, session_id: str, peer_ip: str, peer_port: int,
               parsed) -> bytes:
        subfunc = parsed.params[6]
        if subfunc == _SF_LIST:
            return self._list(parsed)
        elif subfunc == _SF_COUNT:
            return self._count(parsed)
        elif subfunc == _SF_INFO:
            return self._info(parsed)
        return b""

    # ── LIST (sf=0x01) ──────────────────────────────────────────────────

    def _list(self, parsed) -> bytes:
        """
        Return a summary of all block types and their counts.
        7 entries × 4 bytes = 28-byte payload (inner_len=0x1c).

        Confirmed entry order from capture:
            OB, FB, FC, DB, SDB, SFC, SFB
        Counts = user blocks from store + system block counts for
        SDB/SFC/SFB (which are always present on a real CPU).
        """
        # Count user-downloaded blocks from store
        all_blocks = self._store.list_blocks()
        user_counts: dict[str, int] = {
            "OB": sum(1 for b in all_blocks if b.block_type == BLOCK_TYPE_OB),
            "FB": sum(1 for b in all_blocks if b.block_type == BLOCK_TYPE_FB),
            "FC": sum(1 for b in all_blocks if b.block_type == BLOCK_TYPE_FC),
            "DB": sum(1 for b in all_blocks if b.block_type == BLOCK_TYPE_DB),
        }

        entries = bytearray()
        for ascii_code, _int_type, label in _ASCII_TYPE_PAIRS:
            count = user_counts.get(label, 0) + _SYSTEM_COUNTS.get(label, 0)
            entries += ascii_code  # 2 ASCII bytes (e.g. b'08')
            entries += struct.pack(">H", count)

        inner_len = len(entries)
        resp_data = bytes([0xFF, 0x09]) + struct.pack(">H", inner_len) + bytes(entries)

        log.debug("LIST_BLOCKS: %s", {l: user_counts.get(l,0)+_SYSTEM_COUNTS.get(l,0)
                                      for _,_,l in _ASCII_TYPE_PAIRS})
        return _build_userdata_response(parsed.pdu_reference, _SF_LIST, resp_data)

    # ── COUNT (sf=0x02) ─────────────────────────────────────────────────

    def _count(self, parsed) -> bytes:
        """
        List block numbers of a specific type.

        Request data: ff 09 00 02 [type_ascii_2bytes]
        Response: start_index(2) + entries [type_indicator flag num_hi num_lo]

        System blocks (SDB, SFC, SFB) return empty lists since we don't
        track individual system block numbers -- a real tool will still see
        plausible total counts from LIST and gracefully handle empty count
        responses (it falls back to the known total count).
        """
        data = parsed.data
        # Accept both request return-value conventions: 0xFF (snap7 C lib)
        # and 0x0A (python-snap7 3.x, STEP 7). See szl_identity_handler.
        if len(data) < 6 or data[0] not in (0xFF, 0x0A):
            return _build_userdata_response(parsed.pdu_reference, _SF_COUNT,
                                            bytes([0x0A, 0x00, 0x00, 0x00]))

        inner_len = struct.unpack_from(">H", data, 2)[0]
        if inner_len < 2 or len(data) < 6:
            return _build_userdata_response(parsed.pdu_reference, _SF_COUNT,
                                            bytes([0x0A, 0x00, 0x00, 0x00]))

        type_str = data[4:6].decode("ascii", errors="replace")
        int_type, label = _ASCII_TO_TYPE.get(type_str, (None, None))

        entries = bytearray()
        entries += b"\x00\x00"   # start_index = 0

        if int_type is not None:
            all_blocks = self._store.list_blocks()
            blocks = sorted(b.number for b in all_blocks if b.block_type == int_type)
            ti = _TYPE_INDICATOR.get(label, 0x22)
            for num in blocks:
                entries += bytes([ti, _COUNT_ENTRY_FLAG]) + struct.pack(">H", num)

        if len(entries) == 2:
            # No blocks found -- return empty ack
            log.debug("COUNT %s ('%s'): 0 blocks", label or "?", type_str)
            return _build_userdata_response(parsed.pdu_reference, _SF_COUNT,
                                            bytes([0x0A, 0x00, 0x00, 0x00]))

        payload_len = len(entries)
        resp_data = bytes([0xFF, 0x09]) + struct.pack(">H", payload_len) + bytes(entries)
        log.debug("COUNT %s ('%s'): %d blocks", label or "?", type_str,
                  (len(entries) - 2) // 4)
        return _build_userdata_response(parsed.pdu_reference, _SF_COUNT, resp_data)

    # ── INFO (sf=0x03) ──────────────────────────────────────────────────

    def _info(self, parsed) -> bytes:
        """
        Return detailed block header information for a specific block.

        Request data: ff 09 00 08 [block_name_8chars]
            Block name format: type(2) + num(5) + attr(1)
            e.g. '0A00001B' = DB1 with attribute 'B'

        Response: ff 09 00 4e 01 00 00 4a [type_indicator(2)] [74B MC7 header]
            OR:   0a 00 00 00  if block not found

        The 74 bytes of MC7 header are the first 74 bytes of the stored
        block content. The MC7 block format starts with magic 0x70 0x70.
        """
        data = parsed.data
        not_found = bytes([0x0A, 0x00, 0x00, 0x00])

        if len(data) < 12 or data[0] not in (0xFF, 0x0A):
            return _build_userdata_response(parsed.pdu_reference, _SF_INFO, not_found)

        inner_len = struct.unpack_from(">H", data, 2)[0]
        if inner_len != 8 or len(data) < 12:
            return _build_userdata_response(parsed.pdu_reference, _SF_INFO, not_found)

        block_name = data[4:12].decode("ascii", errors="replace")
        type_str   = block_name[0:2]
        num_str    = block_name[2:7]

        int_type, label = _ASCII_TO_TYPE.get(type_str, (None, None))
        if int_type is None or not num_str.isdigit():
            log.debug("INFO: unknown block '%s'", block_name)
            return _build_userdata_response(parsed.pdu_reference, _SF_INFO, not_found)

        num = int(num_str)
        block = self._store.get_block(int_type, num)

        if block is None or not block.content or len(block.content) < 4:
            log.debug("INFO: block %s%d not in store", label, num)
            return _build_userdata_response(parsed.pdu_reference, _SF_INFO, not_found)

        MC7_HEADER_SIZE = 74
        mc7_header = bytes(block.content[:MC7_HEADER_SIZE]).ljust(MC7_HEADER_SIZE, b"\x00")

        ti = _TYPE_INDICATOR.get(label, 0x22)
        # type_indicator pair: confirmed DB=0x22 0x00, SFC=0x42 0x30
        # Use 0x00 as second byte for user blocks (DB/OB/FC/FB)
        ti2 = 0x30 if label in ("SFC", "SFB") else 0x00

        info_header = bytes([0x01, 0x00, 0x00, 0x4A])  # 0x4A=74
        type_indicator_bytes = bytes([ti, ti2])

        inner_payload = info_header + type_indicator_bytes + mc7_header
        inner_len_out = len(inner_payload)
        resp_data = bytes([0xFF, 0x09]) + struct.pack(">H", inner_len_out) + inner_payload

        log.info("INFO: serving %s%d (%d bytes MC7 header)", label, num, MC7_HEADER_SIZE)
        return _build_userdata_response(parsed.pdu_reference, _SF_INFO, resp_data)
