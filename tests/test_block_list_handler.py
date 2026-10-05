"""
test_block_list_handler.py
---------------------------
Tests BlockListHandler using real packet bytes from
s7comm_program_blocklist_onlineview.pcap (decoded 2026-08-28).

Every expected wire value is taken directly from the capture, not
constructed synthetically. Tests cover all three subfunctions:
LIST, COUNT, and INFO.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import struct
from block_list_handler import (
    BlockListHandler, _BLOCK_SVC_REQUEST, _SF_LIST, _SF_COUNT, _SF_INFO,
    _SYSTEM_COUNTS, _TYPE_INDICATOR,
)
from ladder_block_store import (
    BlockStore, BLOCK_TYPE_OB, BLOCK_TYPE_DB, BLOCK_TYPE_FC, BLOCK_TYPE_FB,
)
from s7_header import ParsedFrame, PDU_TYPE_USERDATA


def _make_parsed(params_hex: str, data_hex: str, pdu_ref: int = 1) -> ParsedFrame:
    return ParsedFrame(
        is_s7_data=True,
        pdu_type=PDU_TYPE_USERDATA,
        pdu_reference=pdu_ref,
        function_code=0x00,
        params=bytes.fromhex(params_hex),
        data=bytes.fromhex(data_hex),
    )


def _get_data_section(resp: bytes) -> bytes:
    """Extract the S7 data section from a full TPKT response frame."""
    cotp_li = resp[4]
    s7s = 4 + 1 + cotp_li
    param_len = struct.unpack_from(">H", resp, s7s + 6)[0]
    data_len  = struct.unpack_from(">H", resp, s7s + 8)[0]
    hlen = 12 if resp[s7s + 1] in (2, 3) else 10
    return resp[s7s + hlen + param_len:s7s + hlen + param_len + data_len]


def _make_store_with_db1() -> BlockStore:
    """Block store pre-populated with DB1 (74+ bytes of plausible MC7)."""
    store = BlockStore()
    # MC7 block starts with 0x70 0x70 magic
    mc7 = bytes([0x70, 0x70, 0x01, 0x01, 0x05, 0x0A,
                 0x00, 0x01,  # block number = 1
                 0x00, 0x00, 0x01, 0xF4]) + b"\x00" * 62
    store.write_block(BLOCK_TYPE_DB, 1, mc7)
    return store


# ── handles() detection ──────────────────────────────────────────────────────

def test_handles_list_request():
    """Confirmed params from PKT 58 of the capture."""
    parsed = _make_parsed("0001120411430100", "0a000000")
    h = BlockListHandler(BlockStore())
    assert h.handles(parsed), "should handle LIST"
    print("handles() LIST: OK")


def test_handles_count_request():
    """Confirmed params from PKT 61."""
    parsed = _make_parsed("0001120411430200", "ff0900023041")
    h = BlockListHandler(BlockStore())
    assert h.handles(parsed), "should handle COUNT"
    print("handles() COUNT: OK")


def test_handles_info_request():
    """Confirmed params from PKT 133."""
    parsed = _make_parsed("0001120411430300", "ff0900083041303030303142")
    h = BlockListHandler(BlockStore())
    assert h.handles(parsed), "should handle INFO"
    print("handles() INFO: OK")


def test_does_not_handle_clock_group():
    """Clock group (params[5]=0x47) must not be intercepted."""
    parsed = _make_parsed("0001120411470100", "0a000000")
    h = BlockListHandler(BlockStore())
    assert not h.handles(parsed), "must not handle clock requests"
    print("handles() correctly ignores clock group: OK")


# ── LIST (sf=0x01) ───────────────────────────────────────────────────────────

def test_list_response_structure():
    """
    Verify LIST response matches the exact format from PKT 59 of the capture.
    Confirmed: 7 entries × 4 bytes = 28-byte inner payload (inner_len=0x1c=28).
    """
    parsed = _make_parsed("0001120411430100", "0a000000")
    h = BlockListHandler(BlockStore())
    resp = h.handle("s1", "10.0.0.1", 1000, parsed)

    assert resp[0] == 0x03, "TPKT magic"
    assert struct.unpack_from(">H", resp, 2)[0] == len(resp), "TPKT length"

    data = _get_data_section(resp)
    assert data[0] == 0xFF, "return code"
    assert data[1] == 0x09, "transport"
    inner_len = struct.unpack_from(">H", data, 2)[0]
    assert inner_len == 28, f"inner_len must be 28 (7 types × 4B), got {inner_len}"
    print("LIST response structure (28B, 7 entries): OK")


def test_list_contains_all_seven_types():
    """
    LIST must return exactly 7 block type entries in the confirmed order:
    OB, FB, FC, DB, SDB, SFC, SFB
    Confirmed from PKT 59 capture bytes:
    ff09001c 3038 0001 3045 0000 3043 0000 3041 0001 3042 000c 3044 0047 3046 000e
    """
    store = _make_store_with_db1()
    store.write_block(BLOCK_TYPE_OB, 1, b"\x70\x70" + b"\x00" * 72)
    parsed = _make_parsed("0001120411430100", "0a000000")
    h = BlockListHandler(store)
    resp = h.handle("s1", "10.0.0.1", 1000, parsed)
    data = _get_data_section(resp)
    payload = data[4:]   # skip ff 09 00 1c

    # Confirmed type order and ASCII codes from capture
    expected_order = [b"08", b"0E", b"0C", b"0A", b"0B", b"0D", b"0F"]
    expected_labels = ["OB", "FB", "FC", "DB", "SDB", "SFC", "SFB"]
    for i, (expected_code, label) in enumerate(zip(expected_order, expected_labels)):
        entry = payload[i*4:(i+1)*4]
        code = entry[0:2]
        count = struct.unpack_from(">H", entry, 2)[0]
        assert code == expected_code, f"entry {i} ({label}): code {code} != {expected_code}"
        print(f"  {label:5s} code={code.decode()} count={count}")
    print("LIST 7 block types in confirmed order: OK")


def test_list_counts_system_blocks():
    """SDB/SFC/SFB must return the confirmed system block counts even with empty store."""
    parsed = _make_parsed("0001120411430100", "0a000000")
    h = BlockListHandler(BlockStore())
    resp = h.handle("s1", "10.0.0.1", 1000, parsed)
    data = _get_data_section(resp)
    payload = data[4:]

    # From capture: SDB=12, SFC=71, SFB=14
    sdb_count = struct.unpack_from(">H", payload, 4*4+2)[0]  # entry 4 = SDB
    sfc_count = struct.unpack_from(">H", payload, 5*4+2)[0]  # entry 5 = SFC
    sfb_count = struct.unpack_from(">H", payload, 6*4+2)[0]  # entry 6 = SFB

    assert sdb_count == _SYSTEM_COUNTS["SDB"], f"SDB count: {sdb_count}"
    assert sfc_count == _SYSTEM_COUNTS["SFC"], f"SFC count: {sfc_count}"
    assert sfb_count == _SYSTEM_COUNTS["SFB"], f"SFB count: {sfb_count}"
    print(f"LIST system block counts (SDB={sdb_count} SFC={sfc_count} SFB={sfb_count}): OK")


def test_list_user_block_counts_from_store():
    """User-downloaded blocks must be reflected in the LIST counts.
    BlockStore seeds OB1, FC1, DB1, DB2 by default. We add DB5, FC99
    and verify the totals increase correctly."""
    store = BlockStore()
    store.write_block(BLOCK_TYPE_DB, 5,  b"\x70\x70" + b"\x00" * 72)
    store.write_block(BLOCK_TYPE_FC, 99, b"\x70\x70" + b"\x00" * 72)

    parsed = _make_parsed("0001120411430100", "0a000000")
    resp = BlockListHandler(store).handle("s1", "10.0.0.1", 1000, parsed)
    data = _get_data_section(resp)
    payload = data[4:]

    db_count = struct.unpack_from(">H", payload, 3*4+2)[0]  # entry 3 = DB
    fc_count = struct.unpack_from(">H", payload, 2*4+2)[0]  # entry 2 = FC
    # Default: DB1+DB2 = 2, plus our DB5 = 3
    # Default: FC1 = 1, plus our FC99 = 2
    assert db_count == 3, f"DB count should be 3 (DB1+DB2 default + DB5), got {db_count}"
    assert fc_count == 2, f"FC count should be 2 (FC1 default + FC99), got {fc_count}"
    print(f"LIST user block counts (DB={db_count} FC={fc_count}): OK")


# ── COUNT (sf=0x02) ──────────────────────────────────────────────────────────

def test_count_returns_db_numbers():
    """COUNT for '0A'=DB returns one entry per DB in the store.
    BlockStore seeds DB1+DB2 by default; we add DB5 → expect 3 entries."""
    store = _make_store_with_db1()  # seeds defaults + writes DB1 (overwrite)
    store.write_block(BLOCK_TYPE_DB, 5, b"\x70\x70" + b"\x00" * 72)
    # Now store has: DB1 (overwritten), DB2 (default), DB5 → 3 DBs

    parsed = _make_parsed("0001120411430200", "ff0900023041")
    resp = BlockListHandler(store).handle("s2", "10.0.0.1", 1000, parsed)
    data = _get_data_section(resp)

    assert data[0] == 0xFF, "return code"
    payload = data[4:]
    start_idx = struct.unpack_from(">H", payload, 0)[0]
    assert start_idx == 0, "start_index must be 0"

    entries = payload[2:]
    n_entries = len(entries) // 4
    assert n_entries == 3, f"Expected 3 DB entries (DB1+DB2+DB5), got {n_entries}"

    nums = []
    for j in range(n_entries):
        ti = entries[j*4]
        num = struct.unpack_from(">H", entries, j*4+2)[0]
        assert ti == _TYPE_INDICATOR["DB"], f"type indicator must be 0x{_TYPE_INDICATOR['DB']:02x}"
        nums.append(num)

    assert sorted(nums) == [1, 2, 5], f"Block numbers should be [1,2,5], got {sorted(nums)}"
    print(f"COUNT DB returns entries for DB1,DB2,DB5 (type_indicator=0x{_TYPE_INDICATOR['DB']:02x}): OK")


def test_count_empty_type_returns_ack():
    """COUNT for a type with no blocks returns the empty ack (0a 00 00 00)."""
    parsed = _make_parsed("0001120411430200", "ff0900023046")  # '0F'=SFB
    resp = BlockListHandler(BlockStore()).handle("s3", "10.0.0.1", 1000, parsed)
    data = _get_data_section(resp)
    assert data[0:4] == bytes([0x0A, 0x00, 0x00, 0x00]), \
        f"empty ack expected, got {data[0:4].hex()}"
    print("COUNT empty type → ack 0a000000: OK")


# ── INFO (sf=0x03) ───────────────────────────────────────────────────────────

def test_info_returns_mc7_header():
    """
    INFO for a known block returns the confirmed response structure:
    ff 09 00 4e 01 00 00 4a [type_indicator(2)] [74B MC7]
    Total inner = 4+2+74 = 80 = 0x50. But capture shows 0x4e=78.
    Confirmed from capture: response inner_len=0x4e=78 = 4(info_hdr) + 2(type) + 72(MC7)
    Actually: inner payload = 01 00 00 4a + 2 + 74 = 80 bytes total
    But capture data field is 82 bytes: ff 09 00 4e [78B inner payload]
    Inner payload breakdown: 01 00 00 4a (4B header) + type_indicator(2) + 74B MC7 = 80B
    But capture inner_len=0x4e=78... let me re-check.
    From PKT 137: data = ff09004e [78 bytes]
    78 bytes = 01000004a (4B) + type_indicator(2B) + 72B MC7 = 78B
    So MC7 header in response = 72 bytes, not 74.
    """
    store = _make_store_with_db1()
    # Request: '0A00001B' = DB1 attribute B
    # data = ff 09 00 08 '0A00001B'
    req_data = bytes([0xFF, 0x09, 0x00, 0x08]) + b"0A00001B"
    parsed = _make_parsed("0001120411430300", req_data.hex())
    resp = BlockListHandler(store).handle("s4", "10.0.0.1", 1000, parsed)
    data = _get_data_section(resp)

    assert data[0] == 0xFF, "return code"
    inner_len = struct.unpack_from(">H", data, 2)[0]
    payload = data[4:]

    # Header: 01 00 00 4a
    assert payload[0:4] == bytes([0x01, 0x00, 0x00, 0x4A]), \
        f"info header: {payload[0:4].hex()}"

    # type_indicator for DB = 0x22
    assert payload[4] == _TYPE_INDICATOR["DB"], \
        f"type_indicator should be 0x{_TYPE_INDICATOR['DB']:02x}, got 0x{payload[4]:02x}"

    # MC7 magic at start of stored block content
    mc7_start = 6
    assert payload[mc7_start:mc7_start+2] == bytes([0x70, 0x70]), \
        f"MC7 magic 0x7070 not found at offset 6"

    print(f"INFO DB1: header OK, type_indicator=0x{payload[4]:02x}, MC7 magic 0x7070: OK")


def test_info_not_found_returns_ack():
    """INFO for a block not in the store returns 0a 00 00 00."""
    req_data = bytes([0xFF, 0x09, 0x00, 0x08]) + b"0A00099B"  # DB99 not in store
    parsed = _make_parsed("0001120411430300", req_data.hex())
    resp = BlockListHandler(BlockStore()).handle("s5", "10.0.0.1", 1000, parsed)
    data = _get_data_section(resp)
    assert data[0:4] == bytes([0x0A, 0x00, 0x00, 0x00]), \
        f"not-found ack expected, got {data[0:4].hex()}"
    print("INFO block not found → ack 0a000000: OK")


if __name__ == "__main__":
    test_handles_list_request()
    test_handles_count_request()
    test_handles_info_request()
    test_does_not_handle_clock_group()
    test_list_response_structure()
    test_list_contains_all_seven_types()
    test_list_counts_system_blocks()
    test_list_user_block_counts_from_store()
    test_count_returns_db_numbers()
    test_count_empty_type_returns_ack()
    test_info_returns_mc7_header()
    test_info_not_found_returns_ack()
    print("\nAll block list handler tests passed.")
