"""
test_read_write_parser.py
--------------------------
Tests the read_write_parser against synthetic read_var and write_var
parameter bytes built from the exact structure confirmed in
S7PacketAnalyzer.cs (independent C# implementation). Each test case
mirrors a real operation from S7ClientTests.cs so the parser is
validated against patterns that actually occur in the wild, not just
patterns invented for the test.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import struct
from read_write_parser import (
    parse_read_write_items, parse_from_frame,
    ReadWriteItem, TRANSPORT_SIZE, AREA_CODE,
)
from s7_header import ParsedFrame, PDU_TYPE_JOB_REQUEST, COTP_TYPE_DT


def _build_item(transport_size: int, count: int, db: int, area: int, start_bits: int) -> bytes:
    """
    Build one 12-byte read item. start_bits is packed into 3 bytes big-endian:
    byte9=(start_bits>>16)&0xFF, byte10=(start_bits>>8)&0xFF, byte11=start_bits&0xFF
    """
    return bytes([
        0x12, 0x0A, 0x10,
        transport_size,
    ]) + struct.pack(">H", count) + struct.pack(">H", db) + bytes([area]) + bytes([
        (start_bits >> 16) & 0xFF,
        (start_bits >>  8) & 0xFF,
         start_bits        & 0xFF,
    ])


def _build_read_params(*items_bytes: bytes) -> bytes:
    """Build a complete read_var parameters section."""
    return bytes([0x04, len(items_bytes)]) + b"".join(items_bytes)


def _build_write_params(*items_bytes: bytes) -> bytes:
    return bytes([0x05, len(items_bytes)]) + b"".join(items_bytes)


def _build_write_data_section(items: list[tuple[int, bytes]]) -> bytes:
    """
    Build the write data section: per item: 0x00 + transport_size +
    data_len_in_bits(2) + data + optional padding.
    Confirmed from S7PacketAnalyzer.cs AnalyzeWriteData (lines 276-298).
    """
    result = b""
    for transport_size, data in items:
        bit_len = len(data) * 8
        section = bytes([0x00, transport_size]) + struct.pack(">H", bit_len) + data
        if len(section) % 2 == 1:
            section += b"\x00"
        result += section
    return result


def test_read_single_byte_db500_dbbo():
    """Mirrors S7ClientTests.cs: ReadByteAsync(DataBlocks, 500, 0)"""
    # BYTE = 0x02, count=1, DB=500, area=0x84 (DB), byte 0 → bits 0
    item = _build_item(0x02, 1, 500, 0x84, 0)
    params = _build_read_params(item)

    items = parse_read_write_items(params, b"", 0x04)

    assert len(items) == 1
    i = items[0]
    assert i.transport_size == 0x02
    assert i.transport_size_name == "BYTE"
    assert i.db_number == 500
    assert i.area_code == 0x84
    assert i.byte_address == 0
    assert i.formatted_address == "DB500.DBB0"
    print("Read single byte DB500.DBB0: OK")


def test_read_bit_db500_dbx8_0():
    """Mirrors S7ClientTests.cs: ReadBitAsync(DataBlocks, 500, 8, 0)"""
    # BIT = 0x01, byte 8 bit 0 → start_bits = 8*8 + 0 = 64
    item = _build_item(0x01, 1, 500, 0x84, 64)
    params = _build_read_params(item)

    items = parse_read_write_items(params, b"", 0x04)
    i = items[0]
    assert i.transport_size_name == "BIT"
    assert i.byte_address == 8
    assert i.bit_address == 0
    assert i.formatted_address == "DB500.DBX8.0"
    print("Read bit DB500.DBX8.0: OK")


def test_read_real_db500_dbd26():
    """Mirrors S7ClientTests.cs: ReadRealAsync(DataBlocks, 500, 26)"""
    # REAL = 0x08, byte 26 → start_bits = 26*8 = 208
    item = _build_item(0x08, 1, 500, 0x84, 208)
    params = _build_read_params(item)

    items = parse_read_write_items(params, b"", 0x04)
    i = items[0]
    assert i.transport_size_name == "REAL"
    assert i.byte_address == 26
    assert i.formatted_address == "DB500.DBD26"
    print("Read real DB500.DBD26: OK")


def test_read_multi_item_cross_db():
    """
    Mirrors S7ClientTests.cs TestCrossDBRead -- one request reads from
    both DB500 and DB501 in a single multi-item read_var.
    """
    items_bytes = [
        _build_item(0x02, 1, 500, 0x84,   0),  # DB500.DBB0
        _build_item(0x05, 1, 500, 0x84, 128),  # DB500.DBW16 (INT, byte 16 → bits 128)
        _build_item(0x02, 1, 501, 0x84,   0),  # DB501.DBB0
        _build_item(0x05, 1, 501, 0x84, 128),  # DB501.DBW16
    ]
    params = _build_read_params(*items_bytes)
    items = parse_read_write_items(params, b"", 0x04)

    assert len(items) == 4
    assert items[0].formatted_address == "DB500.DBB0"
    assert items[1].formatted_address == "DB500.DBW16"
    assert items[2].formatted_address == "DB501.DBB0"
    assert items[3].formatted_address == "DB501.DBW16"
    print("Multi-item cross-DB read: all 4 addresses correct -- OK")


def test_write_byte_with_data():
    """
    Mirrors S7ClientTests.cs: WriteByteAsync(DataBlocks, 500, 7, 0x77)
    from TestCrossDBWrite -- write byte 0x77 to DB500.DBB7.
    """
    # BYTE write, byte 7 → start_bits = 56
    item = _build_item(0x02, 1, 500, 0x84, 56)
    params = _build_write_params(item)
    data_section = _build_write_data_section([(0x02, bytes([0x77]))])

    items = parse_read_write_items(params, data_section, 0x05)

    assert len(items) == 1
    i = items[0]
    assert i.formatted_address == "DB500.DBB7"
    assert i.data == bytes([0x77])
    assert i.to_dict()["value"] == 0x77
    print("Write byte 0x77 to DB500.DBB7 with data extraction: OK")


def test_write_real_value():
    """
    Mirrors S7ClientTests.cs: WriteRealAsync(DataBlocks, 500, 26, 123.456f)
    """
    import struct as st
    real_bytes = st.pack(">f", 123.456)
    item = _build_item(0x08, 1, 500, 0x84, 208)  # byte 26 → bits 208
    params = _build_write_params(item)
    data_section = _build_write_data_section([(0x08, real_bytes)])

    items = parse_read_write_items(params, data_section, 0x05)
    i = items[0]
    assert i.formatted_address == "DB500.DBD26"
    assert abs(i.to_dict()["value"] - 123.456) < 0.001
    print(f"Write real 123.456 to DB500.DBD26: value={i.to_dict()['value']:.3f} -- OK")


def test_merker_and_input_areas():
    """Confirm non-DB area codes parse correctly."""
    items_bytes = [
        _build_item(0x02, 1, 0, 0x81, 0),   # I0.0 (Inputs)
        _build_item(0x02, 1, 0, 0x82, 0),   # Q0.0 (Outputs)
        _build_item(0x02, 1, 0, 0x83, 0),   # M0.0 (Merkers)
    ]
    params = _build_read_params(*items_bytes)
    items = parse_read_write_items(params, b"", 0x04)
    assert items[0].formatted_address == "I0"
    assert items[1].formatted_address == "Q0"
    assert items[2].formatted_address == "M0"
    print("Non-DB area codes (I/Q/M): OK")


def test_parse_from_frame_integration():
    """Test the top-level parse_from_frame() with a real ParsedFrame."""
    # DB500.DBD18 DINT×2 — byte 18 → start_bits = 18*8 = 144
    item = _build_item(0x07, 2, 500, 0x84, 18 * 8)
    params = bytes([0x04, 1]) + item

    frame = ParsedFrame(
        is_s7_data=True,
        pdu_type=PDU_TYPE_JOB_REQUEST,
        pdu_reference=42,
        function_code=0x04,
        params=params,
        data=b"",
    )
    result = parse_from_frame(frame)
    assert result is not None
    assert result["function_name"] == "read_var"
    assert result["item_count"] == 1
    assert result["items"][0]["address"] == "DB500.DBD18"
    assert result["items"][0]["type"] == "DINT"
    print("parse_from_frame() integration: OK")


if __name__ == "__main__":
    test_read_single_byte_db500_dbbo()
    test_read_bit_db500_dbx8_0()
    test_read_real_db500_dbd26()
    test_read_multi_item_cross_db()
    test_write_byte_with_data()
    test_write_real_value()
    test_merker_and_input_areas()
    test_parse_from_frame_integration()
    print("\nAll read/write parser tests passed.")
