"""
read_write_parser.py
---------------------
Parses S7comm Read Var (0x04) and Write Var (0x05) request parameters
to extract exactly what DB/area/address/type is being accessed.

This is the intelligence layer on top of raw capture: instead of just
logging raw hex bytes, it tells you "attacker read DB500.DBD26 (REAL)"
or "attacker wrote 0x77 to DB500.DBB7 (BYTE)" -- which is exactly what
you need to understand intent rather than just recording activity.

CONFIRMED STRUCTURE -- sourced from S7PacketAnalyzer.cs (independent
C# implementation), cross-checked against our own real tcpdump captures.
Every field offset and size here was verified against a working, tested
implementation rather than inferred from documentation alone.

Read item (12 bytes per item, in the parameters section):
    byte[0]   = 0x12 (variable specification tag)
    byte[1]   = 0x0A (remaining length = 10)
    byte[2]   = 0x10 (S7ANY syntax ID -- the standard addressing mode)
    byte[3]   = transport_size  (BIT=0x01, BYTE=0x02, WORD=0x04,
                                  INT=0x05, DWORD=0x06, DINT=0x07,
                                  REAL=0x08)
    byte[4:6] = element_count   (big-endian, number of elements)
    byte[6:8] = db_number       (big-endian, 0 for non-DB areas)
    byte[8]   = area_code       (0x81=I, 0x82=Q, 0x83=M, 0x84=DB,
                                  0x1C=Counter, 0x1D=Timer)
    byte[9:12]= start_address   (3-byte big-endian, in BITS)
                                  byte_address = start_address // 8
                                  bit_address  = start_address %  8

Write data (in the data section, after all item headers):
    byte[0]   = return_code (0xFF = success in response)
    byte[1]   = data_transport_size
    byte[2:4] = data_length_in_bits (big-endian)
    byte[4..] = data bytes, word-aligned (padded to even length)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


# -- Lookup tables (confirmed from S7PacketAnalyzer.cs) ----------------

TRANSPORT_SIZE = {
    0x01: "BIT",
    0x02: "BYTE",
    0x03: "CHAR",
    0x04: "WORD",
    0x05: "INT",
    0x06: "DWORD",
    0x07: "DINT",
    0x08: "REAL",
    0x09: "DATE",
}

AREA_CODE = {
    0x81: "I",    # Inputs
    0x82: "Q",    # Outputs
    0x83: "M",    # Flags/Merkers
    0x84: "DB",   # Data Block
    0x1C: "C",    # Counter
    0x1D: "T",    # Timer
}

AREA_NAME = {
    0x81: "Input (I)",
    0x82: "Output (Q)",
    0x83: "Flags (M)",
    0x84: "Data Block (DB)",
    0x1C: "Counter (C)",
    0x1D: "Timer (T)",
}

FUNCTION_CODE = {
    0x00: "cpu_services",
    0x04: "read_var",
    0x05: "write_var",
    0x1A: "request_download",
    0x1B: "download_block",
    0x1C: "download_ended",
    0x1D: "start_upload",
    0x1E: "upload",
    0x1F: "end_upload",
    0x28: "plc_control",
    0x29: "plc_stop",
    0xF0: "setup_communication",
}


def _format_address(area_code: int, db_number: int, start_bits: int,
                    transport_size: int, count: int) -> str:
    """Format a Siemens address in engineering notation: DB500.DBD26, M0.3, etc."""
    byte_addr = start_bits // 8
    bit_addr  = start_bits %  8

    area = AREA_CODE.get(area_code, f"0x{area_code:02x}")

    if area_code == 0x84:   # Data Block
        prefix = f"DB{db_number}."
        if transport_size == 0x01:   # BIT
            return f"{prefix}DBX{byte_addr}.{bit_addr}"
        elif transport_size in (0x02, 0x03):  # BYTE/CHAR
            return f"{prefix}DBB{byte_addr}"
        elif transport_size in (0x04, 0x05):  # WORD/INT
            return f"{prefix}DBW{byte_addr}"
        elif transport_size in (0x06, 0x07, 0x08):  # DWORD/DINT/REAL
            return f"{prefix}DBD{byte_addr}"
        else:
            return f"{prefix}DB+{byte_addr}"
    else:
        if transport_size == 0x01:
            return f"{area}{byte_addr}.{bit_addr}"
        else:
            return f"{area}{byte_addr}"


@dataclass
class ReadWriteItem:
    transport_size: int
    count: int
    db_number: int
    area_code: int
    start_bits: int
    data: bytes = field(default=b"", repr=False)

    @property
    def byte_address(self) -> int:
        return self.start_bits // 8

    @property
    def bit_address(self) -> int:
        return self.start_bits % 8

    @property
    def transport_size_name(self) -> str:
        return TRANSPORT_SIZE.get(self.transport_size, f"0x{self.transport_size:02x}")

    @property
    def area_name(self) -> str:
        return AREA_NAME.get(self.area_code, f"0x{self.area_code:02x}")

    @property
    def formatted_address(self) -> str:
        return _format_address(self.area_code, self.db_number,
                               self.start_bits, self.transport_size, self.count)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "address":        self.formatted_address,
            "area":           self.area_name,
            "db":             self.db_number if self.area_code == 0x84 else None,
            "byte_address":   self.byte_address,
            "bit_address":    self.bit_address,
            "type":           self.transport_size_name,
            "count":          self.count,
        }
        if self.data:
            d["data_hex"] = self.data.hex()
            d["data_len"] = len(self.data)
            # Best-effort value interpretation
            val = _interpret_value(self.transport_size, self.data)
            if val is not None:
                d["value"] = val
        return d


def _interpret_value(transport_size: int, data: bytes) -> Any:
    """Best-effort: decode first element to a Python native type."""
    try:
        if transport_size == 0x01 and len(data) >= 1:   # BIT
            return bool(data[0])
        elif transport_size in (0x02, 0x03) and len(data) >= 1:  # BYTE/CHAR
            return data[0]
        elif transport_size == 0x04 and len(data) >= 2:  # WORD
            return struct.unpack_from(">H", data)[0]
        elif transport_size == 0x05 and len(data) >= 2:  # INT (signed)
            return struct.unpack_from(">h", data)[0]
        elif transport_size == 0x06 and len(data) >= 4:  # DWORD
            return struct.unpack_from(">I", data)[0]
        elif transport_size == 0x07 and len(data) >= 4:  # DINT (signed)
            return struct.unpack_from(">i", data)[0]
        elif transport_size == 0x08 and len(data) >= 4:  # REAL (float)
            return round(struct.unpack_from(">f", data)[0], 6)
    except struct.error:
        pass
    return None


def parse_read_write_items(params: bytes, data: bytes,
                           function_code: int) -> list[ReadWriteItem]:
    """
    Parse read/write var items from the params and data byte-strings.

    params: the parameters section of the S7 PDU (everything after the
            10-byte or 12-byte S7 header, up to param_length bytes).
    data:   the data section (up to data_length bytes).
    function_code: 0x04 (read) or 0x05 (write).

    Returns a list of ReadWriteItem; the .data field is populated only
    for write requests (where the data section carries what was written).
    """
    if len(params) < 2:
        return []

    # params[0] = function code (we already have it)
    # params[1] = item count
    item_count = params[1]
    items: list[ReadWriteItem] = []
    offset = 2  # start of first item

    ITEM_SIZE = 12  # confirmed from S7PacketAnalyzer.cs line 265

    for _ in range(item_count):
        if offset + ITEM_SIZE > len(params):
            break

        # Confirmed byte positions from S7PacketAnalyzer.cs lines 253-257:
        #   [3]    transport_size
        #   [4:6]  element_count (big-endian)
        #   [6:8]  db_number     (big-endian)
        #   [8]    area_code
        #   [9:12] start_address (3-byte big-endian, in bits)
        transport_size = params[offset + 3]
        count          = struct.unpack_from(">H", params, offset + 4)[0]
        db_number      = struct.unpack_from(">H", params, offset + 6)[0]
        area_code      = params[offset + 8]
        start_bits     = (params[offset + 9] << 16 |
                          params[offset + 10] << 8 |
                          params[offset + 11])

        items.append(ReadWriteItem(
            transport_size=transport_size,
            count=count,
            db_number=db_number,
            area_code=area_code,
            start_bits=start_bits,
        ))
        offset += ITEM_SIZE

    # For write requests, attach the data values to their items.
    # Write data section: for each item: return_code(1) + transport(1) +
    # data_length_bits(2) + data(len) + optional padding byte.
    # (Confirmed from S7PacketAnalyzer.cs AnalyzeWriteData, lines 276-298)
    if function_code == 0x05 and data:
        data_offset = 0
        for item in items:
            if data_offset + 4 > len(data):
                break
            data_length_bits = struct.unpack_from(">H", data, data_offset + 2)[0]
            data_length_bytes = (data_length_bits + 7) // 8
            data_offset += 4
            if data_offset + data_length_bytes <= len(data):
                item.data = data[data_offset:data_offset + data_length_bytes]
                data_offset += data_length_bytes
                if data_offset % 2 == 1:  # word-align
                    data_offset += 1

    return items


def parse_from_frame(parsed_frame) -> dict[str, Any] | None:
    """
    Convenience entry point: given a `ParsedFrame` from s7_header.py,
    attempt to parse read/write item details if the function code is
    read_var or write_var. Returns None for anything else.

    The returned dict is ready to merge into the JSONL log's `parsed`
    field, so downstream analysis can filter/query by address and type
    rather than re-deriving everything from raw hex.
    """
    if parsed_frame is None or not parsed_frame.is_s7_data:
        return None

    fc = parsed_frame.function_code
    if fc not in (0x04, 0x05):
        return None

    items = parse_read_write_items(parsed_frame.params, parsed_frame.data, fc)
    if not items:
        return None

    return {
        "function_code":   fc,
        "function_name":   FUNCTION_CODE.get(fc, f"0x{fc:02x}"),
        "item_count":      len(items),
        "items":           [item.to_dict() for item in items],
    }
