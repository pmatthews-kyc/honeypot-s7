"""
test_identity_szl.py
-----------------------
Regression test for the SZL structure corrections made after checking
against a real installed python-snap7 3.1.2 on target hardware (see
identity.py and backend_server.py docstrings for the full story). Locks
in the confirmed-correct byte lengths so a future edit can't silently
reintroduce the earlier wrong sizes (234 bytes instead of 210; a
made-up 0x0111 structure instead of the real 0x0011).
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import os
import logging

from identity import S7Identity


def _make_identity(**overrides) -> S7Identity:
    defaults = dict(
        order_code="6ES7 315-2AG10-0AB0",
        firmware_version="V2.6",
        firmware_version_parts=[2, 6, 0],
        serial_number="S C-XXXXXXXXXXXX",
        plc_name="SIMATIC 300(1)",
        module_name="CPU 315-2 PN/DP",
        copyright="Original Siemens Equipment",
        plant_id="",
        module_type_name="CPU 315-2 PN/DP",
    )
    defaults.update(overrides)
    return S7Identity(**defaults)


def test_szl_001c_header_matches_body():
    """
    The 4-byte header must agree with the body: length_per_record ×
    num_records == len(payload) - 4.

    This was previously a flat 210-byte blob with a zeroed header. snap7
    reads fixed offsets so it never noticed, but plcscan does
    `unpack('!HHHH', data[:8])` then splits the body by length-per-record —
    a zero there raises ValueError and the SZL yields nothing. Real
    hardware returns exactly lpr × nrec bytes, so assert that relationship
    rather than a magic total.
    """
    import struct
    ident = _make_identity()
    data = ident.build_szl_001c()
    lpr, nrec = struct.unpack_from(">HH", data)
    assert lpr == 34, f"length_per_record should be 34 (2 index + 32 data), got {lpr}"
    assert nrec == 6, f"expected 6 records, got {nrec}"
    assert len(data) - 4 == lpr * nrec, (
        f"header says {lpr}x{nrec}={lpr*nrec} body bytes, "
        f"payload has {len(data)-4}")
    # snap7's parse_cpu_info_szl reads ModuleTypeName at data[176:208]
    assert len(data) >= 208, "payload too short for snap7 fixed offsets"
    print(f"SZL 0x001C header consistent: lpr={lpr} nrec={nrec} "
          f"total={len(data)}B: OK")


def test_szl_001c_field_offsets_correct():
    ident = _make_identity(plc_name="TESTNAME", module_name="TESTMODULE",
                            copyright="TESTCOPY", serial_number="TESTSERIAL",
                            module_type_name="TESTTYPE")
    data = ident.build_szl_001c()

    assert data[6:6+8] == b"TESTNAME", "ASName field at offset 6 incorrect"
    assert data[40:40+10] == b"TESTMODULE", "ModuleName field at offset 40 incorrect"
    assert data[108:108+8] == b"TESTCOPY", "Copyright field at offset 108 incorrect"
    assert data[142:142+10] == b"TESTSERIAL", "SerialNumber field at offset 142 incorrect"
    assert data[176:176+8] == b"TESTTYPE", "ModuleTypeName field at offset 176 incorrect"
    print("All SZL 0x001C field offsets match confirmed real structure: OK")


def test_szl_0011_is_exactly_24_bytes():
    ident = _make_identity()
    data = ident.build_order_code_szl()
    assert len(data) == 24, f"SZL 0x0011 must be exactly 24 bytes (confirmed real structure), got {len(data)}"
    print("SZL 0x0011 is exactly 24 bytes: OK")


def test_szl_0011_field_layout():
    ident = _make_identity(order_code="TESTORDER", firmware_version="V9.9")
    data = ident.build_order_code_szl()
    assert data[:9] == b"TESTORDER"
    assert data[20:24] == b"V9.9"
    print("SZL 0x0011 order_code(20)+firmware(4) layout correct: OK")


def test_overlong_firmware_version_truncates_with_warning(caplog):
    ident = _make_identity(firmware_version="v.2.6.0")  # 7 chars, the original broken config value
    with caplog.at_level(logging.WARNING):
        data = ident.build_order_code_szl()
    assert data[20:24] == b"v.2.", "should truncate to first 4 bytes, matching real library behavior"
    assert any("longer than 4 bytes" in r.message for r in caplog.records), \
        "should log a warning about truncation, not fail silently"
    print("Overlong firmware_version truncates AND warns (doesn't fail silently): OK")


def test_module_identification_szl_satisfies_nmap_length_requirement():
    """
    The actual root cause of the real-world crash: nmap's s7-info.nse
    requires the TOTAL wire response to be >= 125 bytes
    (parse_response's `#response >= 125` gate) or it returns nil,
    cascading into a crash in the next function that assumes a valid
    table. python-snap7's own minimal 24-byte SZL 0x0011 structure
    produces a ~57-byte total response and fails this gate outright.
    """
    import struct as _struct
    from szl_identity_handler import SZLIdentityHandler
    from s7_header import ParsedFrame, PDU_TYPE_USERDATA

    ident = _make_identity()
    data = ident.build_module_identification_szl()

    # Measure the REAL frame rather than trusting a hardcoded overhead
    # constant. The old estimate of 33 was 4 bytes low (actual: 37), which
    # would have masked a genuine regression or, as here, flagged a false
    # one. Build the frame the proxy actually sends and count it.
    _h = SZLIdentityHandler(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.yaml.example"))
    _req = ParsedFrame(
        is_s7_data=True, pdu_type=PDU_TYPE_USERDATA,
        pdu_reference=1, function_code=0x00,
        params=_struct.pack(">BBBBBBBB", 0, 1, 0x12, 4, 0x11, 0x44, 1, 0),
        data=_struct.pack(">BBHHH", 0x0A, 0, 4, 0x0011, 0))
    frame = _h.handle("t", "127.0.0.1", 0, _req)
    total_wire_length = len(frame)

    assert total_wire_length >= 125, (
        f"total wire response ({total_wire_length} bytes) must be >= 125 "
        f"to pass nmap's s7-info.nse length gate. Payload is {len(data)}B; "
        f"shrinking the SZL payload breaks nmap scans."
    )
    print(f"Module identification SZL satisfies nmap's length requirement "
          f"({total_wire_length} >= 125): OK")


def test_module_identification_szl_field_offsets_match_nmap():
    """
    Offsets confirmed from two independent sources: test_plcserver.py
    reference implementation (decoded programmatically) and a real
    tcpdump capture. Both confirm: Module at szl_data[6], Basic Hardware
    at szl_data[34], version at [85:88].
    """
    import struct
    ident = _make_identity(order_code="TESTORDER123", firmware_version_parts=[7, 8, 9])
    data = ident.build_module_identification_szl()

    # Proper indexed-record structure
    length_per_record = struct.unpack_from(">H", data, 0)[0]
    num_records       = struct.unpack_from(">H", data, 2)[0]
    assert length_per_record == 28, f"length_per_record wrong: {length_per_record}"
    assert num_records == 3, f"num_records wrong: {num_records}"
    assert struct.unpack_from(">H", data, 4)[0]  == 0x0001, "record 1 index"
    assert struct.unpack_from(">H", data, 32)[0] == 0x0006, "record 2 index"
    assert struct.unpack_from(">H", data, 60)[0] == 0x0007, "record 3 index"

    module   = data[6:].split(b"\x00")[0].decode("ascii")
    basic_hw = data[34:].split(b"\x00")[0].decode("ascii")
    assert module   == "TESTORDER123", f"Module at offset 6 wrong: {module!r}"
    assert basic_hw == "TESTORDER123", f"Basic Hardware at offset 34 wrong: {basic_hw!r}"
    assert (data[85], data[86], data[87]) == (7, 8, 9), \
        f"version bytes at 85-87 wrong: {(data[85], data[86], data[87])}"
    print("Proper record structure + field offsets match confirmed sources: OK")


def test_against_real_captured_response_bytes():
    """All three nmap output fields verified against expected values."""
    ident = _make_identity()
    data = ident.build_module_identification_szl()
    module   = data[6:].split(b"\x00")[0].decode("ascii")
    basic_hw = data[34:].split(b"\x00")[0].decode("ascii")
    version  = f"{data[85]}.{data[86]}.{data[87]}"
    assert module   == "6ES7 315-2AG10-0AB0"
    assert basic_hw == "6ES7 315-2AG10-0AB0"
    assert version  == "2.6.0"
    print("Module/Basic Hardware/Version match expected nmap output: OK")


def test_network_info_szl_structure():
    """SZL 0x0037 uses the confirmed field layout from test_plcserver.py."""
    import struct
    fake_state = {
        "ip_address":  "192.168.1.50",
        "netmask":     "255.255.255.0",
        "mac_address": "28:63:36:12:34:56",
    }
    ident = _make_identity()
    data = ident.build_network_info_szl(network_state=fake_state)

    length_per_record = struct.unpack_from(">H", data, 0)[0]
    num_records       = struct.unpack_from(">H", data, 2)[0]
    assert length_per_record == 48, f"length_per_record={length_per_record}"
    assert num_records       == 1,  f"num_records={num_records}"
    rec = data[4:]
    assert struct.unpack_from(">H", rec, 0)[0] == 0xFFFF, "record index should be 0xffff"
    ip   = ".".join(str(b) for b in rec[2:6])
    mask = ".".join(str(b) for b in rec[6:10])
    mac  = ":".join(f"{b:02x}" for b in rec[14:20])
    assert ip   == "192.168.1.50",      f"IP wrong: {ip}"
    assert mask == "255.255.255.0",     f"mask wrong: {mask}"
    assert mac  == "28:63:36:12:34:56", f"MAC wrong: {mac}"
    print("SZL 0x0037 structure and network fields correct: OK")


def test_szl_list_contains_required_ids():
    """
    SZL 0x0000 must include every ID s7scan queries:
    0x0011, 0x001C, 0x0232, 0x0037 — plus every ID we handle ourselves.
    If any of these are absent, s7scan skips that SZL (line 371 of s7scan.py).
    """
    import struct
    ident = _make_identity()
    data  = ident.build_szl_list()

    lpr  = struct.unpack_from(">H", data, 0)[0]
    nrec = struct.unpack_from(">H", data, 2)[0]
    assert lpr  == 2,  f"lpr must be 2 (one SZL ID per record), got {lpr}"
    assert nrec > 10,  f"expected many records, got {nrec}"

    ids = {struct.unpack_from(">H", data, 4 + i * 2)[0] for i in range(nrec)}
    required = {0x0011, 0x001C, 0x0232, 0x0037,   # what s7scan queries
                0x0424, 0x0D91,                    # what we added to patch
                0x0131, 0x0132}                    # status-tool staples
    missing = required - ids
    assert not missing, f"SZL list missing IDs: {[f'0x{x:04X}' for x in missing]}"
    print(f"SZL 0x0000 list contains {nrec} entries incl. all required IDs: OK")


def test_protection_szl_no_protection():
    """
    SZL 0x0232 must indicate no protection (unprotected PLC in RUN).
    s7scan parses this into a ProtectionRecord; without it, s7scan logs an error.
    """
    import struct
    ident  = _make_identity()
    data   = ident.build_protection_szl()

    lpr  = struct.unpack_from(">H", data, 0)[0]
    nrec = struct.unpack_from(">H", data, 2)[0]
    assert lpr  == 10, f"lpr must be 10 bytes, got {lpr}"
    assert nrec == 1,  f"nrec must be 1, got {nrec}"

    record = data[4:]
    index     = struct.unpack_from(">H", record, 0)[0]
    sch_schutz = struct.unpack_from(">H", record, 2)[0]
    cpu_schutz = struct.unpack_from(">H", record, 4)[0]
    anl_schutz = struct.unpack_from(">H", record, 6)[0]
    mode_sel   = struct.unpack_from(">H", record, 8)[0]

    assert index      == 0x0001, f"index={index:#06x}"
    assert sch_schutz == 0x0000, "sch_schutz should be 0 (no key-switch protection)"
    assert cpu_schutz == 0x0000, "cpu_schutz should be 0 (no CPU protection)"
    assert anl_schutz == 0x0000, "anl_schutz should be 0 (no startup protection)"
    assert mode_sel   == 0x0003, f"mode_sel should be 3 (RUN), got {mode_sel}"
    print("SZL 0x0232 protection: index=1, all protection=0, mode_sel=3 (RUN): OK")


def test_cpu_status_szl_run_state():
    """
    SZL 0x0424 RUN response confirmed from real pcap analysis.
    Mode low byte 0x28 = RUN.
    """
    import struct
    ident = _make_identity()
    data = ident.build_cpu_status_szl("RUN")

    assert len(data) == 24, f"szl_data must be 24 bytes (4 header + 20 record), got {len(data)}"
    lpr  = struct.unpack_from(">H", data, 0)[0]
    nrec = struct.unpack_from(">H", data, 2)[0]
    assert lpr  == 20, f"length_per_record={lpr}"
    assert nrec == 1,  f"num_records={nrec}"

    record = data[4:]
    assert len(record) == 20
    assert struct.unpack_from(">H", record, 0)[0] == 0x5144, "identifier must be 0x5144"
    mode_word = struct.unpack_from(">H", record, 2)[0]
    assert mode_word >> 8 == 0xFF,   "mode high byte must be 0xFF"
    assert mode_word & 0xFF == 0x28, f"RUN mode low byte must be 0x28, got 0x{mode_word&0xFF:02x}"
    assert record[4:12] == b"\x00" * 8, "bytes 4-12 must be zero"
    assert len(record[12:20]) == 8, "timestamp field must be 8 bytes"
    print("SZL 0x0424 RUN state structure (confirmed from real capture): OK")


def test_cpu_status_szl_stop_state():
    """SZL 0x0424 STOP -- low byte 0x08 confirmed from capture (device was in STOP)."""
    import struct
    ident = _make_identity()
    data = ident.build_cpu_status_szl("STOP")
    record = data[4:]
    mode_word = struct.unpack_from(">H", record, 2)[0]
    assert mode_word & 0xFF == 0x08, f"STOP mode low byte must be 0x08, got 0x{mode_word&0xFF:02x}"
    print("SZL 0x0424 STOP state (byte 0x08 confirmed from capture): OK")


def test_module_status_szl_format():
    """SZL 0x0D91 -- confirmed 20-byte static pattern from real pcap."""
    import struct
    ident = _make_identity()
    data = ident.build_module_status_szl()

    assert len(data) == 20, f"must be exactly 20 bytes, got {len(data)}"
    lpr  = struct.unpack_from(">H", data, 0)[0]
    nrec = struct.unpack_from(">H", data, 2)[0]
    assert lpr == 16, f"length_per_record={lpr}"
    assert nrec == 1, f"num_records={nrec}"
    assert data == bytes.fromhex("00100001000002007fff00c000c00000b4020011"), \
        "must match exactly the bytes observed in the real pcap"
    print("SZL 0x0D91 20-byte pattern matches real capture exactly: OK")



if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)

    test_szl_001c_header_matches_body()
    test_szl_001c_field_offsets_correct()
    test_szl_0011_is_exactly_24_bytes()
    test_szl_0011_field_layout()
    test_module_identification_szl_satisfies_nmap_length_requirement()
    test_module_identification_szl_field_offsets_match_nmap()
    test_against_real_captured_response_bytes()
    test_network_info_szl_structure()
    test_szl_list_contains_required_ids()
    test_protection_szl_no_protection()
    test_cpu_status_szl_run_state()
    test_cpu_status_szl_stop_state()
    test_module_status_szl_format()

    print("\n--- Expect a WARNING log line right below this ---")
    ident = _make_identity(firmware_version="v.2.6.0")
    data = ident.build_order_code_szl()
    assert data[20:24] == b"v.2."
    print("--- If a warning appeared above, truncation-warning behavior: OK ---")

    print("\nAll identity SZL tests passed.")
