"""
test_szl_identity_handler.py
-----------------------------
Verifies that SZLIdentityHandler intercepts identity SZL reads and
returns correct data regardless of snap7 version (no backend needed).
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))
import struct, sys, yaml, tempfile, os
from s7_header import ParsedFrame, PDU_TYPE_USERDATA
from szl_identity_handler import SZLIdentityHandler, _OUR_SZL_IDS


def _make_szl_req(szl_id: int, szl_idx: int = 0, pdu_ref: int = 1) -> ParsedFrame:
    data = bytes([0xFF, 0x09, 0x00, 0x04]) + struct.pack(">HH", szl_id, szl_idx)
    return ParsedFrame(
        is_s7_data=True, pdu_type=PDU_TYPE_USERDATA,
        pdu_reference=pdu_ref, function_code=0x00,
        params=bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00]),
        data=data,
    )


def _make_handler() -> SZLIdentityHandler:
    cfg = {
        "identity": {
            "plc_name": "SIMATIC 300(1)",
            "module_name": "CPU 315-2 PN/DP",
            "order_code": "6ES7 315-2AG10-0AB0",
            "firmware_version": "V2.6",
            "firmware_version_parts": [2, 6, 0],
            "serial_number": "S C-TEST123",
            "module_type_name": "CPU 315-2 PN/DP",
            "copyright": "Original Siemens Equipment",
            "plant_id": "",
        }
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(cfg, f)
        path = f.name
    import identity as im
    import pathlib
    im._IDENTITY_CONFIG_PATH = pathlib.Path(path)
    im._identity_cache = None
    im._identity_mtime = 0.0
    h = SZLIdentityHandler(path)
    return h, path


def _extract_szl_data(resp: bytes) -> tuple[int, int, bytes]:
    """Return (szl_id, szl_idx, szl_data) from a full response frame."""
    cotp_li = resp[4]
    s7s = 4 + 1 + cotp_li
    hlen = 12 if resp[s7s + 1] in (2, 3) else 10
    plen = struct.unpack_from(">H", resp, s7s + 6)[0]
    dlen = struct.unpack_from(">H", resp, s7s + 8)[0]
    data = resp[s7s + hlen + plen: s7s + hlen + plen + dlen]
    # data: ff 09 [inner_len] [szl_id(2)] [szl_idx(2)] [szl_data...]
    szl_id  = struct.unpack_from(">H", data, 4)[0]
    szl_idx = struct.unpack_from(">H", data, 6)[0]
    return szl_id, szl_idx, data[8:]


P = "✓"; F = "✗"


def test_handles_our_szl_ids():
    h, path = _make_handler()
    try:
        for szl_id in _OUR_SZL_IDS:
            req = _make_szl_req(szl_id)
            assert h.handles(req), f"should handle SZL 0x{szl_id:04X}"
        print(f"{P} handles() True for all {len(_OUR_SZL_IDS)} owned SZL IDs")
    finally:
        os.unlink(path)


def test_does_not_handle_other_szls():
    h, path = _make_handler()
    try:
        # 0x0131 and 0x0132 are now Tier 2 SZLs handled at proxy layer
        # Only 0x0091 (module status overview) still falls through to snap7
        for szl_id in (0x0091,):
            req = _make_szl_req(szl_id)
            assert not h.handles(req), f"should NOT handle SZL 0x{szl_id:04X}"
        # Confirm the new Tier 2 IDs ARE handled
        for szl_id in (0x0131, 0x0132, 0x0013, 0x0014):
            req = _make_szl_req(szl_id)
            assert h.handles(req), f"should handle SZL 0x{szl_id:04X} (Tier 2)"
        print(f"{P} handles() correctly gates Tier 1+2 vs pass-through SZL IDs")
    finally:
        os.unlink(path)


def test_szl_0011_module_id():
    h, path = _make_handler()
    try:
        resp = h.handle("s1", "10.0.0.1", 1000, _make_szl_req(0x0011))
        assert resp[0] == 0x03, "TPKT magic"
        szl_id, _, szl_data = _extract_szl_data(resp)
        assert szl_id == 0x0011
        order = szl_data[2:22].rstrip(b"\x00").decode("ascii").strip()
        assert "6ES7" in order, f"order code not found: {order!r}"
        print(f"{P} SZL 0x0011 returns order_code='{order}': OK")
    finally:
        os.unlink(path)


def test_szl_001c_plc_name_and_serial():
    h, path = _make_handler()
    try:
        resp = h.handle("s1", "10.0.0.1", 1000, _make_szl_req(0x001C))
        _, _, szl_data = _extract_szl_data(resp)
        plc    = szl_data[6:30].split(b"\x00")[0].decode("ascii")
        serial = szl_data[142:166].split(b"\x00")[0].decode("ascii")
        assert plc    == "SIMATIC 300(1)", f"plc={plc!r}"
        assert serial == "S C-TEST123",   f"serial={serial!r}"
        print(f"{P} SZL 0x001C plc='{plc}' serial='{serial}': OK")
    finally:
        os.unlink(path)


def test_szl_0232_no_protection():
    h, path = _make_handler()
    try:
        resp = h.handle("s1", "10.0.0.1", 1000, _make_szl_req(0x0232))
        _, _, szl_data = _extract_szl_data(resp)
        lpr  = struct.unpack_from(">H", szl_data, 0)[0]
        nrec = struct.unpack_from(">H", szl_data, 2)[0]
        mode_sel = struct.unpack_from(">H", szl_data[4:], 8)[0]
        assert lpr == 10 and nrec == 1, f"lpr={lpr} nrec={nrec}"
        assert mode_sel == 3, f"mode_sel={mode_sel}"
        print(f"{P} SZL 0x0232 protection: lpr=10, mode_sel=3 (RUN): OK")
    finally:
        os.unlink(path)


def test_szl_0000_list_contains_required():
    h, path = _make_handler()
    try:
        resp = h.handle("s1", "10.0.0.1", 1000, _make_szl_req(0x0000))
        _, _, szl_data = _extract_szl_data(resp)
        nrec = struct.unpack_from(">H", szl_data, 2)[0]
        ids  = {struct.unpack_from(">H", szl_data, 4 + i*2)[0] for i in range(nrec)}
        for required in (0x0011, 0x001C, 0x0232, 0x0037):
            assert required in ids, f"0x{required:04X} missing from SZL list"
        print(f"{P} SZL 0x0000 list ({nrec} entries) contains all required IDs: OK")
    finally:
        os.unlink(path)


def test_response_is_valid_tpkt():
    """Every response must be a well-formed TPKT+COTP+S7 frame."""
    h, path = _make_handler()
    try:
        for szl_id in sorted(_OUR_SZL_IDS):
            resp = h.handle("s1", "10.0.0.1", 1000, _make_szl_req(szl_id))
            assert resp[0] == 0x03, f"SZL 0x{szl_id:04X}: not TPKT"
            length = struct.unpack_from(">H", resp, 2)[0]
            assert length == len(resp), f"SZL 0x{szl_id:04X}: length mismatch"
            assert resp[5] == 0xF0,    f"SZL 0x{szl_id:04X}: not COTP DT"
            assert resp[7] == 0x32,    f"SZL 0x{szl_id:04X}: not S7"
        print(f"{P} All {len(_OUR_SZL_IDS)} SZL responses are valid TPKT frames: OK")
    finally:
        os.unlink(path)



def test_accepts_python_snap7_request_form():
    """
    python-snap7 3.x sends 0x0A as the data-section return value in a Read
    SZL request (s7protocol.py build_read_szl_request, confirmed from the
    installed 3.1.2 source). snap7's C library sends 0xFF.

    handles() originally required 0xFF, so python-snap7 clients were never
    intercepted at all. snap7's own server answered the SZLs it happens to
    know and returned error 0x8104 for the rest, which reaches the client
    as "Read SZL failed: Unknown error (0x81)". Both forms must be accepted.
    """
    import struct
    from s7_header import ParsedFrame, PDU_TYPE_USERDATA

    def req(szl_id, first_byte):
        if first_byte == 0x0A:      # python-snap7 / STEP 7
            data = struct.pack(">BBHHH", 0x0A, 0x00, 0x0004, szl_id, 0)
        else:                        # snap7 C library
            data = bytes([0xFF, 0x09, 0x00, 0x04]) + struct.pack(">HH", szl_id, 0)
        return ParsedFrame(
            is_s7_data=True, pdu_type=PDU_TYPE_USERDATA,
            pdu_reference=1, function_code=0x00,
            params=bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00]),
            data=data)

    h, path = _make_handler()
    try:
        for szl_id in (0x0000, 0x0011, 0x001C, 0x0037, 0x0232,
                       0x0424, 0x00A0, 0x0013, 0x0131):
            for form, label in ((0x0A, "python-snap7"), (0xFF, "snap7 C lib")):
                r = req(szl_id, form)
                assert h.handles(r), \
                    f"SZL 0x{szl_id:04X} not handled for {label} request form"
                assert h.handle("s", "127.0.0.1", 0, r), \
                    f"SZL 0x{szl_id:04X} empty response for {label}"
        print(f"{P} both request forms (0x0A and 0xFF) intercepted for all owned SZLs")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    test_handles_our_szl_ids()
    test_does_not_handle_other_szls()
    test_szl_0011_module_id()
    test_szl_001c_plc_name_and_serial()
    test_szl_0232_no_protection()
    test_szl_0000_list_contains_required()
    test_response_is_valid_tpkt()
    print("\nAll SZL identity handler tests passed.")
    test_accepts_python_snap7_request_form()
