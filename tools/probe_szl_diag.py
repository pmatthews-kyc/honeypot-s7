#!/usr/bin/env python3
"""
probe_szl_diag.py — Find why SZL 0x00A0 (diagnostic buffer) fails

Run ON THE PI against the deployed code:
    sudo python3 tools/probe_szl_diag.py [--install-dir /opt/s7honeypot]

Checks, in order, the exact chain a Read SZL request travels:
  1. Is the deployed identity.py the fixed version?
  2. Does build_diagnostic_buffer_szl() run without raising?
  3. How many records does it produce, and does the frame fit the PDU?
  4. Does SZLIdentityHandler claim the ID and build a response?
  5. What does a real client get back?
"""
import argparse
import os
import struct
import sys
import traceback
from pathlib import Path

P, F, W = "\u2713", "\u2717", "!"
MAX_PDU = 480

_ap = argparse.ArgumentParser(description="SZL 0x00A0 diagnostic probe")
_ap.add_argument("--install-dir", default="/opt/s7honeypot",
                 help="Honeypot install dir (default: /opt/s7honeypot). "
                      "Modules are read from <install-dir>/src and config "
                      "from <install-dir>/config.yaml.")
_args, _ = _ap.parse_known_args()

INSTALL_DIR = _args.install_dir
SRC_DIR     = os.path.join(INSTALL_DIR, "src")
CONFIG      = os.path.join(INSTALL_DIR, "config.yaml")
sys.path.insert(0, SRC_DIR)


def main():
    print("\nSZL 0x00A0 diagnostic probe")
    print("=" * 52)
    print(f"install-dir: {INSTALL_DIR}  (modules: {SRC_DIR})")

    # ── 1. Deployed version check ─────────────────────────────────────────
    print("\n[1] Deployed identity.py")
    try:
        src = open(os.path.join(SRC_DIR, "identity.py")).read()
        has_cap = "_MAX_RECORDS_PER_PDU" in src
        has_merge = "import diag_log" in src
        print(f"  {P if has_cap else F} PDU record cap present "
              f"(_MAX_RECORDS_PER_PDU)")
        print(f"  {P if has_merge else F} diag_log merge present")
        if not has_cap:
            print(f"  {W} OLD FILE — the fix is not in {SRC_DIR}/identity.py")
            return
    except Exception as e:
        print(f"  {F} could not read identity.py: {e}")
        return

    # ── 2/3. Build the SZL payload ────────────────────────────────────────
    print("\n[2] build_diagnostic_buffer_szl()")
    try:
        import identity as im
        im._IDENTITY_CONFIG_PATH = Path(CONFIG)
        im._identity_cache = None
        im._identity_mtime = 0.0
        ident = im.read_identity()
        szl = ident.build_diagnostic_buffer_szl()
    except Exception:
        print(f"  {F} raised an exception:")
        traceback.print_exc()
        print(f"\n  {W} The handler returns empty on exception, the request "
              f"falls through to snap7, and the client reports 0x81.")
        return

    lpr, nrec = struct.unpack_from(">HH", szl)
    frame = len(szl) + 60
    print(f"  {P} built OK")
    print(f"      lpr={lpr}  records={nrec}  payload={len(szl)}B")
    print(f"      estimated frame={frame}B  (negotiated PDU={MAX_PDU})")
    if frame > MAX_PDU:
        print(f"  {F} EXCEEDS PDU by {frame - MAX_PDU}B — this is the 0x81")
    else:
        print(f"  {P} fits within PDU ({MAX_PDU - frame}B headroom)")
    if len(szl) != 4 + lpr * nrec:
        print(f"  {F} size mismatch: header says {4 + lpr*nrec}B, "
              f"actual {len(szl)}B")

    # ── 4. Handler dispatch ───────────────────────────────────────────────
    print("\n[3] SZLIdentityHandler dispatch")
    try:
        from szl_identity_handler import SZLIdentityHandler, _OUR_SZL_IDS
        from s7_header import ParsedFrame, PDU_TYPE_USERDATA

        req = ParsedFrame(
            is_s7_data=True, pdu_type=PDU_TYPE_USERDATA,
            pdu_reference=1, function_code=0x00,
            params=bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00]),
            data=bytes([0xFF, 0x09, 0x00, 0x04]) + struct.pack(">HH", 0x00A0, 0),
        )
        print(f"  {P if 0x00A0 in _OUR_SZL_IDS else F} 0x00A0 in _OUR_SZL_IDS")
        h = SZLIdentityHandler(CONFIG)
        print(f"  {P if h.handles(req) else F} handles() returns True")
        resp = h.handle("probe", "127.0.0.1", 0, req)
        if resp:
            print(f"  {P} handle() returned {len(resp)}B")
            if len(resp) > MAX_PDU:
                print(f"  {F} response exceeds PDU by {len(resp)-MAX_PDU}B")
        else:
            print(f"  {F} handle() returned EMPTY — falls through to snap7, "
                  f"client sees 0x81")
    except Exception:
        print(f"  {F} handler raised:")
        traceback.print_exc()

    # ── 5. End-to-end through a real client ───────────────────────────────
    print("\n[4] Live read through the proxy (127.0.0.1:102)")
    try:
        import snap7
        c = snap7.client.Client()
        c.connect("127.0.0.1", 0, 2)
        try:
            data = c.read_szl(0x00A0)
            raw = bytes(getattr(data, "Data", b""))[:64]
            print(f"  {P} read_szl(0x00A0) succeeded: {raw[:16].hex()}...")
        except Exception as e:
            print(f"  {F} read_szl(0x00A0) failed: {e}")
            print(f"      Comparison — a known-good SZL:")
            try:
                c.read_szl(0x0011)
                print(f"      {P} 0x0011 works, so the proxy path is fine "
                      f"and the problem is specific to 0x00A0")
            except Exception as e2:
                print(f"      {F} 0x0011 also fails: {e2}")
        c.disconnect()
    except ImportError:
        print(f"  {W} python-snap7 not importable here; skipped")
    except Exception as e:
        print(f"  {W} could not connect: {e}")

    print()


if __name__ == "__main__":
    main()
