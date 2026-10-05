#!/usr/bin/env python3
"""
verify_live_db_reads.py — Live validation of attach_to_server() against
a real snap7 client
=============================================================================
Everything process_simulator.py and modbus_bridge.py do to make S7comm
reads look like a live process depends on attach_to_server() correctly
guessing snap7.Server's internal memory_areas/S7Area layout (see the
"NOT ACTUALLY CONFIRMED" note in STATUS.md). backend_server.py's DB
pre-allocation means a wrong guess fails *silently* -- reads still
succeed, they just never change. That's not caught by anything else in
this repo:

  - The unit tests (test_read_write_parser.py etc.) only exercise the
    *parsing* of read/write requests -- they never touch a running
    snap7.Server.
  - check_openplc.py's own docstring lists "DB200 in snap7 reflects the
    same values" as check #6, but the function body never implements
    it -- only the Modbus side of the bridge is actually checked.

This script is the missing piece: it acts as a real S7 client (using
python-snap7's Client, the same library a real attacker/engineering
tool would use) and:

  1. Reads every tag process_simulator.py knows about (built-in +
     config-driven), at its real DB/area/offset/size.
  2. Checks the decoded value falls inside its configured [min, max].
  3. Samples again after waiting past one simulator tick and confirms
     tags expected to drift actually changed bytes, and monotonic
     counters actually advanced.
  4. Confirms DB999 is deliberately NOT allocated (real S7 error
     expected) -- proves pre-allocation didn't over-allocate and mask
     a real gap.
  5. If modbus_bridge is enabled in config.yaml, checks bridge-mapped
     tags instead of expecting process_simulator to own them.

USAGE
-----
    # run under the honeypot venv: /opt/s7honeypot/venv/bin/python
    python3 backend_server.py &            # start the backend under test
    python3 verify_live_db_reads.py                       # default: talks
                                                            # directly to the
                                                            # backend (127.0.0.1:1102),
                                                            # bypassing the proxy,
                                                            # to isolate the
                                                            # attach_to_server()
                                                            # write path from
                                                            # proxy-layer concerns.
    python3 verify_live_db_reads.py --host <public-ip> --port 102 \\
        --rack 0 --slot 2                                  # test through the
                                                            # real public-facing
                                                            # proxy instead

CONFIDENCE NOTE, same discipline as the rest of this project: the
snap7 Client API calls used below (db_read/eb_read/ab_read/mb_read,
connect(ip, rack, slot)) reflect the documented python-snap7 3.x
client interface. This has NOT been run in this build environment
(no network access to install python-snap7 / no live backend to
connect to) -- confirm the connect()/read call signatures against your
installed version if you see an AttributeError, the same caveat
backend_server.py already carries for the server-side API.
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

P = "\u2713"; F = "\u2717"; W = "\u26a0"   # ✓ ✗ ⚠


def check(label: str, ok: bool, detail: str = "") -> bool:
    sym = P if ok else F
    print(f"  {sym}  {label}")
    if detail:
        print(f"       {detail}")
    return ok


# ── byte size / unpack per pack_format (mirrors process_simulator._pack_value) ──

_SIZE = {"real": 4, "dint": 4, "int": 2, "word": 2, "byte": 1, "bool": 1}


def _unpack(pack_format: str, data: bytes):
    if pack_format == "real":
        return struct.unpack(">f", data)[0]
    elif pack_format == "dint":
        return struct.unpack(">i", data)[0]
    elif pack_format == "int":
        return struct.unpack(">h", data)[0]
    elif pack_format == "word":
        return struct.unpack(">H", data)[0]
    elif pack_format == "byte":
        return data[0]
    elif pack_format == "bool":
        return bool(data[0])
    raise ValueError(f"unknown pack_format {pack_format!r}")


# ── snap7 client area read, defensive about API surface (same reasoning as
#    process_simulator.attach_to_server()'s own multi-candidate lookup) ──

def _read_area(client, area: str, db_number: int, offset: int, size: int) -> bytes:
    """
    area: "DB" | "I" | "Q" | "M"

    Tries the stable convenience methods first (db_read/eb_read/ab_read/
    mb_read -- E=Eingänge/inputs, A=Ausgänge/outputs, M=Merker/markers,
    same German-derived naming process_simulator.py's own comments use),
    falling back to read_area(Areas.xxx, ...) if a given python-snap7
    build doesn't expose the convenience wrapper.
    """
    if area == "DB":
        return bytes(client.db_read(db_number, offset, size))
    if area == "I":
        if hasattr(client, "eb_read"):
            return bytes(client.eb_read(offset, size))
    elif area == "Q":
        if hasattr(client, "ab_read"):
            return bytes(client.ab_read(offset, size))
    elif area == "M":
        if hasattr(client, "mb_read"):
            return bytes(client.mb_read(offset, size))

    # Fallback: raw read_area with an Areas enum, name varies by version.
    import snap7
    areas_cls = getattr(snap7, "types", None)
    areas_cls = getattr(areas_cls, "Areas", None) or getattr(
        getattr(snap7, "client", None), "Areas", None
    )
    if areas_cls is None:
        raise RuntimeError(
            "Could not locate snap7 Areas enum for read_area() fallback -- "
            "confirm your python-snap7 version's Client API manually."
        )
    area_enum = {"I": "PE", "Q": "PA", "M": "MK", "DB": "DB"}[area]
    enum_val = getattr(areas_cls, area_enum)
    return bytes(client.read_area(enum_val, db_number, offset, size))


# ── build the tag list the same way process_simulator.py does ──

def _load_tags(config_path: str):
    """
    Returns (process_sim_tags, bridge_active, bridge_owned_addresses).

    process_sim_tags: list of the same ProcessTag objects
    ProcessSimulator(config_path).tags would use -- imported directly
    from process_simulator.py so this script can never silently drift
    out of sync with what the honeypot itself actually configures.

    bridge_owned_addresses: set of (area, db_number) pairs the bridge
    takes over when modbus_bridge.enabled -- mirrors the exclude_areas/
    exclude_dbs logic in backend_server.py::run_backend() so this script
    doesn't flag bridge-owned tags as "not drifting" when process_simulator
    correctly isn't writing them.
    """
    # Modules live in <install-dir>/src while config.yaml is in <install-dir>.
    # Add the src/ dir next to the config, not the config's own directory.
    _cfg_dir = Path(config_path).resolve().parent
    _src = _cfg_dir / "src"
    sys.path.insert(0, str(_src if _src.is_dir() else _cfg_dir))
    from process_simulator import ProcessSimulator
    import modbus_bridge

    sim = ProcessSimulator(config_path)
    bridge_active = modbus_bridge.is_enabled(config_path)

    bridge_owned = set()
    if bridge_active:
        # Same hardcoded set backend_server.py::run_backend() applies --
        # kept in sync manually since it isn't exposed as shared config.
        bridge_owned = {("I", 0), ("Q", 0), ("M", 0)}
        for db in (200, 201, 202, 203, 121, 300, 701):
            bridge_owned.add(("DB", db))

    return sim.tags, bridge_active, bridge_owned


# ── main ──

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--host", default="127.0.0.1",
                     help="Default: talk to the backend directly (bypasses "
                          "the proxy) to isolate attach_to_server(). Use the "
                          "public IP + --port 102 to test through the real "
                          "precheck proxy instead.")
    ap.add_argument("--port", type=int, default=1102)
    ap.add_argument("--rack", type=int, default=0)
    ap.add_argument("--slot", type=int, default=2)
    ap.add_argument("--settle-seconds", type=float, default=None,
                     help="Wait between samples. Default: 1.5x "
                          "process_values.interval_seconds from config.")
    args = ap.parse_args()

    print()
    print("S7 Honeypot — Live DB/Area Read Validation")
    print("=" * 52)
    print()

    # ── [1] Load expected tags from the honeypot's own config/code ──
    print("[ 1 ] Loading expected tags from process_simulator.py + config.yaml")
    try:
        tags, bridge_active, bridge_owned = _load_tags(args.config)
        check(f"Loaded {len(tags)} configured tags", True,
              f"modbus_bridge active: {bridge_active}")
    except Exception as e:
        check("Load tags", False, str(e))
        sys.exit(1)
    print()

    if args.settle_seconds is None:
        import yaml
        cfg = yaml.safe_load(Path(args.config).read_text())
        interval = cfg.get("process_values", {}).get("interval_seconds", 2.0)
        args.settle_seconds = interval * 1.5

    # ── [2] Connect a real snap7 client ──
    print(f"[ 2 ] Connecting snap7 client to {args.host}:{args.port} "
          f"(rack={args.rack} slot={args.slot})")
    try:
        import snap7
        client = snap7.client.Client()
        try:
            client.connect(args.host, args.rack, args.slot, tcpport=args.port)
        except TypeError:
            # Older/newer python-snap7 builds may not accept tcpport= --
            # fall back to the 3-arg form (implies port 102).
            client.connect(args.host, args.rack, args.slot)
        ok = check("Connected", bool(client.get_connected())
                   if hasattr(client, "get_connected") else True)
        if not ok:
            sys.exit(1)
    except Exception as e:
        check("Connect", False, str(e))
        print(f"\n  {W}  Is backend_server.py (or the proxy) actually running "
              f"and reachable at {args.host}:{args.port}?")
        sys.exit(1)
    print()

    # ── [3] First sample: every tag in range ──
    print("[ 3 ] First read — value within configured bounds")
    sample1 = {}
    range_fail = 0
    read_fail = 0
    for t in tags:
        owned_by_bridge = (t.area, t.db_number if t.area == "DB" else 0) in bridge_owned
        size = _SIZE.get(t.pack_format, 4)
        try:
            raw = _read_area(client, t.area, t.db_number, t.offset, size)
            val = _unpack(t.pack_format, raw)
            sample1[t.name] = (raw, val)
            in_range = t.min_value <= (float(val) if not isinstance(val, bool) else float(val)) <= t.max_value \
                if t.min_value != t.max_value else True  # zero-width range (e.g. alarm word) always "in range"
            label = f"{t.name:24s} {t.area}{'' if t.area!='DB' else t.db_number}.@{t.offset:<3d} " \
                    f"{t.pack_format:5s} = {val}"
            if owned_by_bridge:
                label += "  [bridge-owned]"
            if not check(label, in_range,
                         "" if in_range else f"expected [{t.min_value}, {t.max_value}]"):
                range_fail += 1
        except Exception as e:
            check(f"{t.name:24s} {t.area}{'' if t.area!='DB' else t.db_number}.@{t.offset}",
                  False, f"read failed: {e}")
            read_fail += 1
    print()

    # ── [4] Second sample after a settle period: drift / monotonic checks ──
    print(f"[ 4 ] Waiting {args.settle_seconds:.1f}s, then re-reading "
          f"(drift / monotonic check)")
    time.sleep(args.settle_seconds)

    STATIC_OK = {"db300_alarm_word"}     # zero-width range tags: no motion expected
    MONOTONIC = {"marker_cycle_count", "db701_heartbeat", "db121_prod_count"}

    drift_fail = 0
    for t in tags:
        if t.name not in sample1:
            continue
        raw1, val1 = sample1[t.name]
        size = _SIZE.get(t.pack_format, 4)
        try:
            raw2 = _read_area(client, t.area, t.db_number, t.offset, size)
            val2 = _unpack(t.pack_format, raw2)
        except Exception as e:
            check(f"{t.name:24s} re-read", False, str(e))
            drift_fail += 1
            continue

        changed = raw1 != raw2
        if t.name in MONOTONIC:
            ok = changed  # must advance every tick
            check(f"{t.name:24s} advanced: {val1} -> {val2}", ok,
                  "" if ok else "counter did not advance -- CPU in STOP, or "
                                 "attach_to_server() write path not reaching "
                                 "this address")
        elif t.name in STATIC_OK or t.max_step == 0:
            check(f"{t.name:24s} static (expected): {val1} == {val2}", True)
            continue  # not a failure either way
        else:
            check(f"{t.name:24s} drifted: {val1} -> {val2}", changed,
                  "" if changed else "value never moved -- likely means "
                                      "attach_to_server() found no working "
                                      "write hook for this area/DB; falls "
                                      "back to a silent no-op (see "
                                      "process_simulator.py's own warning "
                                      "log at startup)")
        if not changed and t.name not in STATIC_OK and t.max_step != 0:
            drift_fail += 1
    print()

    # ── [5] DB999 must NOT be allocated (real S7 error expected) ──
    print("[ 5 ] DB999 correctly unallocated (real S7 address error expected)")
    db999_ok = False
    try:
        client.db_read(999, 0, 1)
        check("DB999 read", False,
              "expected an S7 error (S7ClientTests.cs relies on this) but "
              "the read succeeded -- pre-allocation may have over-reached")
    except Exception as e:
        db999_ok = check("DB999 read correctly raised an error", True, str(e))
    print()

    try:
        client.disconnect()
    except Exception:
        pass

    # ── Summary ──
    print("=" * 52)
    total_fail = range_fail + read_fail + drift_fail + (0 if db999_ok else 1)
    if total_fail == 0:
        print(f"  {P}  All checks passed — attach_to_server()'s memory_areas "
              f"guess is confirmed working against this python-snap7 build.")
    else:
        print(f"  {F}  {total_fail} check(s) failed — see details above.")
        if drift_fail or read_fail:
            print(f"       Likely cause: attach_to_server() in "
                  f"process_simulator.py / modbus_bridge.py did not find a "
                  f"working write hook for one or more areas on this "
                  f"python-snap7 version. Check the startup log for "
                  f"'Area enums found' / 'could not find S7Area enum' "
                  f"warnings, and consider migrating to the confirmed "
                  f"register_db()/register_raw_db() API noted in STATUS.md.")
    print()
    sys.exit(1 if total_fail else 0)


if __name__ == "__main__":
    # snap7 lives in the honeypot virtualenv, not the system Python. Running
    # this under `python3`/`sudo python` gives a bare "No module named 'snap7'"
    # that doesn't hint at the cause. Catch it here and point at the venv.
    try:
        import snap7  # noqa: F401
    except ImportError:
        import sys as _sys
        _sys.stderr.write(
            "\n  python-snap7 is not available under this interpreter.\n"
            "  This tool must run under the honeypot virtualenv:\n\n"
            "    sudo /opt/s7honeypot/venv/bin/python \\\n"
            "        /opt/s7honeypot/tools/verify_live_db_reads.py "
            "--host 127.0.0.1 --port 102 --rack 0 --slot 2\n\n"
            "  (You ran it under the system Python, which doesn't have snap7.)\n\n")
        _sys.exit(1)
    main()
