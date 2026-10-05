#!/usr/bin/env python3
"""
test_diag_log_safety.py — the diagnostic buffer must never leak
what this device actually is.

The diag_events table is read by attackers through two surfaces:
  * SZL 0x00A0 over S7comm (menu option 5 in a typical S7 client)
  * the web portal Diagnostic Buffer page

An earlier install_update.sh wrote "Honeypot software updated —
diagnostic database ready" into it. That single line announces the
honeypot on the surface most carefully built to look like a real PLC.
These tests exist so that never ships again.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))
import os, sys, tempfile
from pathlib import Path
import diag_log

P = "\u2713"


def _fresh_db():
    tmp = tempfile.mktemp(suffix=".db")
    diag_log._DB_PATH = Path(tmp)
    diag_log._init_db()
    # log_s7_read rate-limits per (peer_ip, db) for 60s using module-level
    # state, which otherwise leaks between tests and suppresses the call.
    diag_log._s7_read_last.clear()
    return tmp


def test_revealing_entries_refused():
    tmp = _fresh_db()
    try:
        for desc in [
            "Honeypot software updated \u2014 diagnostic database ready",
            "Schema recreated - write test",
            "snap7 backend restarted",
            "OpenPLC Modbus bridge reconnected",
            "process_simulator tick failed",
            "Python traceback in web_portal",
            "Deployed new version, install complete",
            "Connected to 127.0.0.1 for debug",
        ]:
            diag_log.append_event(0x48, 0x00, desc, source="system")
        stored = diag_log.load_events()
        assert not stored, f"leaked {len(stored)} revealing entries: {stored}"
        print(f"{P} revealing entries refused (honeypot/snap7/openplc/debug/...)")
    finally:
        os.unlink(tmp)


def test_plausible_plc_events_accepted():
    tmp = _fresh_db()
    try:
        expected = [
            "Operating mode: RUN \u2192 STOP \u2014 remote command (from 192.0.2.20)",
            "Operating mode: STOP \u2192 RUN \u2014 remote command (from 192.0.2.20)",
            "OB1: Pump start sequence initiated",
            "OB1: Flow confirmed \u2014 process running (temp 29.8\u00b0C)",
            "OB1: Batch complete - pump stop (level 9.9%)",
            "Process alarm: High temperature (33.8\u00b0C)",
            "Process alarm cleared \u2014 temperature normal",
            "Scan cycle monitoring: OK",
            "Power up",
            "Watchdog reset cleared",
        ]
        for d in expected:
            diag_log.append_event(0x48, 0x10, d, source="process")
        got = len(diag_log.load_events())
        assert got == len(expected), \
            f"filter too aggressive: {got}/{len(expected)} stored"
        print(f"{P} all {got} plausible PLC events accepted")
    finally:
        os.unlink(tmp)


def test_helpers_still_work():
    """The built-in helpers must pass their own filter."""
    tmp = _fresh_db()
    try:
        diag_log.log_stop("192.0.2.20")
        diag_log.log_run("192.0.2.20")
        diag_log.log_process_event("OB1: Pump stopped \u2014 returning to idle", {})
        diag_log.log_s7_read("192.0.2.20", 200, {
            "db200_temperature": 29.7, "db200_flow": 118.5,
            "db200_level": 22.0, "cpu_state": "RUN"})
        # load_events() hides s7_read from clients by design, so check the
        # analyst view to confirm all four helpers passed the safety filter.
        n = len(diag_log.load_events(include_operator_only=True))
        assert n == 4, f"a built-in helper was blocked by the filter ({n}/4)"
        visible = len(diag_log.load_events())
        assert visible == 3, f"expected 3 client-visible, got {visible}"
        print(f"{P} all 4 helpers pass the filter; 3 client-visible, "
              f"s7_read analyst-only")
    finally:
        os.unlink(tmp)



def test_s7_read_events_hidden_from_clients():
    """
    A real S7-300 diagnostic buffer records mode transitions, hardware
    faults, diagnostic interrupts and program errors. It does NOT record
    successful read operations.

    Rendering "[192.0.2.20] S7: Read DB200 - temp=30.1C flow=120.0 ..."
    in a buffer the attacker can read tells them their activity is being
    logged, and puts forensic data on the deception surface. The events
    stay in the database for analyst queries but must never be served to
    a client via SZL 0x00A0 or the web portal.
    """
    tmp = _fresh_db()
    try:
        diag_log.log_stop("192.0.2.20")
        diag_log.log_process_event("OB1: Pump start sequence initiated", {})
        diag_log.log_s7_read("192.0.2.20", 200, {
            "db200_temperature": 30.1, "db200_flow": 120.0,
            "db200_level": 24.9, "cpu_state": "RUN"})

        visible = diag_log.load_events()
        assert len(visible) == 2, f"expected 2 client-visible, got {len(visible)}"
        assert not any("S7: Read" in d for _, d in visible), \
            "s7_read event leaked to the attacker-visible surface"

        full = diag_log.load_events(include_operator_only=True)
        assert len(full) == 3, f"analyst view lost events ({len(full)}/3)"
        assert any("S7: Read" in d for _, d in full), \
            "s7_read event lost - analyst intelligence destroyed"
        print(f"{P} s7_read hidden from clients, retained for analysts")
    finally:
        os.unlink(tmp)


if __name__ == "__main__":
    test_revealing_entries_refused()
    test_plausible_plc_events_accepted()
    test_helpers_still_work()
    test_s7_read_events_hidden_from_clients()
    print("\nAll diag_log safety tests passed.")
