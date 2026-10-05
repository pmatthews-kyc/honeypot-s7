"""
test_mac_spoof.py
-------------------
Tests the part of mac_spoof.py that's actually verifiable in this build
environment: MAC generation and persistence logic. apply_mac() (the
actual `ip link`/`macchanger` interface manipulation) requires real
network hardware and root privileges this environment doesn't have --
that part needs validation on real target hardware, not here. See
module docstring in mac_spoof.py and INSTALL.md.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import tempfile
from pathlib import Path

from mac_spoof import load_or_generate_mac, SIEMENS_OUIS, DEFAULT_OUI


def test_generates_mac_with_correct_oui_prefix():
    state_path = Path(tempfile.mkdtemp()) / "mac_spoof_state.json"
    mac = load_or_generate_mac("28:63:36", state_path)
    assert mac.upper().startswith("28:63:36")
    assert len(mac.split(":")) == 6, "must be a full 6-octet MAC"
    print("Generated MAC has correct OUI prefix and full length: OK")


def test_persists_across_repeated_calls():
    """The core requirement: the SAME mac must come back every time for
    the same OUI, since a real NIC's MAC never changes across reboots --
    regenerating fresh each call would itself be the tell this feature
    exists to avoid."""
    state_path = Path(tempfile.mkdtemp()) / "mac_spoof_state.json"
    first = load_or_generate_mac("28:63:36", state_path)
    for _ in range(5):
        again = load_or_generate_mac("28:63:36", state_path)
        assert again == first, "MAC must be stable across repeated calls"
    print("MAC persists identically across 5 repeated calls: OK")


def test_different_oui_triggers_regeneration():
    state_path = Path(tempfile.mkdtemp()) / "mac_spoof_state.json"
    mac_a = load_or_generate_mac("28:63:36", state_path)
    mac_b = load_or_generate_mac("AC:64:17", state_path)
    assert mac_a != mac_b
    assert mac_b.upper().startswith("AC:64:17")
    # and it should now be stable for the new OUI too
    mac_b_again = load_or_generate_mac("AC:64:17", state_path)
    assert mac_b == mac_b_again
    print("Switching OUI regenerates once, then persists for the new OUI: OK")


def test_all_default_ouis_are_well_formed():
    for oui in SIEMENS_OUIS:
        parts = oui.split(":")
        assert len(parts) == 3, f"OUI {oui} should have exactly 3 octets"
        for p in parts:
            assert len(p) == 2 and all(c in "0123456789ABCDEFabcdef" for c in p)
    assert DEFAULT_OUI in SIEMENS_OUIS
    print("All configured Siemens OUIs are well-formed hex triples: OK")


def test_corrupted_state_file_recovers_gracefully():
    """If the state file exists but is corrupted/unreadable, generation
    should recover rather than crash -- matches the defensive pattern
    used elsewhere in this project (cpu_state.py, network state)."""
    state_path = Path(tempfile.mkdtemp()) / "mac_spoof_state.json"
    state_path.write_text("{ not valid json")
    mac = load_or_generate_mac("28:63:36", state_path)
    assert mac.upper().startswith("28:63:36")
    print("Corrupted state file handled gracefully, regenerates: OK")


if __name__ == "__main__":
    test_generates_mac_with_correct_oui_prefix()
    test_persists_across_repeated_calls()
    test_different_oui_triggers_regeneration()
    test_all_default_ouis_are_well_formed()
    test_corrupted_state_file_recovers_gracefully()
    print("\nAll mac_spoof tests passed.")
