#!/usr/bin/env python3
"""
test_paths.py — the path resolver is the single source of truth for every
runtime state-file location. If it breaks, readers and writers disagree about
where files live — the exact class of bug that caused several regressions
(a database created in one place and read from another; a web portal reading a
different process-state file than the writer used).

These tests lock down that resolution: one config value must drive every path,
overrides must be honored, and a missing/broken config must fall back cleanly
rather than leaving a service with no paths.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import yaml
from paths import Paths, _DEFAULT_STATE_DIR

P = "\u2713"


def _write_cfg(**logging_kv) -> str:
    d = tempfile.mkdtemp()
    p = os.path.join(d, "config.yaml")
    with open(p, "w") as f:
        yaml.dump({"logging": logging_kv}, f)
    return p


def test_single_state_dir_drives_every_path():
    """One x-state-dir value must place every state file under it."""
    cfg = _write_cfg(state_dir="/srv/hp")
    p = Paths.load(cfg)
    assert str(p.state_dir)       == "/srv/hp"
    assert str(p.cpu_state)       == "/srv/hp/cpu_state.json"
    assert str(p.network_state)   == "/srv/hp/network_state.json"
    assert str(p.process_state)   == "/srv/hp/process_state.json"
    assert str(p.mac_spoof_state) == "/srv/hp/mac_spoof_state.json"
    # db and diag default under state_dir when not explicitly set
    assert str(p.honeypot_db)     == "/srv/hp/honeypot.db"
    assert str(p.diag_events)     == "/srv/hp/diag_events.jsonl"
    print(f"{P} one state_dir drives all six paths")


def test_explicit_overrides_win():
    """honeypot_db / diag_events_path override the state_dir default."""
    cfg = _write_cfg(
        state_dir="/srv/hp",
        honeypot_db="/data/custom.db",
        diag_events_path="/data/events.jsonl",
    )
    p = Paths.load(cfg)
    assert str(p.honeypot_db) == "/data/custom.db"
    assert str(p.diag_events) == "/data/events.jsonl"
    # the un-overridden ones still follow state_dir
    assert str(p.cpu_state) == "/srv/hp/cpu_state.json"
    print(f"{P} explicit db/diag overrides win; others still follow state_dir")


def test_missing_config_falls_back_to_default():
    """A missing config must not leave a service with no paths."""
    p = Paths.load("/nonexistent/config.yaml")
    assert str(p.state_dir) == _DEFAULT_STATE_DIR
    assert str(p.honeypot_db) == f"{_DEFAULT_STATE_DIR}/honeypot.db"
    print(f"{P} missing config -> default state dir, no crash")


def test_empty_logging_block_falls_back():
    """A config with no state_dir key falls back to the default."""
    cfg = _write_cfg()   # logging: {} with nothing in it
    p = Paths.load(cfg)
    assert str(p.state_dir) == _DEFAULT_STATE_DIR
    print(f"{P} empty logging block -> default state dir")


def test_all_paths_are_absolute():
    """Every resolved path must be absolute — a relative state path would
    resolve differently depending on each service's working directory."""
    cfg = _write_cfg(state_dir="/srv/hp")
    p = Paths.load(cfg)
    for name in ("state_dir", "cpu_state", "network_state", "process_state",
                 "mac_spoof_state", "honeypot_db", "diag_events"):
        val = getattr(p, name)
        assert os.path.isabs(str(val)), f"{name} is not absolute: {val}"
    print(f"{P} all resolved paths are absolute")


if __name__ == "__main__":
    test_single_state_dir_drives_every_path()
    test_explicit_overrides_win()
    test_missing_config_falls_back_to_default()
    test_empty_logging_block_falls_back()
    test_all_paths_are_absolute()
    print("\nAll paths resolver tests passed.")
