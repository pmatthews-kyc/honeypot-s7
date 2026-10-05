#!/usr/bin/env python3
"""
test_stop_deenergizes_outputs.py — on CPU STOP, the Q (output) area must
de-energize to zero while DB, M, and I hold their last value.

A real S7-300 stops driving its outputs the instant it enters STOP (they go to
the substitute/safe state), but DBs remain readable/writable and non-retentive
markers are only cleared by a subsequent restart, not by STOP itself. Freezing
Q at its last RUNNING value would show a state real hardware can't produce —
e.g. a pump output reading ON while the CPU reports STOP. Both data paths (the
built-in simulator and the OpenPLC bridge) must behave identically.
"""
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import struct
import process_simulator as ps

P = "\u2713"
_CFG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "config.yaml.example")


def test_simulator_deenergizes_Q_leaves_others():
    sim = ps.ProcessSimulator(_CFG)

    # Capture writes so we can see exactly what got zeroed.
    writes = {}
    sim._write_fn = lambda area, db, off, data: writes.__setitem__(
        (area, db, off), data)

    # Give Q tags and a DB/M tag non-zero values, as if running.
    for t in sim.tags:
        if t.area == "Q":
            t.value = 200            # outputs "on"
        elif t.name == "db200_temperature":
            t.value = 30.5
        elif t.name == "marker_cycle_count":
            t.value = 40000

    sim._deenergize_outputs()

    # Every Q tag must now be zero, in tag.value and in the snap7 write.
    q_tags = [t for t in sim.tags if t.area == "Q"]
    assert q_tags, "no Q tags in config — test can't validate"
    for t in q_tags:
        assert t.value == 0, f"{t.name} not zeroed (={t.value})"
    assert writes, "no snap7 writes issued for Q de-energize"
    for (area, _db, _off), data in writes.items():
        assert area == "Q", f"de-energize touched non-Q area {area}"
        assert data == b"\x00" * len(data), "Q write was not zero bytes"

    # DB and M must be untouched.
    db = next(t for t in sim.tags if t.name == "db200_temperature")
    mk = next(t for t in sim.tags if t.name == "marker_cycle_count")
    assert db.value == 30.5, "DB was wrongly cleared on STOP"
    assert mk.value == 40000, "M was wrongly cleared on STOP"
    print(f"{P} simulator: Q de-energized to 0, DB/M frozen")


def test_bridge_deenergizes_Q_leaves_others():
    from modbus_bridge import ModbusBridge
    b = ModbusBridge(_CFG)

    writes = {}
    b._write_fn = lambda area, db, off, data: writes.__setitem__(
        (area, db, off), data)

    # Seed cached portal values as if running: a Q output on, a DB value set.
    b._last_tag_values = {
        "output_byte0": 47,
        "db200_temperature": 30.5,
        "marker_cycle_count": 40000,
    }

    b._deenergize_outputs_stop()

    # Q-area mappings zeroed in snap7...
    assert writes, "bridge issued no Q de-energize writes"
    for (area, _db, _off), data in writes.items():
        assert area == "Q", f"bridge de-energize touched non-Q area {area}"
        assert data == b"\x00" * len(data)

    # ...and the cached Q value the portal shows is zero, DB/M untouched.
    assert b._last_tag_values["output_byte0"] == 0, "portal Q value not zeroed"
    assert b._last_tag_values["db200_temperature"] == 30.5, "DB wrongly cleared"
    assert b._last_tag_values["marker_cycle_count"] == 40000, "M wrongly cleared"
    print(f"{P} bridge: Q de-energized to 0 (snap7 + portal), DB/M frozen")


def test_bridge_deenergize_fires_once_per_stop_edge():
    from modbus_bridge import ModbusBridge
    b = ModbusBridge(_CFG)
    assert b._stopped_deenergized is False, "flag should start False (RUN)"
    print(f"{P} bridge STOP-edge flag initialises correctly")


if __name__ == "__main__":
    test_simulator_deenergizes_Q_leaves_others()
    test_bridge_deenergizes_Q_leaves_others()
    test_bridge_deenergize_fires_once_per_stop_edge()
    print("\nAll STOP de-energize tests passed.")
