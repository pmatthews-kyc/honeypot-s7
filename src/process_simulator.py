"""
process_simulator.py
---------------------
Makes S7 reads return values that look like a live industrial process
instead of static zeros.

WHAT IT SIMULATES
=================
A plausible S7-315-2 PN/DP controlling a manufacturing line.
Three categories:

1. Process area I/Q/M (Inputs / Outputs / Markers)
   Digital I/O bits change slowly as virtual field devices toggle.
   Markers hold intermediate results: step counter, cycle counter,
   accumulated totals.  A real PLC in RUN never has all-zero I/Q/M.

2. DB 500/501 — structured test tags (unchanged from original)
   Confirmed layout from S7ClientTests.cs: byte, bool, int, word,
   dint, real at known offsets.  Process simulator writes here
   so snap7-based test clients see varying values.

3. DB 121-123, 200-203, 300, 701-703 — common cyclic-read DBs
   Observed in 2-S7comm-VarService-CyclicData-1s.pcap.
   A real SCADA polls these every second; returning zeros for all
   of them is an easy tell.  This simulator writes:
     DB 121  – HMI setpoints/status (WORDs)
     DB 200  – Process measurements (REALs: temperature, flow, level)
     DB 300  – Status / alarm words (WORDs, mostly 0 with occasional bits)
     DB 701  – Communication exchange (WORDs)

SNAP7 AREA ENCODING
====================
memory_areas key = (area_enum, number)
  DB:  (S7Area.DB,  db_number)   confirmed from prior work
  I:   (S7Area.PE,  0)           PE = Process Eingänge (inputs)
  Q:   (S7Area.PA,  0)           PA = Process Ausgänge (outputs)
  M:   (S7Area.MK,  0)           MK = Merker (markers)

Area enum candidates tried in priority order per snap7 release history.

DESIGN NOTE
============
Not a physics model — just enough bounded continuity so repeated reads
look like motion, not static values.  Real process values don't teleport
between polls and don't sit at exactly zero for minutes at a time.
"""

from __future__ import annotations

import logging
import math
import random
import struct
import threading
import time
from dataclasses import dataclass, field

import yaml

import cpu_state

log = logging.getLogger("process_simulator")


# ── packing helpers ───────────────────────────────────────────────────────────

def _pack_value(value: float, pack_format: str) -> bytes:
    v = value
    if pack_format == "real":
        return struct.pack(">f", v)
    elif pack_format == "dint":
        return struct.pack(">i", int(v))
    elif pack_format == "int":
        return struct.pack(">h", int(v))
    elif pack_format == "word":
        return struct.pack(">H", int(v) & 0xFFFF)
    elif pack_format == "byte":
        return bytes([int(v) & 0xFF])
    elif pack_format == "bool":
        return bytes([1 if v > 0.5 else 0])
    else:
        return struct.pack(">f", v)


# ── ProcessTag ────────────────────────────────────────────────────────────────

@dataclass
class ProcessTag:
    name: str
    offset: int
    min_value: float
    max_value: float
    max_step: float
    # area: "DB", "I" (inputs), "Q" (outputs), "M" (markers)
    area: str = "DB"
    db_number: int = 0          # only used when area="DB"
    setpoint: float | None = None
    setpoint_gravity: float = 0.0
    event_chance: float = 0.0
    event_multiplier: float = 4.0
    influenced_by: list[dict] = field(default_factory=list)
    pack_format: str = "real"
    value: float = field(init=False)

    def __post_init__(self):
        start = self.setpoint if self.setpoint is not None else \
                (self.min_value + self.max_value) / 2
        self.value = start

    def step(self, current_values: dict[str, float] | None = None) -> float:
        step_size = self.max_step
        if self.event_chance and random.random() < self.event_chance:
            step_size *= self.event_multiplier
        delta = random.uniform(-step_size, step_size)
        if self.setpoint is not None and self.setpoint_gravity > 0:
            delta += (self.setpoint - self.value) * self.setpoint_gravity
        if current_values:
            for inf in self.influenced_by:
                sv = current_values.get(inf["source"])
                if sv is not None:
                    delta += (sv - inf["reference"]) * inf["coefficient"]
        self.value = max(self.min_value, min(self.max_value, self.value + delta))
        return self.value


# ── built-in industrial profile ───────────────────────────────────────────────

def _builtin_tags() -> list[ProcessTag]:
    """
    Standard industrial tags added automatically regardless of config.
    Covers I/Q/M areas and the DB numbers observed in real cyclic captures.

    I area  (Process Inputs):
      IB0   – digital inputs byte 0: conveyor sensors, pushbuttons
      IB1   – digital inputs byte 1: machine state sensors
      IW2   – encoder counter word (0–27648 = 0–100%)
      IW4   – analog input (0–27648 scaled to field signal)

    Q area  (Process Outputs):
      QB0   – digital outputs byte 0: motor contactor, valve solenoids
      QB1   – digital outputs byte 1: indicator lights, enable signals
      QW2   – analog output: speed reference (0–27648)

    M area  (Markers / internal state):
      MB0   – PLC step/state machine (0–15)
      MB1   – error / warning flags byte
      MW2   – OB1 cycle counter (increments every scan)
      MD4   – accumulated production counter (DWORD)

    DB 121  – HMI setpoints (WORDs: speed ref, temperature SP, mode word)
    DB 200  – Process measurements (REALs: temp °C, flow l/min, pressure bar)
    DB 300  – Status / alarm register (WORDs: mostly 0, occasional alarm bits)
    DB 701  – Cross-PLC communication exchange (WORDs, slowly changing)
    """
    tags = []

    # ── I area (Process Inputs) ───────────────────────────────────────────
    # IB0: digital inputs — about half the bits set; slow toggle
    tags.append(ProcessTag(
        name="input_byte0", area="I", offset=0,
        min_value=0, max_value=255, max_step=3,
        setpoint=0b00101101, setpoint_gravity=0.02,
        event_chance=0.08, event_multiplier=2,
        pack_format="byte",
    ))
    # IB1: more digital inputs — fewer bits set (limit switches)
    tags.append(ProcessTag(
        name="input_byte1", area="I", offset=1,
        min_value=0, max_value=255, max_step=2,
        setpoint=0b01000010, setpoint_gravity=0.02,
        event_chance=0.05, event_multiplier=2,
        pack_format="byte",
    ))
    # IW2: encoder position (0–27648, representing 0–100% of travel)
    tags.append(ProcessTag(
        name="input_encoder", area="I", offset=2,
        min_value=0, max_value=27648, max_step=180,
        setpoint=13824, setpoint_gravity=0.005,
        event_chance=0.03, event_multiplier=3,
        pack_format="word",
    ))
    # IW4: analog sensor (temperature transmitter, 4–20mA → 0–27648)
    tags.append(ProcessTag(
        name="input_analog1", area="I", offset=4,
        min_value=5530, max_value=18432, max_step=120,
        setpoint=12000, setpoint_gravity=0.02,
        pack_format="word",
    ))

    # ── Q area (Process Outputs) ──────────────────────────────────────────
    # QB0: motor contactor + valve solenoids
    tags.append(ProcessTag(
        name="output_byte0", area="Q", offset=0,
        min_value=0, max_value=255, max_step=2,
        setpoint=0b00101100, setpoint_gravity=0.02,
        event_chance=0.06, event_multiplier=2,
        pack_format="byte",
    ))
    # QB1: indicator lights + enable signals
    tags.append(ProcessTag(
        name="output_byte1", area="Q", offset=1,
        min_value=0, max_value=255, max_step=1,
        setpoint=0b11000010, setpoint_gravity=0.02,
        event_chance=0.04, event_multiplier=2,
        pack_format="byte",
    ))
    # QW2: analog speed reference to VFD (0–27648 = 0–50 Hz)
    tags.append(ProcessTag(
        name="output_speed_ref", area="Q", offset=2,
        min_value=0, max_value=27648, max_step=200,
        setpoint=16384, setpoint_gravity=0.015,
        event_chance=0.02, event_multiplier=2,
        pack_format="word",
    ))

    # ── M area (Markers / internal state) ────────────────────────────────
    # MB0: PLC step/state machine byte (0=idle, 1=starting, 2=running,
    #       3=stopping, 4=alarm, etc.)  Spends most time at step 2.
    tags.append(ProcessTag(
        name="marker_step", area="M", offset=0,
        min_value=0, max_value=4, max_step=0.5,
        setpoint=2, setpoint_gravity=0.08,
        event_chance=0.04, event_multiplier=2,
        pack_format="byte",
    ))
    # MB1: error / warning flags (mostly 0)
    tags.append(ProcessTag(
        name="marker_flags", area="M", offset=1,
        min_value=0, max_value=15, max_step=1,
        setpoint=0, setpoint_gravity=0.15,
        event_chance=0.03, event_multiplier=3,
        pack_format="byte",
    ))
    # MW2: OB1 cycle counter (monotonically increasing, wraps at 65535)
    # Modelled as a ramp — always increasing
    tags.append(ProcessTag(
        name="marker_cycle_count", area="M", offset=2,
        min_value=0, max_value=65535, max_step=1,
        setpoint=None, setpoint_gravity=0.0,
        pack_format="word",
    ))
    tags[-1].value = random.randint(0, 60000)  # start mid-range

    # ── DB 121: HMI setpoints (WORDs) ────────────────────────────────────
    # Typical HMI ↔ PLC exchange: speed setpoint, temperature setpoint,
    # production count, mode word, status word.
    tags += [
        ProcessTag(name="db121_speed_sp", area="DB", db_number=121, offset=0,
                   min_value=8000, max_value=20000, max_step=100,
                   setpoint=14000, setpoint_gravity=0.02, pack_format="word"),
        ProcessTag(name="db121_temp_sp", area="DB", db_number=121, offset=2,
                   min_value=5000, max_value=8000, max_step=50,
                   setpoint=6500, setpoint_gravity=0.03, pack_format="word"),
        ProcessTag(name="db121_prod_count", area="DB", db_number=121, offset=4,
                   min_value=0, max_value=65535, max_step=1,
                   setpoint=None, pack_format="word"),
        ProcessTag(name="db121_mode_word", area="DB", db_number=121, offset=6,
                   min_value=1, max_value=3, max_step=0.3,
                   setpoint=1, setpoint_gravity=0.20, pack_format="word"),
        ProcessTag(name="db121_status_word", area="DB", db_number=121, offset=8,
                   min_value=0x0021, max_value=0x0027, max_step=1,
                   setpoint=0x0023, setpoint_gravity=0.05, pack_format="word"),
    ]
    tags[-4].value = random.randint(1000, 5000)  # prod_count starts mid

    # ── DB 200: Process measurements (REALs) ─────────────────────────────
    # Temperature (°C), flow (l/min), pressure (bar), tank level (%)
    tags += [
        ProcessTag(name="db200_temperature", area="DB", db_number=200, offset=0,
                   min_value=35.0, max_value=85.0, max_step=0.3,
                   setpoint=65.0, setpoint_gravity=0.02,
                   event_chance=0.01, event_multiplier=5, pack_format="real"),
        ProcessTag(name="db200_flow", area="DB", db_number=200, offset=4,
                   min_value=0.0, max_value=120.0, max_step=1.5,
                   setpoint=80.0, setpoint_gravity=0.03,
                   event_chance=0.02, event_multiplier=3, pack_format="real"),
        ProcessTag(name="db200_pressure", area="DB", db_number=200, offset=8,
                   min_value=0.5, max_value=6.0, max_step=0.05,
                   setpoint=3.5, setpoint_gravity=0.03, pack_format="real"),
        ProcessTag(name="db200_level", area="DB", db_number=200, offset=12,
                   min_value=10.0, max_value=95.0, max_step=0.4,
                   setpoint=60.0, setpoint_gravity=0.01, pack_format="real"),
        ProcessTag(name="db200_temp2", area="DB", db_number=200, offset=16,
                   min_value=20.0, max_value=60.0, max_step=0.2,
                   setpoint=42.0, setpoint_gravity=0.02, pack_format="real"),
    ]

    # ── DB 300: Status / alarm word ───────────────────────────────────────
    # Normally 0; alarm bits set occasionally.
    tags.append(ProcessTag(
        name="db300_alarm_word", area="DB", db_number=300, offset=0,
        min_value=0, max_value=0, max_step=0,
        setpoint=0, setpoint_gravity=0.30,
        event_chance=0.02, event_multiplier=16,
        pack_format="word",
    ))
    tags.append(ProcessTag(
        name="db300_status_word", area="DB", db_number=300, offset=2,
        min_value=0x0001, max_value=0x000F, max_step=1,
        setpoint=0x0003, setpoint_gravity=0.05, pack_format="word",
    ))

    # ── DB 701: Cross-PLC / SCADA communication exchange ─────────────────
    tags += [
        ProcessTag(name="db701_cmd_word", area="DB", db_number=701, offset=0,
                   min_value=0, max_value=3, max_step=0.3,
                   setpoint=1, setpoint_gravity=0.10, pack_format="word"),
        ProcessTag(name="db701_feedback", area="DB", db_number=701, offset=2,
                   min_value=0, max_value=3, max_step=0.2,
                   setpoint=1, setpoint_gravity=0.10, pack_format="word"),
        ProcessTag(name="db701_heartbeat", area="DB", db_number=701, offset=4,
                   min_value=0, max_value=65535, max_step=1,
                   setpoint=None, pack_format="word"),
    ]
    tags[-1].value = random.randint(0, 30000)

    return tags


# ── ProcessSimulator ──────────────────────────────────────────────────────────

class ProcessSimulator:
    def __init__(self, config_path: str = "config.yaml", interval: float = 2.0):
        configure_paths(config_path)   # resolve _PROCESS_STATE_PATH from config
        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        pv_cfg = cfg.get("process_values", {})
        self.enabled  = pv_cfg.get("enabled", False)
        self.interval = pv_cfg.get("interval_seconds", interval)

        # Config-driven tags (DB500/DB501 and any user-added tags)
        config_tags: list[ProcessTag] = []
        for tc in pv_cfg.get("tags", []):
            config_tags.append(ProcessTag(
                name=tc["name"],
                area=tc.get("area", "DB"),
                db_number=tc.get("db_number", tc.get("db_number", 0)),
                offset=tc["offset"],
                min_value=tc["min"],
                max_value=tc["max"],
                max_step=tc["max_step"],
                setpoint=tc.get("setpoint"),
                setpoint_gravity=tc.get("setpoint_gravity", 0.0),
                event_chance=tc.get("event_chance", 0.0),
                event_multiplier=tc.get("event_multiplier", 4.0),
                influenced_by=tc.get("influenced_by", []),
                pack_format=tc.get("pack_format", "real"),
            ))

        # Built-in tags are always added when the simulator is enabled.
        # They cover I/Q/M and the common SCADA-polled DBs so those areas
        # never return static zeros.
        self.tags: list[ProcessTag] = config_tags + _builtin_tags()

        self._stop      = threading.Event()
        self._thread: threading.Thread | None = None
        self._write_fn  = None   # set by attach_to_server()
        self._read_fn   = None   # set by attach_to_server(); syncs bridge→tag.value
        # When modbus_bridge is active it writes process_state.json directly.
        # Set this flag so the simulator doesn't overwrite the bridge's values.
        self.skip_process_state: bool = False
        # Data-acquisition watchdog (bridge mode only). Loaded from config;
        # dormant unless skip_process_state is True (i.e. the bridge owns
        # the process values and can therefore lose communication).
        _wd = pv_cfg.get("watchdog", {})
        self._wd_threshold   = float(_wd.get("fault_threshold_seconds", 60))
        self._wd_fault_msg   = _wd.get("fault_event",   "Process data acquisition fault")
        self._wd_restore_msg = _wd.get("restore_event", "Process data acquisition restored")
        self._wd_fault_active: bool = False   # True while a fault is being reported
        self._last_seq_state: int | None = None  # for process event detection
        # When modbus_bridge is active, these sets tell the simulator to
        # skip tags that are owned by the bridge so they don't get
        # overwritten by the random-walk on the next tick.
        self.exclude_areas: set[str] = set()   # e.g. {"I","Q","M"}
        self.exclude_dbs:   set[int] = set()   # e.g. {200, 121, 300}

    def _bridge_data_age(self) -> float:
        """
        Seconds since the bridge last refreshed process_state.json.
        The bridge writes it every poll (~0.5s), so a large age means the
        bridge has stopped delivering data. Returns a large number if the
        file is missing. Only meaningful in bridge mode.
        """
        try:
            import os, time as _t
            return _t.time() - os.stat(_PROCESS_STATE_PATH).st_mtime
        except FileNotFoundError:
            return 1e9
        except Exception:
            return 0.0

    # ── server attachment ─────────────────────────────────────────────────

    def attach_to_server(self, server) -> bool:
        """
        Build write/read functions that operate on the pinned ctypes buffers
        created by _preallocate_dbs() and registered with snap7 via
        Srv_RegisterArea().  Writing to a ctypes element (buf[i] = x) updates
        the C-level memory that snap7 points to, so the next S7 read request
        returns the new value.

        Previous approach wrote to server.memory_areas[key] which was a plain
        Python bytearray.  snap7 had no pointer to that bytearray — it was
        serving from its own C-level registered memory — so writes were silently
        discarded and S7 reads always returned zeros.
        """
        s7_buffers = getattr(server, "s7_buffers", None)
        if not s7_buffers:
            log.warning("server has no s7_buffers — _preallocate_dbs() may have "
                        "failed to register areas with snap7; reads will return zeros")
            return False

        log.info("attach_to_server: using s7_buffers (%d areas registered)",
                 len(s7_buffers))

        def write_fn(area: str, number: int, offset: int, data: bytes) -> None:
            key = (area, number if area == "DB" else 0)
            buf = s7_buffers.get(key)
            if buf is None:
                return
            end = min(offset + len(data), len(buf))
            # bytearray slice assignment — mutates the SAME object snap7
            # serves reads from (server.memory_areas holds this reference)
            buf[offset:end] = data[:end - offset]

        def read_fn(area: str, number: int, offset: int, length: int) -> bytes | None:
            """Read current snap7 buffer bytes (same memory snap7 serves)."""
            key = (area, number if area == "DB" else 0)
            buf = s7_buffers.get(key)
            if buf is None:
                return None
            return bytes(buf[offset:offset + length])

        self._write_fn = write_fn
        self._read_fn  = read_fn
        return True

    # ── simulation tick ───────────────────────────────────────────────────

    def _tick(self) -> None:
        # Snapshot pre-tick values so cross-tag influences are consistent
        current = {t.name: t.value for t in self.tags}

        for t in self.tags:
            # Skip tags owned by the modbus_bridge when it is active.
            if t.area in self.exclude_areas:
                continue
            if t.area == "DB" and t.db_number in self.exclude_dbs:
                continue
            # marker_step is driven by a real state machine below, not the
            # random walk — a sequencer that runs backwards (2->1, 4->3) is
            # impossible on a real PLC and produces nonsense diagnostic events.
            if t.name == "marker_step":
                continue
            if t.name == "marker_cycle_count":
                t.value = (t.value + 1) % 65536
                if self._write_fn:
                    self._write_fn(t.area, t.db_number, t.offset,
                                   _pack_value(t.value, t.pack_format))
            elif t.name == "db701_heartbeat":
                t.value = (t.value + 1) % 65536
                if self._write_fn:
                    self._write_fn(t.area, t.db_number, t.offset,
                                   _pack_value(t.value, t.pack_format))
            elif t.name == "db121_prod_count":
                # Production counter increments slowly ~0-3 parts per tick
                t.value = min(65535, t.value + random.randint(0, 2))
                if self._write_fn:
                    self._write_fn(t.area, t.db_number, t.offset,
                                   _pack_value(t.value, t.pack_format))
            else:
                new_val = t.step(current)
                packed  = _pack_value(new_val, t.pack_format)
                if self._write_fn:
                    try:
                        self._write_fn(t.area, t.db_number, t.offset, packed)
                    except Exception as exc:
                        log.error("Write failed %s (area=%s db=%d off=%d): %s",
                                  t.name, t.area, t.db_number, t.offset, exc)
                log.debug("%s = %.2f (area=%s DB%d off=%d)",
                          t.name, new_val, t.area, t.db_number, t.offset)

        # Advance the marker_step sequencer with real state-machine logic
        # (not random walk) so its transitions are always valid.
        self._advance_sequencer()

        if not self.skip_process_state:
            # Default (simulator) mode: the simulator IS the data source, so
            # it writes the snapshot every tick and there is nothing external
            # to lose communication with. The watchdog does not apply here.
            _write_process_state_impl(self.tags, cpu_state="RUN")
            self._check_seq_transition()
        else:
            # Bridge mode: the bridge owns process_state.json. We only watch
            # its freshness and raise/clear a data-acquisition fault. We do
            # NOT write values ourselves — on a fault, values FREEZE at their
            # last bridge-written state so the web portal and S7comm DB reads
            # stay consistent (both frozen, both explained by the event).
            self._run_acquisition_watchdog()

    def _run_acquisition_watchdog(self) -> None:
        """
        Detect and report loss of process-data acquisition from the bridge.
        Called each tick in bridge mode. Raises one diagnostic event when
        data goes stale past the threshold, and one when it recovers.

        Recovery is detected by the BRIDGE overwriting the snapshot, not by
        file age: while a fault is active this method rewrites the file (to
        keep the frozen values inside the portal's staleness window and set
        the COMM_FAULT banner flag), which refreshes the mtime. If recovery
        were judged by age, our own refresh would make it look recovered on
        the very next tick and the fault would flap fault->restored->fault.
        Instead, while faulted we treat a snapshot whose cpu_state is no
        longer COMM_FAULT as proof the bridge has resumed writing.
        """
        if not self._wd_fault_active:
            # Not currently faulted: a stale file past threshold raises a fault.
            if self._bridge_data_age() > self._wd_threshold:
                self._wd_fault_active = True
                log.warning("Process data acquisition fault: no bridge update "
                            "for >%.0fs — values frozen, event raised",
                            self._wd_threshold)
                self._raise_watchdog_event(self._wd_fault_msg)
                self._mark_process_state_stopped()
        else:
            # Currently faulted: recovery only when the bridge overwrites our
            # COMM_FAULT marker with a fresh snapshot of its own.
            if self._bridge_wrote_since_fault():
                self._wd_fault_active = False
                log.info("Process data acquisition restored (bridge resumed)")
                self._raise_watchdog_event(self._wd_restore_msg)
            else:
                # Still down: keep the frozen snapshot fresh so the portal
                # doesn't lose the overview to the staleness window.
                self._mark_process_state_stopped()

    def _bridge_wrote_since_fault(self) -> bool:
        """
        True if the process snapshot's cpu_state is no longer COMM_FAULT,
        meaning the bridge has written a fresh snapshot since we marked the
        fault. Missing/unreadable file counts as still-faulted.
        """
        try:
            import json
            from pathlib import Path
            data = json.loads(Path(_PROCESS_STATE_PATH).read_text())
            return data.get("cpu_state") != "COMM_FAULT"
        except Exception:
            return False

    def _raise_watchdog_event(self, description: str) -> None:
        """Write one watchdog event to the diagnostic buffer (both surfaces)."""
        try:
            import diag_log as _dl
            _dl.log_process_event(description, {})
        except Exception as exc:
            log.debug("watchdog event log failed: %s", exc)

    def _mark_process_state_stopped(self) -> None:
        """
        Flag the frozen snapshot so the web portal shows a fault banner.
        Rewrites process_state.json in place with the SAME tag values the
        bridge last wrote (values freeze — we do not substitute our own),
        only changing cpu_state to signal the fault to the portal.
        """
        try:
            import json, os, time
            from pathlib import Path
            if not os.path.exists(_PROCESS_STATE_PATH):
                return
            data = json.loads(Path(_PROCESS_STATE_PATH).read_text())
            data["cpu_state"] = "COMM_FAULT"      # portal renders the banner
            data["timestamp"] = time.time()        # keep it inside staleness window
            tmp = _PROCESS_STATE_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, _PROCESS_STATE_PATH)
        except Exception as exc:
            log.debug("could not mark process_state COMM_FAULT: %s", exc)

    def _run(self) -> None:
        was_running = True   # tracks the RUN->STOP edge so de-energizing fires once
        while not self._stop.is_set():
            # Honour the CPU state: a real S7-300 in STOP does not execute
            # OB1, so process values freeze.  The cycle counter also stops
            # incrementing (that's what makes STOP detectable to live monitors).
            state = cpu_state.read_cpu_state()
            if state == "RUN":
                self._tick()
                was_running = True
            else:
                if was_running:
                    # Edge-triggered: fires exactly once per RUN->STOP
                    # transition, not on every tick while stopped.
                    self._deenergize_outputs()
                    was_running = False
                log.debug("Process simulator paused (CPU in STOP)")
                # Still write the state file with frozen values so the web
                # portal can display them (with a STOP indicator) rather than
                # hiding the process overview after the 30s staleness window.
                # Skipped when modbus_bridge is active — bridge owns this file.
                if not self.skip_process_state:
                    _write_process_state_impl(self.tags, cpu_state=state)
            self._stop.wait(self.interval)

    def _deenergize_outputs(self) -> None:
        """
        Zero the Q (process output) area on the RUN->STOP transition.

        A real S7-300 stops driving its outputs the instant it enters STOP --
        OB1 halts, and the CPU commands the output modules to their
        substitute state (normally de-energized/zero) rather than continuing
        to show whatever OB1 last wrote. Freezing Q at its last RUNNING value
        (which is what simply pausing the tick loop would do) produces a
        state a real device can't show: e.g. a pump output reading ON while
        the CPU reports STOP.

        DB, M, and I are NOT touched here -- they legitimately hold their
        last value through STOP (DBs are always readable/writable in STOP;
        non-retentive M is only cleared by a subsequent restart, not by STOP
        alone; I is a read sample that just stops refreshing).

        Runs once per transition, not every tick, both to match real
        hardware (an edge event, not a continuous re-zero) and to avoid
        fighting any operator write to Q while stopped.
        """
        import struct
        for t in self.tags:
            if t.area != "Q":
                continue
            t.value = 0
            if self._write_fn:
                self._write_fn(t.area, t.db_number, t.offset,
                               _pack_value(0, t.pack_format))
        log.info("CPU entered STOP: Q (process outputs) de-energized to 0 "
                 "-- DB/M/I remain frozen at last value")

    # ── public API ────────────────────────────────────────────────────────

    def start(self, server=None) -> None:
        if not self.enabled:
            log.info("Process simulator disabled in config, not starting")
            return
        if server is not None:
            self.attach_to_server(server)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        n_db  = sum(1 for t in self.tags if t.area == "DB")
        n_iqm = sum(1 for t in self.tags if t.area in ("I", "Q", "M"))
        log.info("Process simulator started: %d DB tags, %d I/Q/M tags, "
                 "%.1fs interval", n_db, n_iqm, self.interval)

    # ── seq_state transition detection (built-in simulator only) ─────────
    _SIM_SEQ_EVENTS: dict = {
        (0, 1): "OB1: Pump start sequence initiated",
        (1, 2): "OB1: Flow confirmed \u2014 process running",
        (2, 3): "OB1: Low level warning \u2014 pump stop",
        (2, 4): "Process alarm: High temperature",
        (3, 0): "OB1: Pump stopped \u2014 returning to idle",
        (4, 0): "Process alarm cleared \u2014 temperature normal",
    }

    def _advance_sequencer(self) -> None:
        """
        Drive marker_step through a realistic pump-control state machine.

        States: 0=IDLE 1=STARTING 2=RUNNING 3=STOPPING 4=ALARM
        Valid transitions only — mirrors the OpenPLC process_sim.st logic
        so the built-in simulator and OpenPLC produce the same event shapes.

        Timing is driven by the tick count so a full cycle takes minutes,
        not seconds — matching how a real batch process behaves.
        """
        step_tag = next((t for t in self.tags if t.name == "marker_step"), None)
        if step_tag is None:
            return

        seq = int(step_tag.value)
        self._seq_ticks = getattr(self, "_seq_ticks", 0) + 1

        def temp_of(name, default=0.0):
            t = next((t for t in self.tags if t.name == name), None)
            return t.value if t else default

        temp = temp_of("db200_temperature", 50.0)
        lvl  = temp_of("db200_level", 50.0)

        new_seq = seq
        if seq == 0:      # IDLE — start after ~15 ticks (30s at 2s interval)
            if self._seq_ticks >= 15:
                new_seq = 1
        elif seq == 1:    # STARTING — confirm flow after ~5 ticks
            if self._seq_ticks >= 5:
                new_seq = 2
        elif seq == 2:    # RUNNING — alarm on high temp, stop on low level,
                          # or complete the batch after ~600 ticks (20 min)
            if temp > 82.0:
                new_seq = 4
            elif lvl < 15.0:
                new_seq = 3
            elif self._seq_ticks >= 600:
                new_seq = 3      # batch complete → stopping
        elif seq == 3:    # STOPPING — settle for ~5 ticks then idle
            if self._seq_ticks >= 5:
                new_seq = 0
        elif seq == 4:    # ALARM — hold ~15 ticks, clear when temp normal
            if self._seq_ticks >= 15 and temp < 78.0:
                new_seq = 0

        if new_seq != seq:
            step_tag.value = float(new_seq)
            self._seq_ticks = 0
            if self._write_fn:
                self._write_fn(step_tag.area, step_tag.db_number,
                               step_tag.offset,
                               _pack_value(step_tag.value, step_tag.pack_format))

    def _check_seq_transition(self) -> None:
        """
        Log process events when marker_step changes.

        Only logs transitions that are valid in a real pump sequencer
        (the keys of _SIM_SEQ_EVENTS). The built-in simulator's marker_step
        is a bounded random walk, so it can produce impossible transitions
        like 2→1 or 4→3. Logging those would put obviously-wrong events in
        the diagnostic buffer — worse than logging nothing, since a real
        S7-315 running OB1 never shows a sequencer running backwards.
        """
        step_tag = next((t for t in self.tags if t.name == "marker_step"), None)
        if step_tag is None:
            return
        seq  = int(step_tag.value)
        prev = self._last_seq_state
        self._last_seq_state = seq
        if prev is None or prev == seq:
            return

        key = (prev, seq)
        base = self._SIM_SEQ_EVENTS.get(key)
        if base is None:
            return   # not a valid sequencer transition — don't log it

        # Enrich with current values
        def tv(name):
            t = next((t for t in self.tags if t.name == name), None)
            return t.value if t else 0.0

        temp = tv("db200_temperature"); flow = tv("db200_flow")
        lvl  = tv("db200_level")

        if key == (1, 2):
            desc = f"{base} (temp {temp:.1f}\u00b0C)"
        elif key == (2, 3):
            # 2→3 is either a genuine low-level stop or a completed batch
            if lvl < 15.0:
                desc = f"OB1: Low level warning \u2014 pump stop (level {lvl:.1f}%)"
            else:
                desc = f"OB1: Batch complete \u2014 pump stop (level {lvl:.1f}%)"
        elif key == (2, 4):
            desc = f"{base} ({temp:.1f}\u00b0C)"
        elif key == (4, 0):
            desc = f"{base} (temp {temp:.1f}\u00b0C)"
        else:
            desc = base

        try:
            import diag_log as _dl
            _dl.log_process_event(desc, {
                "temperature": round(temp, 2),
                "flow":        round(flow, 2),
                "level":       round(lvl, 2),
                "seq_state":   seq,
            })
        except Exception as exc:
            log.debug("sim process event log failed: %s", exc)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format="%(name)s %(levelname)s %(message)s")
    sim = ProcessSimulator("config.yaml")
    sim.enabled = True
    sim.start(server=None)
    print(f"Running {len(sim.tags)} tags for 20 seconds...")
    try:
        for _ in range(10):
            time.sleep(2)
            print("--- tick ---")
            for t in sim.tags[:6]:
                print(f"  {t.name:30s}  {t.area}/DB{t.db_number} off={t.offset:3d}"
                      f"  val={t.value:>10.2f}  fmt={t.pack_format}")
    except KeyboardInterrupt:
        pass
    finally:
        sim.stop()


# ── shared state file for web portal ─────────────────────────────────────────

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import Paths as _Paths
_PROCESS_STATE_PATH = str(_Paths.load().process_state)


def configure_paths(config_path="config.yaml") -> None:
    """Resolve the process-state path from config.yaml."""
    global _PROCESS_STATE_PATH
    try:
        from paths import Paths
        _PROCESS_STATE_PATH = str(Paths.load(config_path).process_state)
    except Exception:
        pass

def _write_process_state_impl(tags: list, path: str = _PROCESS_STATE_PATH,
                               cpu_state: str = "RUN") -> None:
    """
    Write a snapshot of key process values to a JSON file so the web
    portal can display live data without IPC or snap7 access.
    Called from ProcessSimulator._run() on every interval — even during
    STOP (with cpu_state="STOP") so the portal doesn't lose the values.
    """
    import json, os
    from pathlib import Path

    snapshot = {
        "timestamp":  time.time(),
        "cpu_state":  cpu_state,          # "RUN" or "STOP"
        "tags": {}
    }
    for t in tags:
        snapshot["tags"][t.name] = round(t.value, 3)

    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snapshot, f)
        os.replace(tmp, path)
    except Exception as exc:
        log.warning("process_state write failed: %s", exc)
