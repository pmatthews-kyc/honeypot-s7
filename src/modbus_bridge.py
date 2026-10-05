"""
modbus_bridge.py
-----------------
Optional replacement for the process_simulator's random-walk logic.

When  modbus_bridge.enabled: true  in config.yaml, this module polls
OpenPLC's Modbus TCP server and writes the results directly into the
snap7 Server's memory_areas — the same dict that S7comm read variable
(fc=0x04) requests are served from.  The effect: S7comm reads return
values driven by a real IEC 61131-3 program running in OpenPLC rather
than the built-in Python random-walk.

The process_simulator still runs when the bridge is active (for the
heartbeat counters and DB500/501 test tags that aren't mapped from
Modbus), but its I/Q/M and process-DB tags are skipped when the bridge
owns those addresses.

ARCHITECTURE
============

    OpenPLC (port 502, Modbus TCP)
         │  poll every poll_interval seconds
         │  (pymodbus client)
         ▼
    ModbusBridge._poll()           ← this file
         │  map Modbus registers → S7 address
         │  struct.pack into correct byte format
         ▼
    snap7.Server.memory_areas      ← same dict read by S7comm
         │
         ▼
    S7comm read variable (fc=0x04) ← attacker/tool reads real PLC values

STANDARD OpenPLC MODBUS REGISTER MAP (OpenPLC 3.x default)
===========================================================

    Function  Address   OpenPLC variable   S7 equivalent
    ──────────────────────────────────────────────────────
    FC1/FC5   coil 0    %QX0.0             Q0.0
    FC1/FC5   coil 7    %QX0.7             Q0.7
    FC2       DI 0      %IX0.0             I0.0
    FC3/FC16  HR 0      %MW0               MW0
    FC3/FC16  HR 100    %QW0               QW0
    FC4       IR 0      %IW0               IW0

INSTALLATION
============

    pip install pymodbus     # or: pip3 install pymodbus --break-system-packages
    # Install and configure OpenPLC (https://autonomylogic.com/)
    # Set x-modbus-bridge: true in config.yaml
"""

from __future__ import annotations

import logging
import struct
import threading
import time
from pathlib import Path
from typing import Optional

import yaml

log = logging.getLogger("modbus_bridge")

_UNSET = object()   # sentinel: unit keyword not yet detected

# Optional pymodbus import — only needed when bridge is enabled.
# Imported lazily in start() so the module can always be imported.
_pymodbus_ok = False


def _check_pymodbus() -> bool:
    try:
        from pymodbus.client import ModbusTcpClient  # pymodbus ≥ 3.x
        return True
    except ImportError:
        try:
            from pymodbus.client.sync import ModbusTcpClient  # pymodbus 2.x
            return True
        except ImportError:
            return False


# ── config helpers ─────────────────────────────────────────────────────────────

def is_enabled(config_path: str = "config.yaml") -> bool:
    """Return True if modbus_bridge.enabled is set in config.yaml."""
    try:
        cfg = yaml.safe_load(Path(config_path).read_text())
        return bool(cfg.get("modbus_bridge", {}).get("enabled", False))
    except Exception:
        return False


# ── address map entry ──────────────────────────────────────────────────────────

class _MapEntry:
    __slots__ = ("modbus_type", "modbus_start", "count",
                 "s7_area", "s7_db", "s7_offset", "s7_format", "tag_name")

    def __init__(self, d: dict):
        self.modbus_type  = d["modbus_type"]
        self.modbus_start = int(d["modbus_start"])
        self.count        = int(d["count"])
        self.s7_area      = d["s7_area"]
        self.s7_db        = int(d.get("s7_db", 0))
        self.s7_offset    = int(d["s7_offset"])
        self.s7_format    = d["s7_format"]
        self.tag_name     = d.get("tag_name", "")  # optional: populates process_state.json


# ── packing helpers ────────────────────────────────────────────────────────────

def _pack(fmt: str, regs: list, bits: list) -> tuple[Optional[bytes], Optional[float]]:
    """
    Convert Modbus response into snap7 bytes AND a float for process_state.json.
    Returns (bytes_for_snap7, float_value_for_portal).
    float_value is None for formats that don't map to a single process number.
    """
    try:
        if fmt == "real":
            raw = struct.pack(">HH", regs[0], regs[1])
            val = struct.unpack(">f", raw)[0]
            return raw, val
        elif fmt == "real_x10":
            fval = regs[0] / 10.0
            return struct.pack(">f", fval), fval
        elif fmt == "real_x100":
            fval = regs[0] / 100.0
            return struct.pack(">f", fval), fval
        elif fmt == "word":
            return struct.pack(">H", regs[0]), float(regs[0])
        elif fmt == "int":
            return struct.pack(">h", regs[0]), float(regs[0])
        elif fmt == "dint":
            return struct.pack(">i", (regs[0] << 16) | regs[1]), float((regs[0] << 16) | regs[1])
        elif fmt == "byte":
            return bytes([regs[0] & 0xFF]), float(regs[0] & 0xFF)
        elif fmt == "bits_to_byte":
            val = 0
            for i, b in enumerate(bits[:8]):
                if b:
                    val |= (1 << i)
            return bytes([val]), float(val)
        else:
            log.warning("unknown s7_format: %s", fmt)
            return None, None
    except (IndexError, struct.error) as exc:
        log.debug("pack failed (%s): %s", fmt, exc)
        return None, None


# ── ModbusBridge ───────────────────────────────────────────────────────────────

class ModbusBridge:
    """
    Polls OpenPLC Modbus TCP and writes values into snap7 memory_areas.
    Controlled by modbus_bridge.enabled in config.yaml.
    """

    def __init__(self, config_path: str = "config.yaml"):
        cfg = yaml.safe_load(Path(config_path).read_text())
        mb  = cfg.get("modbus_bridge", {})

        # Resolve the process-state path once, from the same source the web
        # portal reads. Avoids depending on process_simulator's module global
        # being configured before the first poll.
        try:
            from paths import Paths
            self._process_state_path = str(Paths.load(config_path).process_state)
        except Exception:
            from paths import Paths
            self._process_state_path = str(Paths.load().process_state)

        self.enabled       = bool(mb.get("enabled", False))
        self.host          = mb.get("host", "127.0.0.1")
        self.port          = int(mb.get("port", 502))
        self.unit_id       = int(mb.get("unit_id", 1))
        self.poll_interval = float(mb.get("poll_interval", 2.0))
        self._mapping      = [_MapEntry(e) for e in mb.get("mapping", [])]

        self._stop         = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._write_fn     = None   # set by attach_to_server()
        self._last_seq_state: Optional[int] = None  # for process event detection
        self._unit_kw = _UNSET     # pymodbus unit keyword, detected on first read
        self._fail_count = 0       # consecutive poll failures (for log rate-limit)
        self._last_tag_values: dict = {}   # held during CPU STOP
        self._stopped_deenergized: bool = False  # Q-zeroed once per STOP edge

    # ── server attachment ──────────────────────────────────────────────────

    def attach_to_server(self, server) -> bool:
        """
        Use the pinned ctypes buffers in server.s7_buffers (created by
        _preallocate_dbs and registered with snap7) to build a write_fn.
        Writing to ctypes elements updates the C-level memory snap7 serves.
        """
        s7_buffers = getattr(server, "s7_buffers", None)
        if not s7_buffers:
            log.warning("server has no s7_buffers — bridge cannot write to snap7")
            return False

        def write_fn(s7_area: str, s7_db: int, offset: int, data: bytes) -> None:
            key = (s7_area, s7_db if s7_area == "DB" else 0)
            buf = s7_buffers.get(key)
            if buf is None:
                return
            end = min(offset + len(data), len(buf))
            # bytearray slice assignment — same object snap7 reads from
            buf[offset:end] = data[:end - offset]

        self._write_fn = write_fn
        log.info("Modbus bridge attach_to_server: using s7_buffers")
        return True

    # ── pymodbus API compatibility ─────────────────────────────────────────
    # The unit/slave keyword changed across pymodbus 3.x releases:
    #   3.0-3.6   read_holding_registers(addr, count, slave=1)
    #   3.7+      read_holding_registers(addr, count=1, slave=1)
    #   3.9+      read_holding_registers(addr, count=1, device_id=1)
    # Passing the wrong keyword raises TypeError, which previously surfaced
    # only as "OpenPLC Modbus lost - reconnecting" with no reason logged.
    # Detect the working form once, then reuse it.

    def _call_read(self, fn, start: int, count: int):
        """
        Call a pymodbus read fn, coping with signature changes across 3.x.

        CONFIRMED from deployment:
            TypeError: ModbusClientMixin.read_holding_registers()
                       takes 2 positional arguments but 3 were given
        This build accepts ONLY the address positionally — `count` and the
        unit id must both be keywords. Earlier releases accepted
        (address, count) positionally. Try keyword forms first.
        """
        forms = ([self._unit_kw] if self._unit_kw is not _UNSET
                 else ["slave", "device_id", None])
        last_exc = None
        for kw in forms:
            # count as keyword (modern pymodbus), then positional (legacy)
            attempts = [
                (lambda k=kw: fn(start, count=count, **({k: self.unit_id} if k else {}))),
                (lambda k=kw: fn(start, count, **({k: self.unit_id} if k else {}))),
            ]
            for attempt in attempts:
                try:
                    rr = attempt()
                    if self._unit_kw is _UNSET:
                        self._unit_kw = kw
                        log.info("pymodbus call form detected: count=keyword, "
                                 "unit keyword=%s", kw or "(omitted)")
                    return rr
                except TypeError as exc:
                    last_exc = exc
                    continue
        raise last_exc if last_exc else RuntimeError("no working read form")

    # ── poll loop ──────────────────────────────────────────────────────────

    def _connect(self):
        """Return a connected Modbus client or None."""
        try:
            # pymodbus 3.x
            from pymodbus.client import ModbusTcpClient
            client = ModbusTcpClient(self.host, port=self.port)
        except ImportError:
            # pymodbus 2.x
            from pymodbus.client.sync import ModbusTcpClient
            client = ModbusTcpClient(self.host, port=self.port)

        if client.connect():
            return client
        return None

    def _prime_values(self, client) -> bool:
        """
        Read the mapped tags once into _last_tag_values without writing to
        snap7. Called at startup so that if the CPU is already in STOP, the
        frozen web-portal display shows the real process state rather than
        the ST program's initial constants.
        """
        got = {}
        for entry in self._mapping:
            if not entry.tag_name:
                continue
            try:
                if entry.modbus_type == "holding":
                    rr = self._call_read(client.read_holding_registers,
                                         entry.modbus_start, entry.count)
                    if rr.isError():
                        continue
                    _, fval = _pack(entry.s7_format, rr.registers, [])
                elif entry.modbus_type == "coil":
                    rr = self._call_read(client.read_coils,
                                         entry.modbus_start, entry.count)
                    if rr.isError():
                        continue
                    _, fval = _pack(entry.s7_format, [], rr.bits)
                else:
                    continue
                if fval is not None:
                    got[entry.tag_name] = round(fval, 3)
            except Exception as exc:
                log.debug("priming %s[%d] failed: %s",
                          entry.modbus_type, entry.modbus_start, exc)
        if got:
            self._last_tag_values = got
            return True
        return False

    def _deenergize_outputs_stop(self) -> None:
        """
        Zero the Q (process output) area on the RUN->STOP edge, in both snap7
        memory and the cached values the portal shows. DB/M/I are left frozen.

        A real S7-300 stops driving outputs the instant it enters STOP, so a
        Q read must return 0 rather than the last RUNNING value. This mirrors
        ProcessSimulator._deenergize_outputs() so the OpenPLC-bridge data path
        and the built-in simulator behave identically when the CPU is stopped.
        """
        zeroed = 0
        for entry in self._mapping:
            if entry.s7_area != "Q":
                continue
            # zero the snap7 memory this maps to
            if self._write_fn:
                width = {"word": 2, "byte": 1, "bits_to_byte": 1,
                         "real_x10": 4, "real_x100": 4, "real": 4,
                         "int": 2, "dint": 4}.get(entry.s7_format, 2)
                self._write_fn(entry.s7_area, entry.s7_db,
                               entry.s7_offset, b"\x00" * width)
            # zero the cached value the web portal renders
            if entry.tag_name and entry.tag_name in self._last_tag_values:
                self._last_tag_values[entry.tag_name] = 0
            zeroed += 1
        if zeroed:
            log.info("CPU entered STOP: Q (process outputs) de-energized to 0 "
                     "in bridge mode -- DB/M/I remain frozen")

    def _poll(self, client) -> bool:
        """
        Read all mapped Modbus addresses and write into snap7 memory.

        CPU STATE AWARENESS: OpenPLC keeps running regardless of what our
        emulated CPU claims. When the honeypot CPU is in STOP, a real
        S7-315 freezes its process image — OB1 stops executing and values
        hold. Without this check the web portal shows a STOP banner while
        DB200 keeps changing, which is a direct contradiction an attacker
        can see from two surfaces at once.
        """
        import cpu_state as _cpu_state
        from process_simulator import _write_process_state_impl

        state = _cpu_state.read_cpu_state()

        if state == "STOP":
            # Freeze: do not poll OpenPLC into snap7, do not refresh values —
            # BUT de-energize the Q (output) area to zero, matching real S7-300
            # STOP behavior (outputs go to substitute state; DB/M/I hold their
            # last value). Without this, a Q read in STOP would return the
            # frozen RUNNING value (e.g. pump ON), which a real device can't
            # show while the CPU reports STOP. Mirrors ProcessSimulator.
            # _deenergize_outputs() so both data sources behave identically.
            if not self._stopped_deenergized:
                self._deenergize_outputs_stop()
                self._stopped_deenergized = True

            # Keep writing process_state.json so the web portal shows the
            # frozen values (with cpu_state=STOP) and the now-zeroed outputs,
            # rather than losing the overview to the staleness window.
            if self._last_tag_values:
                try:
                    import json, os, time
                    snap = {"timestamp": time.time(), "cpu_state": "STOP",
                            "tags": self._last_tag_values}
                    tmp = self._process_state_path + ".tmp"
                    with open(tmp, "w") as f:
                        json.dump(snap, f)
                    os.replace(tmp, self._process_state_path)
                except Exception as exc:
                    log.debug("process_state.json (STOP) write failed: %s", exc)
            return True     # connection is healthy; we are deliberately idle

        # Back in RUN — allow the next STOP to de-energize again.
        self._stopped_deenergized = False

        tag_values: dict[str, float] = {}

        for entry in self._mapping:
            try:
                if entry.modbus_type == "coil":
                    rr = self._call_read(client.read_coils,
                                         entry.modbus_start, entry.count)
                    if rr.isError():
                        continue
                    data, fval = _pack(entry.s7_format, [], rr.bits)
                elif entry.modbus_type == "discrete":
                    rr = self._call_read(client.read_discrete_inputs,
                                         entry.modbus_start, entry.count)
                    if rr.isError():
                        continue
                    data, fval = _pack(entry.s7_format, [], rr.bits)
                elif entry.modbus_type == "holding":
                    rr = self._call_read(client.read_holding_registers,
                                         entry.modbus_start, entry.count)
                    if rr.isError():
                        continue
                    data, fval = _pack(entry.s7_format, rr.registers, [])
                elif entry.modbus_type == "input":
                    rr = self._call_read(client.read_input_registers,
                                         entry.modbus_start, entry.count)
                    if rr.isError():
                        continue
                    data, fval = _pack(entry.s7_format, rr.registers, [])
                else:
                    continue

                if data and self._write_fn:
                    self._write_fn(entry.s7_area, entry.s7_db,
                                   entry.s7_offset, data)

                if entry.tag_name and fval is not None:
                    tag_values[entry.tag_name] = round(fval, 3)

            except Exception as exc:
                # Was log.debug — a failure here shows up only as
                # "Modbus lost - reconnecting" with no reason, which cost
                # a full debugging cycle. Log the actual exception.
                if self._fail_count < 3 or self._fail_count % 100 == 0:
                    log.warning("Modbus poll failed on %s[%d] (%s): %s",
                                entry.modbus_type, entry.modbus_start,
                                type(exc).__name__, exc)
                return False

        # Write process_state.json directly so the web portal shows
        # OpenPLC-driven values without depending on the simulator sync.
        if tag_values:
            self._last_tag_values = dict(tag_values)   # held if CPU goes to STOP
            try:
                import json, os, time
                snap = {"timestamp": time.time(), "cpu_state": state, "tags": tag_values}
                tmp = self._process_state_path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(snap, f)
                os.replace(tmp, self._process_state_path)
            except Exception as exc:
                log.debug("process_state.json write failed: %s", exc)

        # Detect seq_state transitions and log as process diagnostic events
        if "marker_step" in tag_values:
            self._check_seq_transition(int(tag_values["marker_step"]), tag_values)

        return True

    # ── seq_state transition detection ────────────────────────────────────

    _SEQ_EVENTS: dict = {
        (0, 1): "OB1: Pump start sequence initiated",
        (1, 2): "OB1: Flow confirmed \u2014 process running",
        (2, 3): "OB1: Low level warning \u2014 pump stop",
        (2, 4): "Process alarm: High temperature",
        (3, 0): "OB1: Pump stopped \u2014 returning to idle",
        (4, 0): "Process alarm cleared \u2014 temperature normal",
    }

    def _check_seq_transition(self, seq: int, tag_values: dict) -> None:
        """
        Log a process event when the OpenPLC sequencer state changes.
        Only valid state-machine transitions are logged — a Modbus read
        glitch producing an impossible transition (e.g. 4→3) must not put
        a nonsensical event in the diagnostic buffer.
        """
        prev = self._last_seq_state
        self._last_seq_state = seq
        if prev is None or prev == seq:
            return
        key  = (prev, seq)
        base = self._SEQ_EVENTS.get(key)
        if base is None:
            log.debug("ignoring invalid seq transition %d -> %d", prev, seq)
            return
        temp = tag_values.get("db200_temperature", 0)
        flow = tag_values.get("db200_flow", 0)
        lvl  = tag_values.get("db200_level", 0)

        # Enrich description with current process values
        if key == (1, 2):
            desc = f"{base} (temp {temp:.1f}\u00b0C)"
        elif key == (2, 3):
            desc = f"{base} (level {lvl:.1f}%)"
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
                "level":       round(lvl,  2),
                "seq_state":   seq,
            })
        except Exception as exc:
            log.debug("process event log failed: %s", exc)

    def _run(self) -> None:
        client = None
        primed = False
        while not self._stop.is_set():
            try:
                if client is None:
                    log.info("Connecting to OpenPLC Modbus at %s:%d …",
                             self.host, self.port)
                    client = self._connect()
                    if client is None:
                        log.warning("OpenPLC Modbus connection failed — "
                                    "retrying in %ds", self.poll_interval)
                        self._stop.wait(self.poll_interval)
                        continue
                    log.info("OpenPLC Modbus connected (unit %d)", self.unit_id)

                # Prime once so a CPU that starts in STOP freezes on real
                # values rather than the ST program's initial constants.
                if not primed:
                    primed = True
                    if self._prime_values(client):
                        log.info("Primed %d process values for display",
                                 len(self._last_tag_values))

                ok = self._poll(client)
                if ok and self._fail_count:
                    log.info("OpenPLC Modbus recovered after %d failures",
                             self._fail_count)
                    self._fail_count = 0
                if not ok:
                    self._fail_count += 1
                    if self._fail_count in (1, 5, 25) or self._fail_count % 100 == 0:
                        log.warning("OpenPLC Modbus lost — reconnecting "
                                    "(failure #%d)", self._fail_count)
                    try:
                        client.close()
                    except Exception:
                        pass
                    client = None

            except Exception as exc:
                # A bare exception in the loop body previously killed the
                # bridge thread outright: it stopped writing process_state.json
                # with no restart, and the web portal's Process Overview
                # vanished once the file went stale (>120s). The whole
                # iteration is now guarded so a single bad poll, priming read,
                # or reconnect can never take the thread down. Drop the client
                # so the next iteration reconnects cleanly.
                self._fail_count += 1
                if self._fail_count in (1, 5, 25) or self._fail_count % 100 == 0:
                    log.warning("Modbus bridge iteration error #%d (%s): %s — "
                                "recovering", self._fail_count,
                                type(exc).__name__, exc)
                try:
                    if client:
                        client.close()
                except Exception:
                    pass
                client = None

            self._stop.wait(self.poll_interval)

        if client:
            try:
                client.close()
            except Exception:
                pass

    # ── public API ─────────────────────────────────────────────────────────

    def start(self, server=None) -> bool:
        """
        Start the bridge thread.  Returns False if:
          - bridge is disabled in config
          - pymodbus is not installed
          - no mapping entries configured
        """
        if not self.enabled:
            log.info("Modbus bridge disabled (x-modbus-bridge: false) — "
                     "using built-in process_simulator")
            return False

        if not _check_pymodbus():
            log.error("pymodbus not installed — cannot start Modbus bridge. "
                      "Run: pip3 install pymodbus --break-system-packages")
            return False

        if not self._mapping:
            log.warning("modbus_bridge.mapping is empty — nothing to poll")
            return False

        if server is not None:
            self.attach_to_server(server)

        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="modbus-bridge")
        self._thread.start()
        log.info("Modbus bridge started: %d map entries, %.1fs interval, "
                 "target %s:%d",
                 len(self._mapping), self.poll_interval, self.host, self.port)
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
