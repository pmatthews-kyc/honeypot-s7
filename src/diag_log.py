"""
diag_log.py
-----------
SQLite-backed diagnostic event log for the web portal diagnostic buffer.

Three event sources write to one table:
  source='operator'  STOP/START mode transitions (cpu_state.write_cpu_state)
  source='process'   Pump cycles, alarms, level warnings from OpenPLC/simulator
  source='s7_read'   S7 client reads of process data (DB200) with Modbus values

The web portal _build_diag_events() reads from here instead of diag_events.jsonl.
config.yaml:  logging.honeypot_db  (path set at top with x-honeypot-db anchor)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path

import yaml

log = logging.getLogger("diag_log")

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import Paths as _Paths
_DB_PATH   = _Paths.load().honeypot_db
_MAX_EVENTS = 100

# Words that must never appear in a diagnostic buffer entry.
#
# This table is read by attackers through TWO surfaces: SZL 0x00A0 over
# S7comm and the web portal diagnostic page. An entry such as
# "Honeypot software updated - diagnostic database ready" (written by an
# earlier version of install_update.sh) announces exactly what the device
# is, on the surface most carefully built to look like a real PLC.
#
# Any event whose description contains one of these is rejected and logged
# to the service journal instead, where only the operator sees it.
_FORBIDDEN_TERMS = (
    "honeypot", "snap7", "python", "simulator", "openplc", "modbus",
    "database", "sqlite", "debug", "test event", "install", "deploy",
    "schema", "traceback", "exception", "localhost", "127.0.0.1",
)


def _is_safe_description(desc: str) -> bool:
    """True if the text is plausible as a real PLC diagnostic entry."""
    low = desc.lower()
    return not any(term in low for term in _FORBIDDEN_TERMS)

# Rate-limit S7 read events: log once per (peer_ip, db_number) per 60 seconds
_s7_read_last: dict[tuple, float] = {}
_S7_READ_INTERVAL = 60.0


# ── configuration ─────────────────────────────────────────────────────────────

def configure(config_path: "str | Path" = "config.yaml") -> None:
    """Read the DB path from config.yaml and initialise the schema."""
    global _DB_PATH
    try:
        from paths import Paths
        _DB_PATH = Paths.load(config_path).honeypot_db
        _init_db()
        log.info("diag_log SQLite: %s", _DB_PATH)

        p = str(_DB_PATH)
        if p.startswith("/tmp/") or p.startswith("/var/tmp/"):
            log.warning("Diagnostic database is under %s — this is cleared on "
                        "reboot and is not shared between systemd services "
                        "using PrivateTmp. Set x-state-dir / logging.honeypot_db "
                        "to a persistent path such as /var/lib/s7honeypot.",
                        p.split("/")[1])
    except Exception as exc:
        log.warning("diag_log.configure failed (%s); using default %s", exc, _DB_PATH)


# ── schema ─────────────────────────────────────────────────────────────────────

def _init_db() -> None:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS diag_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fake_ts     REAL    NOT NULL,
                real_ts     REAL    NOT NULL,
                source      TEXT    NOT NULL DEFAULT 'system',
                peer_ip     TEXT,
                description TEXT    NOT NULL,
                raw_value   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_diag_fake_ts
                ON diag_events(fake_ts DESC);
        """)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(str(_DB_PATH), timeout=5.0, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.row_factory = sqlite3.Row
    return con


# ── write ──────────────────────────────────────────────────────────────────────

def append_event(event_class: int, event_num: int, description: str,
                 epoch: float | None = None, peer_ip: str | None = None,
                 source: str = "operator",
                 values: dict | None = None,
                 log_path: "Path | None" = None) -> None:
    """
    Append one diagnostic event to the SQLite database.
    epoch defaults to time.time() (used as fake_ts — anchored to the
    fake_boot_epoch offset in _build_diag_events on the web portal side).
    """
    ts  = epoch or time.time()
    raw = json.dumps(values) if values else None
    db  = log_path or _DB_PATH

    # Refuse anything that would reveal what this device really is. The
    # diagnostic buffer is attacker-visible via SZL 0x00A0 and the web
    # portal, so a leaked operational message here is worse than no event.
    if not _is_safe_description(description):
        log.warning("REFUSED diagnostic buffer entry (attacker-visible "
                    "surface): %r", description)
        return

    try:
        db.parent.mkdir(parents=True, exist_ok=True)
        with _connect() as con:
            con.execute(
                "INSERT INTO diag_events "
                "(fake_ts, real_ts, source, peer_ip, description, raw_value) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ts, time.time(), source, peer_ip, description, raw)
            )
            # Keep the table at most _MAX_EVENTS rows (real S7-300 holds 100)
            con.execute(
                "DELETE FROM diag_events WHERE id NOT IN "
                "(SELECT id FROM diag_events ORDER BY fake_ts DESC LIMIT ?)",
                (_MAX_EVENTS,)
            )
        log.debug("diag_event [%s] %s", source, description)
    except Exception as exc:
        log.warning("diag_log append failed: %s", exc)


# ── read ───────────────────────────────────────────────────────────────────────

def load_events(limit: int = 100,
                log_path: "Path | None" = None,
                include_operator_only: bool = False) -> list[tuple[float, str]]:
    """
    Return [(fake_ts, description), ...] newest-first for the DECEPTION
    surfaces (SZL 0x00A0 and the web portal diagnostic buffer).

    's7_read' events are EXCLUDED by default. A real S7-300 diagnostic
    buffer records mode changes, hardware faults, diagnostic interrupts and
    program errors — never routine successful reads. Showing an attacker
    "[their.ip] S7: Read DB200 — temp=30.1C ..." tells them their activity
    is being recorded and renders forensic data on the surface that is
    supposed to look like ordinary PLC hardware.

    Pass include_operator_only=True for analyst queries; those events stay
    in the database and remain fully queryable, they are just never shown
    to a client.
    """
    db = log_path or _DB_PATH
    if not db.exists():
        return []
    try:
        with sqlite3.connect(str(db), timeout=3.0) as con:
            con.execute("PRAGMA journal_mode=WAL")
            if include_operator_only:
                rows = con.execute(
                    "SELECT fake_ts, description FROM diag_events "
                    "ORDER BY fake_ts DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT fake_ts, description FROM diag_events "
                    "WHERE source NOT IN ('s7_read') "
                    "ORDER BY fake_ts DESC LIMIT ?", (limit,)
                ).fetchall()
        return [(r[0], r[1]) for r in rows]
    except Exception as exc:
        log.warning("diag_log load failed: %s", exc)
        return []


# ── convenience helpers ────────────────────────────────────────────────────────

def log_stop(peer_ip: str = "", log_path: "Path | None" = None) -> None:
    """Record RUN → STOP (S7 event 0x48/0x01)."""
    who = f" (from {peer_ip})" if peer_ip else ""
    append_event(0x48, 0x01,
                 f"Operating mode: RUN \u2192 STOP \u2014 remote command{who}",
                 source="operator", peer_ip=peer_ip or None,
                 log_path=log_path)


def log_run(peer_ip: str = "", log_path: "Path | None" = None) -> None:
    """Record STOP → RUN (S7 event 0x48/0x00)."""
    who = f" (from {peer_ip})" if peer_ip else ""
    append_event(0x48, 0x00,
                 f"Operating mode: STOP \u2192 RUN \u2014 remote command{who}",
                 source="operator", peer_ip=peer_ip or None,
                 log_path=log_path)


def log_process_event(description: str,
                      values: dict | None = None) -> None:
    """
    Record a process state transition from OpenPLC or the built-in simulator.
    Called by modbus_bridge._poll() on seq_state change, and by
    process_simulator._tick() when marker_step changes.
    """
    append_event(0x48, 0x10, description,
                 source="process", values=values)


def log_s7_read(peer_ip: str, db_number: int,
                process_snapshot: dict | None = None) -> None:
    """
    Record an S7 client reading process data, showing the Modbus values
    that were live at the time of the read.
    Rate-limited: one event per (peer_ip, db_number) per 60 seconds so
    a polling SCADA doesn't flood the buffer.
    """
    key = (peer_ip, db_number)
    now = time.time()
    if now - _s7_read_last.get(key, 0.0) < _S7_READ_INTERVAL:
        return
    _s7_read_last[key] = now

    if process_snapshot:
        temp  = process_snapshot.get("db200_temperature", 0)
        flow  = process_snapshot.get("db200_flow", 0)
        lvl   = process_snapshot.get("db200_level", 0)
        state = process_snapshot.get("cpu_state", "RUN")
        if state == "STOP":
            desc = (f"[{peer_ip}] S7: Read DB{db_number} \u2014 "
                    f"temp={temp:.1f}\u00b0C  flow={flow:.1f} l/min  "
                    f"level={lvl:.1f}%  (CPU STOP \u2014 values frozen)")
        else:
            desc = (f"[{peer_ip}] S7: Read DB{db_number} \u2014 "
                    f"temp={temp:.1f}\u00b0C  flow={flow:.1f} l/min  "
                    f"level={lvl:.1f}%")
    else:
        desc = f"[{peer_ip}] S7: Read DB{db_number}"

    append_event(0x48, 0x20, desc,
                 source="s7_read", peer_ip=peer_ip,
                 values=process_snapshot)
