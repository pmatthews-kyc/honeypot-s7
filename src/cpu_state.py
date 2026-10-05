"""
cpu_state.py
-------------
Single shared source of truth for CPU run/stop state, so that a real
STOP command accepted by block_transfer_handler.py (which runs inside
honeypot.py's proxy process) is actually visible to the OTHER processes
in this project that might report device state -- the web portal
(separate process) and the new SZL-status interception (szl_status_handler.py,
also running inside the proxy, but kept as a distinct module so it can be
tested independently and reused if the architecture changes).

Before this module existed, block_transfer_handler.py tracked
`_cpu_state` as a plain in-memory attribute -- correct within that one
process, invisible everywhere else. This is the fix: the same small
JSON-state-file pattern already used by boot_ip_writer.py for network
state (`/var/lib/s7honeypot/network_state.json`), applied here for CPU
state instead of inventing a second mechanism.

This is small, frequently-written runtime state, not capture data -- it
deliberately lives under /var/lib alongside network_state.json, NOT on
the removable capture drive managed by storage.py, matching the same
reasoning already applied to network_state.json.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import Paths as _Paths
STATE_PATH = _Paths.load().cpu_state


def configure(config_path="config.yaml") -> None:
    """Resolve STATE_PATH from config.yaml (single source of truth)."""
    global STATE_PATH
    try:
        from paths import Paths
        STATE_PATH = Paths.load(config_path).cpu_state
    except Exception:
        pass   # keep the default

STATE_RUN = "RUN"
STATE_STOP = "STOP"


def write_cpu_state(state: str, path: "Path | None" = None,
                    peer_ip: str = "") -> None:
    """
    path defaults to None (resolved to the current value of STATE_PATH
    inside the function body) rather than defaulting directly to
    STATE_PATH in the signature -- a default argument value is bound
    once at function-definition time, so a caller that patches
    cpu_state.STATE_PATH afterward (e.g. tests injecting a temp path)
    would silently keep hitting the original path with the naive
    version. This was a real bug caught by actually running the test
    that patches STATE_PATH -- worth the comment so it doesn't regress.

    peer_ip is the IP of the client that issued the mode change; if
    supplied it is recorded in the diagnostic event log so the buffer
    shows who sent each STOP/START command.
    """
    if path is None:
        path = STATE_PATH
    if state not in (STATE_RUN, STATE_STOP):
        raise ValueError(f"invalid cpu state: {state!r}")

    # Read the previous state so we only log genuine transitions.
    prev = read_cpu_state(path)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"state": state, "changed_at": time.time()}, indent=2))

    # Append the transition to the persistent diagnostic event log so the
    # web portal diagnostic buffer shows a new entry for each STOP/START.
    if state != prev:
        try:
            import diag_log as _dl
            if state == STATE_STOP:
                _dl.log_stop(peer_ip=peer_ip)
            else:
                _dl.log_run(peer_ip=peer_ip)
        except Exception as exc:
            # Was a silent `pass`. A swallowed failure here means STOP/START
            # commands never reach the diagnostic buffer while everything
            # else appears to work — which is exactly what happened in
            # deployment and took a full debugging cycle to find.
            # The state write itself must still succeed, so we log and move on.
            import logging as _logging
            _logging.getLogger("cpu_state").warning(
                "Could not record %s transition in diagnostic buffer "
                "(%s): %s", state, type(exc).__name__, exc)


def read_cpu_state(path: "Path | None" = None) -> str:
    """Defaults to RUN if the state file doesn't exist yet -- a freshly
    booted device that's never received a STOP command should read as
    running, not as an error condition. Same late-binding fix as
    write_cpu_state() above -- path resolved inside the body, not as a
    directly-bound default."""
    if path is None:
        path = STATE_PATH
    if not path.exists():
        return STATE_RUN
    try:
        data = json.loads(path.read_text())
        state = data.get("state", STATE_RUN)
        return state if state in (STATE_RUN, STATE_STOP) else STATE_RUN
    except (json.JSONDecodeError, OSError):
        return STATE_RUN
