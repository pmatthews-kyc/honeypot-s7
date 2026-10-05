"""
paths.py — single source of truth for runtime state file locations.

Every service resolves its state paths through here instead of hardcoding
/var/lib/s7honeypot/... in a dozen modules. That hardcoding caused two
regressions: a database created in the wrong place, and a web portal reading
a different file than the writer used. One config value, one resolver.

config.yaml:
    x-state-dir: &state_dir "/var/lib/s7honeypot"   # top-of-file anchor
    logging:
      state_dir:        *state_dir
      honeypot_db:      *honeypot_db
      diag_events_path: *diag_events

Usage:
    from paths import Paths
    p = Paths.load("config.yaml")
    p.cpu_state          # <state_dir>/cpu_state.json
    p.network_state      # <state_dir>/network_state.json
    p.process_state      # <state_dir>/process_state.json
    p.mac_spoof_state    # <state_dir>/mac_spoof_state.json
    p.honeypot_db        # logging.honeypot_db (explicit override)
    p.diag_events        # logging.diag_events_path (explicit override)

Anything not explicitly overridden in config falls under state_dir, so a
single x-state-dir change relocates the whole set.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("paths")

_DEFAULT_STATE_DIR = "/var/lib/s7honeypot"


@dataclass
class Paths:
    state_dir:       Path
    cpu_state:       Path
    network_state:   Path
    process_state:   Path
    mac_spoof_state: Path
    honeypot_db:     Path
    diag_events:     Path

    @classmethod
    def load(cls, config_path: "str | Path | None" = "config.yaml") -> "Paths":
        """
        Build a Paths object from config.yaml. Falls back to the historical
        /var/lib/s7honeypot defaults for anything missing or on any error,
        so a malformed config never leaves a service with no paths at all.

        A missing config file is the normal case at IMPORT time — modules
        call Paths.load() at import to seed a default, before the service's
        WorkingDirectory or an explicit configure() supplies the real path.
        That case is silent. Only a config that EXISTS but can't be parsed
        (malformed YAML, unreadable) warrants a warning, because that is a
        real operator error rather than expected import-time ordering.
        """
        state_dir = _DEFAULT_STATE_DIR
        db = diag = ""
        try:
            import yaml
            cfg = yaml.safe_load(Path(config_path).read_text())
            lg = cfg.get("logging", {}) or {}
            state_dir = (lg.get("state_dir")
                         or cfg.get("x-state-dir")
                         or _DEFAULT_STATE_DIR)
            db   = lg.get("honeypot_db", "")
            diag = lg.get("diag_events_path", "")
        except FileNotFoundError:
            # Expected at import time — the caller will configure() later, or
            # the service's WorkingDirectory will make the relative path resolve.
            log.debug("config not found at %s; using defaults under %s",
                      config_path, state_dir)
        except Exception as exc:
            # Config exists but is broken — a real problem worth surfacing.
            log.warning("paths.load failed to parse %s (%s); using defaults "
                        "under %s", config_path, exc, state_dir)

        sd = Path(state_dir)
        return cls(
            state_dir       = sd,
            cpu_state       = sd / "cpu_state.json",
            network_state   = sd / "network_state.json",
            process_state   = sd / "process_state.json",
            mac_spoof_state = sd / "mac_spoof_state.json",
            honeypot_db     = Path(db)   if db   else sd / "honeypot.db",
            diag_events     = Path(diag) if diag else sd / "diag_events.jsonl",
        )

    def ensure_dir(self) -> None:
        """Create the state directory if it doesn't exist."""
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            log.warning("could not create state dir %s: %s", self.state_dir, exc)
