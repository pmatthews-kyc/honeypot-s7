"""
storage.py
-----------
Resolves where capture data (pcaps, JSONL logs) actually lives, with two
goals:

  1. One place to point at a large removable drive, not two separate
     config paths to keep in sync.
  2. Fail loudly if that drive isn't actually mounted, rather than
     silently creating directories on the SD card and filling it up
     without anyone noticing -- which is the realistic failure mode for
     a removable-drive setup (drive unplugged, mount didn't come up
     before the service started, wrong device node after a reboot).

Resolution order for the data directory:
  1. S7HONEYPOT_DATA_DIR environment variable, if set
  2. storage.data_dir in config.yaml
  3. hard failure -- no silent fallback to a default path, since a
     silent fallback is exactly the failure mode this module exists to
     prevent
"""

from __future__ import annotations

import os
from pathlib import Path


class StorageError(Exception):
    pass


def resolve_data_dir(cfg: dict) -> Path:
    env_override = os.environ.get("S7HONEYPOT_DATA_DIR")
    if env_override:
        return Path(env_override).expanduser()

    storage_cfg = cfg.get("storage", {})
    data_dir = storage_cfg.get("data_dir")
    if not data_dir:
        raise StorageError(
            "No data directory configured. Set storage.data_dir in "
            "config.yaml, or export S7HONEYPOT_DATA_DIR, before starting."
        )
    return Path(os.path.expandvars(data_dir)).expanduser()


def verify_mounted(path: Path, require_mount: bool) -> None:
    """
    Confirm `path` is itself the root of a currently-mounted filesystem
    (i.e. a real removable drive mount point), not just a directory that
    happens to exist on the root filesystem.

    Uses os.path.ismount() directly on `path` -- NOT by walking up parent
    directories and accepting any mount point found along the way, since
    that walk will always eventually reach "/", which is itself always a
    mount point. A version of this check that walks up and accepts "/"
    would silently pass for every path on the system, which defeats the
    entire point of the check.
    """
    if not require_mount:
        return

    if not path.exists():
        raise StorageError(
            f"{path} does not exist. If this is meant to be your removable "
            f"drive's mount point, create the mount-point directory and "
            f"mount the drive there before starting -- this check "
            f"deliberately does NOT auto-create a missing mount point, "
            f"since doing so could silently create it on the SD card "
            f"instead. For local testing without a removable drive, set "
            f"storage.require_mount: false in config.yaml."
        )

    if not os.path.ismount(path):
        raise StorageError(
            f"{path} exists but is not currently the root of a mounted "
            f"filesystem. This usually means the removable drive isn't "
            f"mounted here yet (or was unmounted). Check `lsblk`/`mount`, "
            f"fix the mount, then restart. To bypass this check (NOT "
            f"recommended -- capture data will land on whatever disk "
            f"{path} actually lives on, likely the SD card), set "
            f"storage.require_mount: false in config.yaml."
        )


def resolve_and_verify(cfg: dict) -> Path:
    """One-call helper: resolve the data dir and verify it's mounted per
    config, before any capture/logging component tries to write to it."""
    storage_cfg = cfg.get("storage", {})
    require_mount = storage_cfg.get("require_mount", True)

    data_dir = resolve_data_dir(cfg)
    verify_mounted(data_dir, require_mount)
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def substitute_data_dir(template: str, data_dir: Path) -> str:
    """Expand a ${DATA_DIR} placeholder in a config path string."""
    return template.replace("${DATA_DIR}", str(data_dir))
