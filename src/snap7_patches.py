"""
snap7_patches.py
----------------
Runtime patches for the pure-Python snap7 server shipped in
python-snap7 (confirmed on the Pi at
/usr/local/lib/python3.13/dist-packages/snap7/server/__init__.py).

Rather than swapping to the C libsnap7 library — which fixes one issue
and introduces another (the COTP CC class byte) — these patches correct
the pure-Python server's behaviour in place. The pure-Python server is
inspectable and patchable from Python, which for a honeypot is a real
advantage over a compiled binary.

CONFIRMED SOURCE FACTS (read from the installed library):
    line  80: self.memory_areas: Dict[Tuple[S7Area, int], bytearray] = {}
    line 923: def _read_from_memory_area(self, area, db_number, start, count)
    line 939:     if area_key not in self.memory_areas: ...
    line 946:     area_data = self.memory_areas[area_key]

PATCHES APPLIED
---------------
1. Unallocated-DB reads return an S7 error, not zeros.
   A real S7-300 returns "data block does not exist" for a DB that
   isn't in the loaded program. Returning zeros makes every DB number
   1-65535 look present, which no real PLC does.

2. Out-of-range offset reads return an S7 error.
   Reading past the end of a real DB returns an address error, not
   a short/zero-padded result.

3. Optional read logging hook so the honeypot can see which areas
   clients actually probe (feeds the diagnostic buffer).
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

log = logging.getLogger("snap7_patches")

# DBs deliberately absent so error probes get a realistic error.
# S7ClientTests.TestErrorHandling probes DB999 expecting failure.
ABSENT_DBS = frozenset({999})

# Set by apply_read_patches(); called as read_hook(area_name, db, start, count, ok)
_read_hook: Optional[Callable] = None


def set_read_hook(fn: Optional[Callable]) -> None:
    """Register a callback invoked on every memory-area read."""
    global _read_hook
    _read_hook = fn


def apply_read_patches(server) -> bool:
    """
    Wrap server._read_from_memory_area so that:
      - reads of DBs in ABSENT_DBS return None (S7 error path)
      - reads of any unallocated area return None rather than zeros
      - reads past the end of an allocated area return None
      - each read is reported to the optional read hook

    Returns True if the patch was applied.
    """
    original = getattr(server, "_read_from_memory_area", None)
    if original is None:
        log.warning("server has no _read_from_memory_area — "
                    "unallocated DB reads may return zeros (minor tell)")
        return False

    mem = getattr(server, "memory_areas", None)
    if mem is None:
        log.warning("server has no memory_areas — read patch not applied")
        return False

    def patched_read(area, db_number, start, count):
        area_name = getattr(area, "name", str(area))

        # 1. Deliberately-absent DBs behave like a DB not in the program
        if area_name == "DB" and db_number in ABSENT_DBS:
            log.debug("read DB%d rejected (deliberately absent)", db_number)
            if _read_hook:
                _read_hook(area_name, db_number, start, count, False)
            return None

        # 2. Unallocated area — real PLC returns an address error
        key = (area, db_number)
        if key not in mem:
            log.debug("read %s%d rejected (not allocated)", area_name, db_number)
            if _read_hook:
                _read_hook(area_name, db_number, start, count, False)
            return None

        # 3. Read past the end of the area — real PLC returns an error
        buf = mem[key]
        if start + count > len(buf):
            log.debug("read %s%d @%d+%d rejected (past end, size=%d)",
                      area_name, db_number, start, count, len(buf))
            if _read_hook:
                _read_hook(area_name, db_number, start, count, False)
            return None

        result = original(area, db_number, start, count)
        if _read_hook:
            _read_hook(area_name, db_number, start, count, result is not None)
        return result

    server._read_from_memory_area = patched_read
    log.info("snap7 read patches applied "
             "(absent DBs: %s; unallocated and out-of-range reads error)",
             ", ".join(f"DB{n}" for n in sorted(ABSENT_DBS)))
    return True


def apply_write_patches(server) -> bool:
    """
    Wrap server._write_to_memory_area so writes to absent or unallocated
    areas fail rather than silently creating them. A real PLC cannot have
    a DB conjured into existence by a write from a client.
    """
    original = getattr(server, "_write_to_memory_area", None)
    if original is None:
        return False

    mem = getattr(server, "memory_areas", None)
    if mem is None:
        return False

    def patched_write(area, db_number, start, write_data):
        area_name = getattr(area, "name", str(area))

        if area_name == "DB" and db_number in ABSENT_DBS:
            log.debug("write DB%d rejected (deliberately absent)", db_number)
            return False

        key = (area, db_number)
        if key not in mem:
            log.debug("write %s%d rejected (not allocated)", area_name, db_number)
            return False

        buf = mem[key]
        if start + len(write_data) > len(buf):
            log.debug("write %s%d @%d rejected (past end)", area_name, db_number, start)
            return False

        return original(area, db_number, start, write_data)

    server._write_to_memory_area = patched_write
    log.info("snap7 write patches applied "
             "(writes to absent/unallocated areas rejected)")
    return True


def apply_all(server) -> dict:
    """
    Apply every patch. Never raises — a honeypot serving slightly-wrong
    data is far better than one in a systemd restart loop.
    Returns a dict of patch name → applied (bool).
    """
    results = {}
    for name, fn in (("read", apply_read_patches), ("write", apply_write_patches)):
        try:
            results[name] = fn(server)
        except Exception as exc:
            log.warning("snap7 %s patch failed: %s", name, exc)
            results[name] = False
    return results
