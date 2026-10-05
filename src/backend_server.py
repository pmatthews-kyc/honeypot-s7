"""
backend_server.py
------------------
Runs the actual protocol-handling s7.Server. NOT loopback-only, despite
this module's original design intent -- see the note below, this is
important.

CORRECTED 2026-08-26 against a real installed python-snap7 3.1.2 on
target hardware. The original version of this file was written without
network access to inspect the real library and guessed `from s7 import
Server` -- there is no top-level `s7` package at all in this library,
so that import crashed immediately every time this process started,
meaning the backend never actually ran. This was the root cause of an
observed failure where nmap's s7-info script got no S7 data back at
all: honeypot.py's proxy would accept a connection, try to relay it to
a backend that was never listening, and silently close the connection.

CONFIRMED REAL API (checked directly against the installed package):
    import snap7
    server = snap7.Server()
    server.start(tcp_port=1102)
    server.stop()

IMPORTANT -- NOT ACTUALLY LOOPBACK-ONLY: server.start() takes NO host/
bind-address parameter at all (confirmed signature:
`start(self, tcp_port: int = 102) -> int`). Confirmed on real target
hardware that it binds 0.0.0.0 -- i.e. all interfaces -- with no way to
restrict this from the Python side. This means the raw, unwrapped
backend is directly reachable on the network on port 1102 unless
blocked at the firewall level. fingerprint_harden.sh's `apply` command
adds an iptables rule dropping any non-loopback connection to this
port specifically because of this constraint -- that rule is NOT
optional defense-in-depth here, it is the actual isolation guarantee.
Run `fingerprint_harden.sh status` to confirm both the rule and what
the backend actually bound to.

The identity/SZL data lives in an instance method,
`snap7.server.Server._get_szl_data(self, szl_id, szl_index)`, a plain
if/elif dispatch by SZL ID (source confirmed directly, see identity.py's
build_szl_001c/build_module_identification_szl docstrings for the exact
byte structures this was checked against, including a real crash in
nmap's s7-info.nse that was traced all the way to its root cause and
fixed). Patched here at the CLASS level (so every Server instance picks
it up), wrapping the original function rather than replacing it -- SZL
IDs this project doesn't customize (0x0131 comm params, 0x0232
protection level, 0x0000 SZL list) still fall through to the library's
own correct implementation instead of breaking.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import cpu_state
from identity import S7Identity, read_identity
import identity as _identity_mod

log = logging.getLogger("backend_server")


def apply_identity_patch(config_path: str = "config.yaml") -> None:
    """
    Monkey-patch snap7.server.Server._get_szl_data so every SZL response
    is built from the current config.yaml at request time.

    read_identity() is mtime-cached: re-parses config.yaml only when the
    file has changed on disk (one os.stat() per call otherwise).  The result:
    edit config.yaml (serial number, firmware, order code, plant ID …) and
    the next SZL query from any scanner returns the new values without
    restarting any service.
    """
    _identity_mod._IDENTITY_CONFIG_PATH = Path(config_path)

    try:
        import snap7.server as srv
    except ImportError as e:
        log.error("Could not import snap7.server: %s", e)
        return

    if not hasattr(srv, "Server") or not hasattr(srv.Server, "_get_szl_data"):
        log.warning(
            "snap7.server.Server._get_szl_data not found -- identity patch "
            "NOT applied.  Confirmed against python-snap7 3.1.2."
        )
        return

    original_get_szl_data = srv.Server._get_szl_data

    def patched_get_szl_data(self, szl_id: int, szl_index: int):
        # read_identity() is mtime-cached, so this is effectively free
        # when config.yaml has not changed since the last call.
        ident = read_identity(config_path)

        if szl_id == 0x0000:
            return ident.build_szl_list()
        if szl_id == 0x001C:
            return ident.build_szl_001c()
        if szl_id == 0x0011:
            return ident.build_module_identification_szl()
        if szl_id == 0x0037:
            return ident.build_network_info_szl()
        if szl_id == 0x0232:
            return ident.build_protection_szl()
        if szl_id == 0x0424:
            return ident.build_cpu_status_szl(cpu_state.read_cpu_state())
        if szl_id == 0x0D91:
            return ident.build_module_status_szl()
        return original_get_szl_data(self, szl_id, szl_index)

    srv.Server._get_szl_data = patched_get_szl_data
    ident = read_identity(config_path)
    log.info(
        "Identity patch applied (hot-reload enabled): "
        "module=%s order=%s firmware=%s serial=%s",
        ident.module_name, ident.order_code,
        ident.firmware_version, ident.serial_number,
    )


def _preallocate_dbs(server) -> None:
    """
    Pre-populate snap7's memory_areas so all reads return valid data.

    CONFIRMED against the installed pure-Python snap7 server
    (/usr/local/lib/python3.13/dist-packages/snap7/server/__init__.py):

      line  80: self.memory_areas: Dict[Tuple[S7Area, int], bytearray] = {}
      line 231: self.memory_areas[area_key] = data     (register_area)
      line 923: def _read_from_memory_area(self, area: S7Area, db_number, ...)
      line 946: area_data = self.memory_areas[area_key]

    Three facts that drive this implementation:

    1. register_area() takes a **SrvArea** enum, not S7Area. It maps
       SrvArea -> S7Area internally and raises ValueError for anything
       else. Passing S7Area.PE (129) is what produced
       "ValueError: Unsupported area: 129".

    2. register_area() does `data = bytearray(userdata)` -- it COPIES the
       buffer. A ctypes array passed in is copied once at registration;
       later writes to that ctypes array are never seen by the server.

    3. Reads are served directly from self.memory_areas[(S7Area.X, index)]
       which holds plain **bytearrays**.

    Therefore: populate memory_areas directly with bytearrays keyed by the
    S7Area enum, and have write_fn mutate those same bytearrays in place.
    No register_area call, no ctypes.
    """
    # Always create the tracking dict first so attach_to_server() never
    # finds the attribute missing, even if this function returns early.
    server.s7_buffers = {}

    if not hasattr(server, "memory_areas"):
        log.warning("server has no memory_areas dict -- S7 reads will return "
                    "errors; this snap7 build is not supported")
        return

    # ── locate the S7Area enum (the KEY type for memory_areas) ────────────
    # CRITICAL: must be the SAME class object the server uses internally.
    # Confirmed from the installed library (line 936):
    #     area_key = (area, db_number)
    #     if area_key not in self.memory_areas:
    #         return bytearray([0x42, 0xFF, 0x12, 0x34])[:count]
    # A key built from a different S7Area class hashes differently, so every
    # read falls through to that dummy 0x42FF1234 buffer — which is exactly
    # what a live deployment produced before this lookup was fixed.
    #
    # The server module imports S7Area at its top level, so reading it off
    # that module gives us the exact object. Try that first, then fall back.
    S7Area = None
    try:
        server_mod = sys.modules.get(type(server).__module__)
        if server_mod is not None and hasattr(server_mod, "S7Area"):
            S7Area = server_mod.S7Area
            log.info("Found S7Area on the server's own module (%s)",
                     type(server).__module__)
    except Exception as exc:
        log.debug("server-module S7Area lookup failed: %s", exc)

    if S7Area is None:
        for modname in ("snap7.server", "snap7.type", "snap7.types",
                        "snap7.protocol", "snap7"):
            try:
                mod = __import__(modname, fromlist=["S7Area"])
                if hasattr(mod, "S7Area"):
                    S7Area = mod.S7Area
                    log.info("Found S7Area enum in %s", modname)
                    break
            except ImportError:
                continue

    if S7Area is None:
        log.error("Could not locate the S7Area enum. memory_areas cannot be "
                  "pre-allocated, so EVERY S7 read will return the library's "
                  "dummy 0x42FF1234 buffer — an immediate honeypot tell.")
        return

    def _area(*names):
        for n in names:
            if hasattr(S7Area, n):
                return getattr(S7Area, n)
        return None

    db_area = _area("DB", "S7AreaDB")
    pe_area = _area("PE", "S7AreaPE")
    pa_area = _area("PA", "S7AreaPA")
    mk_area = _area("MK", "S7AreaMK")

    if db_area is None:
        log.warning("S7Area.DB not found -- cannot pre-allocate DBs")
        return

    mem = server.memory_areas

    # CONFIRMED from python-snap7 3.1.2 source: both _read_from_memory_area
    # and _write_to_memory_area do `with self.area_locks[area_key]:` — so a
    # key present in memory_areas but missing from area_locks raises KeyError,
    # which the outer `except Exception` swallows and turns into all-zeros.
    # register_area() creates the lock; because we populate memory_areas
    # directly we must create it ourselves.
    import threading as _threading
    locks = getattr(server, "area_locks", None)
    if locks is None:
        locks = {}
        server.area_locks = locks

    def _alloc(area_enum, area_str: str, index: int, size: int):
        """Create a bytearray + its lock, and track it for write_fn."""
        if area_enum is None:
            return None
        key = (area_enum, index)
        if key not in mem or len(mem[key]) < size:
            mem[key] = bytearray(size)
        if key not in locks:
            locks[key] = _threading.Lock()
        # Track by the string name attach_to_server() uses
        server.s7_buffers[(area_str, index if area_str == "DB" else 0)] = mem[key]
        return mem[key]

    # ── I/Q/M areas (index 0) ─────────────────────────────────────────────
    for area_enum, area_str in ((pe_area, "I"), (pa_area, "Q"), (mk_area, "M")):
        if area_enum is not None:
            _alloc(area_enum, area_str, 0, 256)
        else:
            log.info("S7Area for %s not available on this build", area_str)

    # ── DB 1-998 (DB999 deliberately absent so error probes get an error) ──
    allocated = 0
    for db_number in range(1, 999):
        if _alloc(db_area, "DB", db_number, 512) is not None:
            allocated += 1

    # DB999 must NOT exist: S7ClientTests.TestErrorHandling probes it
    # expecting "data block does not exist". Remove it if a previous run
    # or the library itself created it on demand.
    mem.pop((db_area, 999), None)
    locks.pop((db_area, 999), None)
    server.s7_buffers.pop(("DB", 999), None)

    areas = sorted({k[0] for k in server.s7_buffers})

    # Self-check: prove the keys we wrote are the keys the server reads with.
    # If they mismatch, _read_from_memory_area returns its dummy 0x42FF1234
    # buffer for every request — a silent failure this check makes loud.
    verified = False
    try:
        probe = getattr(server, "_read_from_memory_area", None)
        if probe is not None:
            got = probe(db_area, 200, 0, 4)
            verified = got is not None and bytes(got[:4]) != b"\x42\xff\x12\x34"
    except Exception as exc:
        log.debug("pre-allocation self-check could not run: %s", exc)

    log.info("Pre-allocated %d DBs + areas %s in memory_areas "
             "(bytearrays, written in place); DB999 intentionally absent",
             allocated, areas)

    if verified:
        log.info("Self-check OK: DB200 read returns allocated memory, "
                 "not the library dummy buffer")
    else:
        log.error("SELF-CHECK FAILED: a DB200 read did not return allocated "
                  "memory. S7Area key mismatch — reads will return the "
                  "library's dummy 0x42FF1234 data. Check which module the "
                  "server imports S7Area from.")


def _patch_missing_area_error(server) -> None:
    """
    Ensure reads of unregistered areas return an S7 error, not zeros.

    A real S7-315 returns "data block does not exist" for a DB with no
    program allocation. S7ClientTests.TestErrorHandling probes DB999
    expecting a failure; a server that returns zeros for every DB number
    an attacker asks for is behaving like a memory dict, not a PLC.

    IMPORTANT — COMPARE BY VALUE, NOT IDENTITY:
    memory_areas is keyed by (S7Area, index). The S7Area enum object we
    import here is not guaranteed to be the same class object snap7 passes
    internally (different import paths, or a plain Enum vs IntEnum, hash
    differently). A naive `key not in memory_areas` check therefore fails
    for EVERY area and turns the whole honeypot into an error generator —
    confirmed on deployment. We build a set of int(area) values instead.
    """
    original = getattr(server, "_read_from_memory_area", None)
    if original is None:
        log.debug("server has no _read_from_memory_area — skipping error patch")
        return

    # Snapshot which (area_value, index) pairs are legitimately allocated.
    try:
        allocated = {(int(a), int(i)) for (a, i) in server.memory_areas.keys()}
    except Exception as exc:
        log.warning("Could not enumerate memory_areas keys (%s) — "
                    "skipping missing-area patch", exc)
        return

    # Safety valve: if pre-allocation clearly didn't work, do NOT install
    # this patch. Serving zeros is a mild tell; erroring on every read is a
    # broken honeypot that no client can talk to at all.
    if len(allocated) < 100:
        log.warning("Only %d areas allocated — skipping missing-area patch "
                    "(pre-allocation appears to have failed)", len(allocated))
        return

    def patched(area, db_number, start, count):
        try:
            key = (int(area), int(db_number))
        except (TypeError, ValueError):
            return original(area, db_number, start, count)
        if key not in allocated:
            log.info("S7 read of unregistered area 0x%02X db=%d offset=%d "
                     "-> address error (as a real PLC would)",
                     key[0], key[1], start)
            return None          # snap7 turns this into an S7 address error
        return original(area, db_number, start, count)

    server._read_from_memory_area = patched
    log.info("Patched _read_from_memory_area: %d areas allocated; "
             "unregistered areas (e.g. DB999) now return an S7 error",
             len(allocated))


def _reconcile_cpu_state_with_boot() -> None:
    """
    A freshly "booted" PLC must not still be in STOP.

    cpu_state.json persists across service restarts, so a PLC STOP issued
    before a restart leaves the CPU in STOP. Meanwhile fake_boot_epoch is
    regenerated, so the diagnostic buffer reports "Power up" and
    "STOP -> RUN" minutes ago while SZL 0x0424 says STOP. A real S7-315
    that completed its startup sequence with the key switch at RUN is in
    RUN — the two surfaces contradict each other.

    Rule: if the recorded state change happened BEFORE the current
    fake_boot_epoch, it belongs to a previous power cycle and is
    superseded by startup. A STOP issued after boot is honoured, exactly
    as real hardware would.
    """
    import json
    try:
        from paths import Paths
        net_path = Paths.load(getattr(_reconcile_cpu_state_with_boot, "_cfg", "config.yaml")).network_state
        if not net_path.exists():
            return
        boot_epoch = json.loads(net_path.read_text()).get("fake_boot_epoch", 0)
        if not boot_epoch:
            return

        state_path = cpu_state.STATE_PATH
        if not state_path.exists():
            return
        data = json.loads(state_path.read_text())
        if data.get("state") != cpu_state.STATE_STOP:
            return

        changed_at = data.get("changed_at", 0)
        if changed_at < boot_epoch:
            # Pre-dates this power cycle — startup puts the CPU back in RUN.
            # Written directly so no STOP->RUN diagnostic event is logged:
            # the synthetic boot sequence already contains that transition.
            state_path.write_text(json.dumps(
                {"state": cpu_state.STATE_RUN, "changed_at": boot_epoch + 5},
                indent=2))
            log.info("CPU was STOP from before this power cycle "
                     "(state change %.0fs before boot) — startup restores RUN",
                     boot_epoch - changed_at)
        else:
            log.info("CPU is in STOP from a command issued after boot — "
                     "honouring it")
    except Exception as exc:
        log.warning("Could not reconcile CPU state with boot epoch: %s", exc)


def _start_server_loopback(server, port: int) -> bool:
    """
    Attempt to bind snap7.Server to 127.0.0.1 only using Srv_StartTo from
    libsnap7.so.  This is belt-and-suspenders alongside the iptables INPUT
    rule in fingerprint_harden.sh — it means port 1102 never appears on the
    external NIC regardless of whether the firewall script has been run.

    The Python snap7.Server.start() wrapper calls Srv_Start() which binds to
    0.0.0.0 with no way to specify an address.  The C library does export
    Srv_StartTo(S7Object, const char *Address, int Port) which binds to a
    specific IP.  We call it directly via ctypes.

    Returns True if the loopback-only bind succeeded, False if Srv_StartTo is
    not available (older libsnap7 build) — caller falls back to server.start().
    """
    import ctypes, ctypes.util
    try:
        lib_name = ctypes.util.find_library("snap7")
        if not lib_name:
            return False
        lib = ctypes.CDLL(lib_name)
        fn  = lib.Srv_StartTo                    # raises AttributeError if absent
        fn.restype  = ctypes.c_int
        fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint16]

        # Get the raw C pointer from the Python snap7 Server object.
        # python-snap7 stores it as server.pointer (property) or server._pointer.
        ptr = getattr(server, "pointer", None) or getattr(server, "_pointer", None)
        if ptr is None:
            return False

        ret = fn(ptr, b"127.0.0.1", port)
        if ret == 0:
            log.info("snap7 backend bound to 127.0.0.1:%d (Srv_StartTo)", port)
            return True
        log.warning("Srv_StartTo returned %d — falling back to server.start()", ret)
        return False
    except (AttributeError, OSError) as exc:
        log.debug("Srv_StartTo not available (%s) — using server.start()", exc)
        return False


def run_backend(config_path: str = "config.yaml") -> None:
    import diag_log as _dl
    _dl.configure(config_path)
    cpu_state.configure(config_path)

    apply_identity_patch(config_path)

    # A PLC that just completed startup must not still be in STOP from a
    # previous power cycle — see _reconcile_cpu_state_with_boot().
    _reconcile_cpu_state_with_boot()

    # python-snap7 is the one hard runtime dependency the backend cannot do
    # without. install.sh installs and verifies it, but give a clear message
    # rather than a raw ModuleNotFoundError if it is somehow missing (e.g. the
    # service was started against the system Python instead of the venv).
    try:
        import snap7
    except ImportError:
        log.error("python-snap7 not installed. The backend cannot start "
                  "without it. Install it into the honeypot virtualenv:\n"
                  "  /opt/s7honeypot/venv/bin/pip install python-snap7\n"
                  "and ensure the service runs under that interpreter.")
        raise SystemExit(1)
    server = snap7.Server()

    # Try to bind to loopback only so port 1102 never appears on the
    # external NIC even before fingerprint_harden.sh has been run.
    if not _start_server_loopback(server, 1102):
        # Srv_StartTo not available — fall back to the Python wrapper which
        # binds to 0.0.0.0.  The iptables INPUT rule in fingerprint_harden.sh
        # provides the external-facing protection in this case.
        server.start(tcp_port=1102)
        log.warning("snap7 bound to 0.0.0.0:1102 — "
                    "ensure fingerprint_harden.sh apply has been run to "
                    "block port 1102 on the external interface")

    log.info("Backend snap7.Server running on port 1102")

    # DB pre-allocation must never crash the backend — a honeypot serving
    # zeros is far better than a honeypot in a systemd restart loop.
    try:
        _preallocate_dbs(server)
    except Exception as exc:
        log.error("DB pre-allocation failed (continuing anyway): %s", exc,
                  exc_info=True)

    # Make reads of unregistered areas (e.g. DB999) return an S7 error
    # rather than zeros. Must run AFTER pre-allocation so the legitimate
    # DBs are already in memory_areas.
    try:
        _patch_missing_area_error(server)
    except Exception as exc:
        log.warning("Could not patch missing-area error handling: %s", exc)

    # Patch the pure-Python snap7 read/write paths so unallocated and
    # deliberately-absent DBs return S7 errors instead of zeros, matching
    # what a real S7-315 does. See snap7_patches.py for the confirmed
    # source-line references this is based on.
    try:
        import snap7_patches
        results = snap7_patches.apply_all(server)
        log.info("snap7 behaviour patches: %s", results)
    except Exception as exc:
        log.warning("snap7 patches not applied: %s", exc)

    from process_simulator import ProcessSimulator
    from modbus_bridge import ModbusBridge

    bridge = ModbusBridge(config_path)
    bridge_active = bridge.start(server=server)

    simulator = ProcessSimulator(config_path)
    if bridge_active:
        # Bridge owns the I/Q/M and process DB values; simulator handles
        # the remaining tags (counters, DB500/501 test tags) that aren't
        # mapped from Modbus.
        log.info("Modbus bridge active — process_simulator running in "
                 "counter-only mode (I/Q/M and DB200 driven by OpenPLC)")
        simulator.exclude_areas = {"I", "Q", "M"}
        simulator.exclude_dbs   = {200, 201, 202, 203, 121, 300, 701}
        # Bridge writes process_state.json directly with OpenPLC values.
        # Stop the simulator writing it so it doesn't overwrite the bridge.
        simulator.skip_process_state = True
    simulator.start(server=server)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        simulator.stop()
        server.stop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    run_backend(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")
