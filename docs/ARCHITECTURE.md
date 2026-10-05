# Architecture and Design Decisions

This explains *why* the honeypot is built the way it is — the design decisions
that shaped it — and how the pieces fit together at runtime. For what each
deception layer defeats, see [FINGERPRINTING.md](FINGERPRINTING.md).

---

## The core decision: a proxy in front of a generic server

The honeypot is two processes:

- **`honeypot.py`** — the public-facing proxy on TCP/102. It does all the
  filtering, capture, interception, and deception.
- **`backend_server.py`** — a loopback-only (`127.0.0.1:1102`) instance of
  python-snap7's pure-Python S7 server. It just serves memory: variable reads
  and writes against pre-allocated data blocks.

Everything that makes this a *honeypot* rather than a generic S7 server lives
in the proxy. The backend is deliberately dumb.

**Why split it this way?** python-snap7's server is a moving target — it had a
recent ground-up rewrite and continues to change. Hooking its internals for
filtering and capture would couple the honeypot to a specific version's API.
By putting that logic in a frame-parsing proxy in front of the server, the
honeypot depends only on the *protocol* (which is stable) and not the
*library* (which is not). When the library emits a value a real PLC wouldn't
(the COTP and PDU tells in FINGERPRINTING.md), the proxy patches it on the way
out — again, independent of the library version.

This decision has paid off repeatedly. The library's internal memory model
turned out to be entirely different from what was first assumed (a
`register_area`/ctypes model versus the actual `memory_areas` bytearray dict
keyed by an `S7Area` enum), and because reads/writes flow through a
pre-allocation step the honeypot controls rather than library internals the
proxy hooks, adapting to the real API was contained to one module.

---

## Protocol and port choices

**S7comm over Modbus.** Siemens PLCs don't natively speak Modbus TCP (it's an
add-on integration library); S7comm on TCP/102 is essentially always present.
Emulating Modbus as the primary protocol would be a tell in itself.

**Port profile matched to a real device class.** A real S7-300/400 exposes 102
always; a web UI on 80 is common; SNMP is sometimes present. The honeypot's
port profile matches a plausible real deployment rather than an arbitrary set.

---

## Identity as configuration, sourced responsibly

Device identity — order code, firmware, serial, module name, copyright — lives
in `config.yaml` and is rendered into the SZL responses by `identity.py`. The
shipped defaults are Conpot's publicly documented, vetted generic S7-300
values, **not scraped from any real live device**. This is a deliberate line:
*device-class emulation, not device impersonation.* Deployers are expected to
set a unique serial (a shared one becomes a fingerprint — see the README).

The same identity feeds the SNMP agent and the web portal, so the surfaces
can't contradict each other.

---

## One configuration, one path resolver

Every runtime path — the capture directory, the state files, the diagnostic
database — resolves through a single module, `paths.py`, from one set of
`config.yaml` anchors (`x-data-dir`, `x-state-dir`, `x-honeypot-db`). No module
hardcodes a state-file location.

This exists because the alternative caused real bugs: a database created in one
place and read from another, a web portal reading a different process-state
file than the writer used. When a reader and a writer compute a path
independently, they can disagree. Routing every path through one resolver from
one config value makes that class of bug structurally impossible — change
`x-state-dir` and the whole set moves together.

---

## The capture pipeline

Built for **reconstruction**, not just detection:

- **`s7_precheck.py`** — a session is only captured if it presents a valid
  TPKT + COTP Connection Request. This filters generic internet scan noise.
  Its limits are stated honestly: it cannot distinguish a targeted attacker
  from an S7-aware fuzzer — that's a post-hoc log-analysis problem, not a
  capture-layer one.
- **`capture_manager.py`** — one `tshark` pcap per validated session, keyed to
  peer IP/port, size- and duration-capped.
- **`command_logger.py`** — a structured JSONL line per parsed S7/SNMP/HTTP
  message: function code, best-effort field parsing, *and* the full raw hex
  payload — everything needed to rebuild exactly what was sent, correlated by
  `session_id`.

The JSONL raw command stream and the SQLite diagnostic buffer are separate on
purpose: the JSONL is the complete operator-facing forensic record (including
data an attacker must never see); the SQLite buffer holds only the small set
of PLC-plausible events that get rendered *back* to attackers.

---

## Frame-based relay, not byte forwarding

`s7_header.py` does a proper TPKT/COTP/S7 parse-and-build. The relay reads
whole frames rather than blindly forwarding bytes, which is what lets it
intercept specific function codes — SZL reads, clock functions, block transfer,
PLC STOP/START — and answer them directly at the proxy without the backend
needing to implement them. This also handles fragmented TCP segments correctly
(a real capture test exercises this) and Userdata (0x07) PDUs, both of which
the original byte-forwarding approach got wrong.

---

## Shared-state pattern for cross-process consistency

Several facts must stay consistent across independent components: the CPU
RUN/STOP state (written by the block handler, read by the SZL 0x0424 handler
and the web portal), the network identity (written at boot, read by SNMP and
the portal), the process snapshot (written by the simulator or bridge, read by
the portal). Each is a small JSON state file, resolved through `paths.py`.

This is how a STOP command issued over S7comm shows up on the web portal and in
SNMP: they all read the same file. It's a simple pattern, but it's what keeps
the surfaces from telling different stories.

---

## Process values: two sources, one interface

The backend serves whatever is in its data-block memory. Two things can drive
that memory:

- **`process_simulator.py`** (default) — a self-contained pump/heat-exchanger
  state machine with bounded, correlated values. No external dependency.
- **`modbus_bridge.py`** (optional) — polls a real OpenPLC runtime over Modbus
  (loopback only) and writes its IEC 61131-3 program outputs into the same
  backend memory.

Both write to the same places, so the rest of the system doesn't care which is
active. When the bridge is enabled, the simulator steps aside for the
bridge-owned tags and takes on a watchdog role, reporting a data-acquisition
fault if the bridge stops delivering (see FINGERPRINTING.md, Layer 7).

---

## Development philosophy: build, then actually run it

Nearly every subtle bug in this project's history was caught not by writing
code but by *running* it — against the test suite, against real scanning
tools, against a live deployment. Wrong SNMP type tags, wrong SZL byte
offsets, an empty-versus-absent HTTP header, a mount check that couldn't fail,
the entire snap7 memory-model misunderstanding, a data path a reader and writer
disagreed on — none of these were visible by inspection. They surfaced by
execution.

The test suite (`tests/`) exists for exactly this reason, and the honesty about
what has and hasn't been validated (see the README's validation section) is
part of the same discipline: the difference between "designed well" and
"proven" is real, and worth stating plainly.
