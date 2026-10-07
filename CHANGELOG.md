# Changelog

All notable changes to honeypot-s7 are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/).

## [Unreleased]

- **OpenPLC boot check now requires the program to be executing.** After a
  reboot the runtime answered on 502 with every register at zero (no program
  running); the bridge copied zeros, the portal froze, and nothing reported
  an error. `openplc_autostart.sh` now also reads the scan counter (HR6)
  across a 2 s window and fails `s7honeypot-openplc` if it isn't advancing.
  `install_openplc.sh` runs the same check at the end, prints a Program
  status line, and finishes with explicit OpenPLC UI steps (upload
  `process_sim.st`, Start PLC, enable "Start in RUN mode"); its stale process
  description (75 °C setpoint etc.) now matches `process_sim.st`.
  `check_openplc.py` reports the real failure (connection reset / Modbus
  exception code / truncated reply) and flags all-zero registers, instead of
  a generic "No Modbus response".

- **OpenPLC runtime forced into RUN at every container start.** After a
  reboot the OpenPLC container came back but the PLC runtime (and Modbus 502
  inside it) did not — OpenPLC v3 only auto-starts it if "Start in RUN mode"
  was saved. The host-side `docker-proxy` still accepted on 127.0.0.1:502 and
  reset every read, so the bridge looped connect/reconnect and the portal
  showed "Process data acquisition fault". New `deploy/openplc_autostart.sh`
  runs as `ExecStartPost` of `s7honeypot-openplc.service`: waits for the web
  UI, logs in, sends `start_plc`, and fails the unit if 502 never opens inside
  the container. `install_openplc.sh` also sets the run-mode flag in
  OpenPLC's settings DB so the two agree. TROUBLESHOOTING §4 documents the
  symptom.

- **Boot order: everything starts after ip-writer.** `harden`, `backend`
  (and therefore `proxy`) and `synack-spoof` now carry `After=`/`Wants=`
  `s7honeypot-ip-writer`, so the full chain is mac-spoof → ip-writer → the
  rest. ip-writer takes `--settle` (default 5 s, for the post-MAC-spoof link
  flap) and `--wait` (default 90 s, DHCP poll) from two new config keys,
  `x-boot-settle-seconds` / `x-boot-ip-wait-seconds`; the unit's
  `TimeoutStartSec` is derived from them.

- **ip-writer no longer fails at boot on slow DHCP.** On a Debian box with
  no `*-wait-online` unit, `network-online.target` is reached before the NIC
  has an address, so `boot_ip_writer.py` ran too early, exited 1, and took
  `snmp` + `web` down with it (`Requires=`). Seen on a fresh install: failed
  at boot, succeeded on a manual restart 84 s later. Now: the script polls for
  up to 90 s for an IPv4 address; the unit has `Restart=on-failure` as a
  backstop; and `snmp`/`web` use `Wants=` so a late lease delays the recorded
  IP instead of stopping those services.

- **TTL rewrite now covers UDP.** SNMP replies were leaving with the Linux
  TTL (nmap `-sU` showed `ttl 64` on 161) while TCP and ICMP showed 30.
  `fingerprint_harden.sh` apply/revert/status handle `udp` alongside
  `tcp`/`icmp`.

- **Installer exercised end to end on a clean Debian-family host** (Ubuntu
  24.04 container, root, no systemd). Fixes from that run:
  - `python3-netfilterqueue` is not packaged on every release (absent on
    Ubuntu 24.04, present on Debian 12 / Raspberry Pi OS). `install.sh` now
    tries apt first and otherwise builds `NetfilterQueue` from pip inside the
    venv (installing `libnetfilter-queue-dev` + `python3-dev`), instead of
    aborting the whole install.
  - `honeypot.py` (the proxy) never called `cpu_state.configure()` /
    `diag_log.configure()`, so STOP/RUN transitions were written to the
    state dir of whatever `config.yaml` was in the current directory rather
    than the config it was started with. This also made the test suite leak
    a STOP into the real `/var/lib/s7honeypot/`.
  - `verify_live_db_reads.py` tries the python-snap7 3.2 keyword
    (`tcp_port=`) before the 3.1 one (`tcpport=`).
  - `s7_repl.py` option 6 decodes SZL 0x0424 itself: python-snap7 3.2.x's
    `get_cpu_state()` is a stub that always answers RUN.
  - `generate_services.py` and `fingerprint_harden.sh` no longer print
    stale "next steps" / "not persistent" advice that contradicts the
    installer and the boot unit.

- **INSTALL.md fast path rewritten.** The old fast path said to edit config
  after installing, which meant the units and hardening rules were generated
  for the example interface (`ens33`). It also said to start only
  `s7honeypot-proxy`, which pulled in the backend but left the MAC spoof, IP
  writer, hardening, SNMP, web portal and SYN-ACK spoofer stopped. It now
  configures first, places OpenPLC before the first start, and starts the
  units with a reboot or an explicit ordered start. It adds a verification
  checklist (expected unit states, listening ports, every iptables/ip6tables
  rule, network-state match, external nmap/ping/PDU checks), a
  symptom→fix table, and a safe procedure for changing config after install.
  README, the TROUBLESHOOTING hardening sections and `install.sh`'s printed
  next steps now match it.

- **`s7_repl.py` option 19 — scan a DB number range.** Probes each DB in a
  range (default 1–50) and classifies it as DATA (first 8 bytes shown in hex +
  ASCII), all-zeros, or ERROR (absent). Warns up front that large ranges are
  noisy and can stress a real CPU; asks for confirmation above 200 DBs and
  refuses above 2000. Probes are paced 50 ms apart, the read size is limited
  to 1–200 bytes (an oversized read would fail on every DB and be misreported
  as "absent"), and the scan aborts with a clear message if the connection
  drops instead of reporting the rest of the range as missing.

- **`session_analyzer.py` finds `commands.jsonl` from config.** The default
  path was a hardcoded `/var/log/s7honeypot/commands.jsonl` that never
  existed; it now resolves `logging.jsonl_path` (with `${DATA_DIR}`) from
  `--config` (default `config.yaml`), honouring `S7HONEYPOT_DATA_DIR`.

- **IPv6 disabled.** A real S7-300 is IPv4-only; modern Linux answers IPv6 by
  default, so responding on IPv6 at all is a binary tell.
  `fingerprint_harden.sh` now disables IPv6 (sysctl + ip6tables backstop,
  reversible), and the web/SNMP/proxy services bind IPv4-only sockets.


- **TTL corrected to the real S7-300 value (30).** The previous hardening set
  TTL to 64 — which is Linux's default, so it presented a Linux TTL and did
  nothing. Real S7-300 hardware uses TTL 30, a distinctive value. The rewrite
  now covers ICMP as well as TCP (so `ping` doesn't leak the Linux TTL) and is
  scoped to the honeypot NIC via mangle rather than the global sysctl, leaving
  the host's own management traffic untouched. Configurable via `x-target-ttl`.


- **PDU size is now configurable** via `identity.max_pdu` in config.yaml
  (240/480/960 — the real S7 values; a non-standard size is itself a tell, and
  the loader warns if one is set). The value flows consistently to the
  connection-setup PDU-negotiation patch, SZL 0x0131 (communication
  capability), and the SZL 0x00A0 diagnostic-buffer record cap (which now
  scales with the PDU so the response always fits). Default remains 480.

- **STOP de-energizes outputs.** On CPU STOP the Q (process output) area and
  output coils now go to 0, matching real S7-300 behavior (outputs de-energize
  to the substitute state when the CPU stops driving them), while DB, M, and I
  areas hold their last value. Previously all areas froze uniformly, so a Q
  read in STOP returned the last RUNNING value — a state real hardware can't
  show. Applied consistently to both the built-in simulator and the OpenPLC
  bridge, in snap7 memory and the web portal.

## [0.1.0] — Initial public release

First public release. A high-interaction Siemens S7-300 (CPU 315-2 PN/DP)
honeypot with the following capabilities.

### Protocol surfaces
- **S7comm** (TCP/102): connection setup, PDU negotiation, SZL identity reads
  (0x0011, 0x001C, 0x0424, 0x00A0, 0x0013, 0x0014, 0x0131, 0x0132, 0x0037,
  0x0232), variable read/write, block transfer, PLC STOP/START — answering as
  a CPU 315-2 PN/DP.
- **Web portal** (TCP/80): S7-300 web-diagnostics replica with module
  identification, Ethernet details, live process overview, and a diagnostic
  buffer backed by real event history.
- **SNMP** (UDP/161): hand-rolled v1/v2c responder with correct type tags,
  seeded restart-resilient uptime, and dynamic IP/MAC.

### Deception / fingerprint hardening
- Cross-surface identity consistency from a single config.
- Library-tell patching at the proxy: COTP Connection Confirm (DST-REF and
  class byte), PDU negotiation corrected to the real 480-byte value.
- TCP-stack hardening: TTL rewrite, SACK/timestamp/window-scaling disable,
  SYN-ACK window/option rewrite via NFQUEUE.
- Blocked ports use `REJECT --reject-with tcp-reset` so `nmap` reports
  `closed` (as real unused ports do) rather than the more revealing
  `filtered`.
- MAC spoofed to a real Siemens Amberg OUI.
- Diagnostic-buffer safety filter preventing any entry that would name the
  honeypot's own machinery.

### Process values
- Built-in self-driven process simulator (pump/heat-exchanger state machine).
- Optional OpenPLC integration: a real IEC 61131-3 program bridged into the S7
  memory, with OpenPLC's ports bound to loopback only.
- Data-acquisition watchdog: on bridge failure, values freeze consistently
  across S7comm and the web portal and a plant-agnostic "Process data
  acquisition fault" is raised, clearing on recovery.

### Capture
- One pcap per validated session (valid TPKT+COTP required, filtering scan
  noise) plus a structured JSONL log with parsed fields and full raw hex,
  correlated by session.

### Infrastructure
- Single-config path resolution (`paths.py`) — no hardcoded state locations.
- Installer with a Python 3.9+ version gate, deploying into an isolated
  virtualenv; systemd units generated from config and run under the venv.
- 19-module test suite covering BER/ASN.1, S7 frame parse/build, SZL byte
  layouts, the COTP/PDU patches, block transfer, the path resolver, the
  watchdog, and the diagnostic-buffer safety filter.

### Validation
Exercised against `nmap --script s7-info`, `plcscan`, `snmpwalk`, and
python-snap7 clients, and run in live deployment, with real bugs found and
fixed at each stage.

[Unreleased]: https://github.com/USER/honeypot-s7/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/USER/honeypot-s7/releases/tag/v0.1.0
