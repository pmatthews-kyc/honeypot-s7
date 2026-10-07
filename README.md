# honeypot-s7

*Created by Patrick Matthews for educational purposes.*

A high-interaction honeypot that impersonates a **Siemens SIMATIC S7-300
(CPU 315-2 PN/DP)** programmable logic controller. It answers S7comm on
TCP/102, serves a Siemens-style web diagnostics portal on port 80, responds
to SNMP, and — optionally — drives its process values from a real OpenPLC
runtime executing IEC 61131-3 logic. Every connection is captured to pcap
and structured JSON for later analysis.

Built for **authorized defensive security research**: capturing and
reconstructing S7comm attack traffic on an isolated or instrumented network.

![Web diagnostics portal](docs/img/portal.png)

---

## ⚠️ Responsible use

This project deceives connecting systems into believing they are talking to a
real industrial controller. That is legitimate and useful for defenders, but
it carries responsibilities:

- **Only deploy on infrastructure you own or are explicitly authorized to
  operate a honeypot on.** Operating a deceptive service may have legal
  implications depending on your jurisdiction and network.
- **Never place it on a network where it could be mistaken for, or interfere
  with, a real control system.** It accepts PLC STOP and block-transfer
  commands without authentication (that is *correct* S7-300 behavior and part
  of the deception) — pointed at the wrong network, that behavior is a
  liability.
- **You are responsible for the data you capture** — attacker traffic may
  contain sensitive material. Store and handle it accordingly.
- This is research tooling, provided under the GPL with **no warranty**. You
  assume all risk of deployment.

---

## What it does

| Surface | Behavior |
|---|---|
| **S7comm** (TCP/102) | Connection setup, PDU negotiation, SZL identity reads (module/component identification, CPU state, diagnostic buffer, memory areas, comms capability), variable read/write, block transfer, PLC STOP/START. Answers as a CPU 315-2 PN/DP. |
| **Web portal** (TCP/80) | Faithful replica of the S7-300 web diagnostics interface — module identification, Ethernet details, live process overview, diagnostic buffer with real event history. |
| **SNMP** (UDP/161) | `sysDescr`, `sysName`, `sysUpTime` (seeded, restart-resilient), interface/address tables — all sourced from the same identity as the other surfaces so they never contradict each other. |
| **Process values** | Either a self-contained Python simulator (bounded, correlated, state-machine driven) or a real **OpenPLC** runtime executing an IEC 61131-3 program, bridged into the S7 memory the controller serves. |
| **Capture** | One pcap per validated session plus a structured JSONL log of every parsed S7/SNMP/HTTP message — parsed fields *and* full raw hex, correlated by session. |

The identity, network fingerprint, SNMP data, and web portal all draw from
one configuration, so an attacker cross-referencing the surfaces sees a single
consistent device rather than three fakes that drift apart.

---

## Architecture

```
                       Internet / ICS network
                                │
                                ▼   TCP/102
                    ┌───────────────────────┐
                    │   honeypot.py (proxy)  │   public-facing
                    │   • s7_precheck: only  │   • frame-level relay
                    │     valid TPKT+COTP    │   • intercepts SZL, clock,
                    │     sessions proceed   │     block, STOP/START
                    │   • per-session pcap   │   • patches library tells
                    │     + JSONL logging    │     (COTP CC, PDU size)
                    └───────────┬───────────┘
                                │  TCP/1102 (loopback only)
                                ▼
                    ┌───────────────────────┐
                    │  backend_server.py     │   snap7 pure-Python S7 server
                    │  • pre-allocates DBs   │
                    │  • serves reads/writes │
                    └───────────┬───────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
     process_simulator   modbus_bridge      (shared state files,
     (built-in values)   (OpenPLC values)   resolved via paths.py)
```

The proxy does the deception and capture; the backend just serves memory.
Filtering and interception live in the proxy so they don't depend on the
snap7 library's internals — a deliberate hedge, since that library is a
moving target. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
design rationale.

---

## Quick start
Tested on Debian 13 and OrangePI Debian/

On a Debian-based Raspberry Pi (or similar SBC):

```bash
git clone <your-repo-url> honeypot-s7
cd honeypot-s7
cp config.yaml.example config.yaml
nano config.yaml                       # x-interface + unique serial FIRST
sudo bash deploy/install.sh
```

Edit `config.yaml` **before** running `install.sh` — at minimum
`x-interface` and a unique serial. The installer generates the systemd units
and the hardening rules from it. `install.sh` installs system and Python
dependencies, deploys to `/opt/s7honeypot`, and enables the units. Then:

```bash
sudo reboot        # starts every unit in the right order
```

[INSTALL.md → The fast path](INSTALL.md#the-fast-path) has the full sequence,
how to start without rebooting, and a checklist to confirm services, ports and
firewall rules are correct.

**Optional — realistic process values from OpenPLC** (run this after
`install.sh` and *before* the reboot):

OpenPLC runs in Docker. You do **not** need Docker installed beforehand —
`install_openplc.sh` installs Docker Engine and the compose plugin for you,
then builds and configures OpenPLC:

```bash
sudo bash /opt/s7honeypot/deploy/install_openplc.sh
```

This runs OpenPLC in Docker (Modbus and its IDE bound to loopback only, never
exposed on the external interface), uploads the process program, and enables
the bridge. See [INSTALL.md](INSTALL.md) for the full deployment guide, and
[`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) for confirming it works and
diagnosing the common problems (the venv rule, OpenPLC "up but not running",
which services are safe to restart, fingerprint verification).

To remove it cleanly — services, hardening, virtualenv, install dir — run
`sudo bash deploy/uninstall.sh` (captured data is preserved unless you pass
`--purge-data`).

---

## Configuration

All deployment-specific settings are anchors at the top of `config.yaml`:

| Anchor | Purpose |
|---|---|
| `x-interface` | NIC the honeypot listens on |
| `x-data-dir` | where pcaps and the command log are written (point at a removable drive) |
| `x-state-dir` | runtime state files (cpu/network/process state, database) |
| `x-siemens-oui` | MAC prefix spoofed to a real Siemens OUI |
| `x-openplc` / `x-modbus-bridge` | enable the OpenPLC process engine |

Change one value to relocate a whole class of paths — every module resolves
through `paths.py`, so readers and writers can't disagree. **Change the
`serial_number` before deploying**: a shared serial across copies would itself
become a fingerprint identifying the deployment as this honeypot.

-----

## Validation status

This project has been exercised against standard ICS scanning tools —
`nmap --script s7-info`, `plcscan`, `snmpwalk`, and python-snap7 clients — and
run in live deployment, with real bugs found and fixed at each stage
(SZL byte layouts, PDU negotiation, SNMP type tags, the snap7 memory model).

**Known remaining gaps**, stated plainly:

- **TCP options ordering in the SYN-ACK** — the strongest `p0f` / `nmap -O`
  passive signal — is only partially addressed. TTL and sysctl tuning plus a
  SYN-ACK window/option rewrite cover the common cases; a full raw-socket
  handshake rebuild is scoped as separate work, worthwhile only against
  sophisticated targeted recon.
- **No TLS/JA3S** anywhere — moot while nothing in the stack speaks TLS, but
  relevant if an HTTPS portal or OPC UA endpoint is added later.
- **Block content is not real MC7 bytecode** — read-back blocks have
  realistic headers but won't decompile as working logic.

See [`docs/FINGERPRINTING.md`](docs/FINGERPRINTING.md) for the full account of
what each deception layer defeats and where the boundaries are.

---

## Credits

- [python-snap7](https://github.com/gijzelaerr/python-snap7) — the pure-Python
  S7 server this builds on.
- [OpenPLC](https://autonomylogic.com/) — the IEC 61131-3 runtime used for
  realistic process values.
- Generic S7-300 identity defaults derive from
  [Conpot](https://github.com/mushorg/conpot)'s publicly documented values —
  device-class emulation, not impersonation of any real unit.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
