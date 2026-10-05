# Fingerprinting and Deception

This document describes every technique used to make the honeypot look and
behave like a real Siemens S7-300, organized by the layer of inspection each
measure defeats. It is written for defenders who want to understand what the
honeypot does and does not hide — and, equally, for anyone evaluating whether
it is convincing enough for their threat model.

A note on why this is public: everything here is discoverable by inspecting
the code, and understanding *how* honeypots evade detection is exactly what a
defender needs in order to deploy one that works. The techniques below are
also, individually, well documented in the ICS security literature.

---

## The guiding principle: internal consistency

The single strongest defense against fingerprinting is not any individual
banner — it is that **every surface agrees**. An attacker who reads the S7comm
SZL identity, the SNMP `sysDescr`, and the web portal's module table sees one
device with one order code, one serial, one firmware, one IP, one MAC. All of
it derives from a single configuration (`config.yaml`) resolved through one
path module (`paths.py`), so the surfaces cannot drift apart even across
restarts or redeployment. A honeypot whose *claimed* state contradicts its
*actual* state is trivially caught; that failure mode is designed out.

---

## Layer 1 — Protocol identity (S7comm)

**S7comm chosen as the primary protocol, not Modbus.** Siemens PLCs do not
natively speak Modbus TCP — it is an optional add-on library — while S7comm on
TCP/102 is present on essentially every real unit. Emulating Modbus as the
primary protocol would itself be a tell. (When OpenPLC provides process
values, its Modbus port is bound to loopback only and never appears on the
external interface — see Layer 7.)

**SZL identity records populated from config.** The System Status List
responses that `nmap --script s7-info`, `plcscan`, and Shodan's S7 module read
to fingerprint a device — module identification (0x0011), component
identification (0x001C), CPU state (0x0424), diagnostic buffer (0x00A0),
memory areas (0x0013), system areas (0x0014), and communication capability
(0x0131/0x0132) — are all answered from configuration with byte-exact
structures confirmed against real hardware captures and the Wireshark s7comm
dissector.

Two byte-layout bugs found by testing against a real `plcscan` are worth
noting, because they show how exacting this has to be:

- SZL 0x001C shipped as a flat blob with a zeroed record header
  (`length-per-record = 0`). snap7 reads it by fixed offset and never
  noticed, but plcscan parses the header and splits the body by record
  length — a zero there raised `ValueError` and the scan reported nothing.
- SZL 0x0011 declared 84 body bytes but returned 96 (padded "for safety"),
  so a header-parsing client saw a fourth, truncated record.

Both are fixed with exact `length-per-record × record-count` sizing, verified
against both snap7's fixed-offset reader and plcscan's header-driven parser.

**Library tells patched at the proxy.** The snap7 server, being a generic S7
server rather than a Siemens emulator, emits values no real S7-315 does. These
are corrected in the relay so the fix is independent of the library version:

- **COTP Connection Confirm** — snap7 returns DST-REF `0x0000` and a
  class/options byte of `0x01`. A real S7-315 echoes the client's SRC-REF and
  uses `0x00`. Strict clients (STEP 7, TIA Portal, python-snap7) reject the
  non-zero class byte with "TCP connected, ISO didn't". Both bytes are patched
  on the outgoing CC.
- **PDU negotiation** — snap7 advertises a max PDU of 960 bytes. The confirmed
  spec value for a CPU 315-2 PN/DP is 480. The negotiate ACK is patched to
  480, which also makes it agree with the value reported in SZL 0x0131. Before
  the fix the two surfaces contradicted each other — arguably a worse tell
  than either value alone.

---

## Layer 2 — Network / TCP stack (`fingerprint_harden.sh`)

Application-layer identity spoofing does nothing about the fact that the box
is, at the kernel level, obviously Linux. This closes the cheap, high-value
gaps:

- **TTL rewrite** via `iptables -t mangle` on outbound traffic from the
  honeypot interface (both TCP and ICMP), setting the IP TTL to **30** — the
  confirmed value a real Siemens S7-300 presents. This is distinctive: not
  Linux's 64, Windows' 128, or network-gear 255. Applying it to ICMP as well
  as TCP matters because a `ping` echo reply doesn't originate from the S7
  port, so without the ICMP rule the reply would leak the host's Linux TTL of
  64 while the S7 service claimed to be Siemens — a direct inconsistency. The
  rewrite is scoped to the honeypot NIC via mangle rather than the global
  `ip_default_ttl` sysctl, so it doesn't change the TTL of the host's own
  management traffic (SSH, DNS). The value is configurable via `x-target-ttl`.
- **TCP timestamps, SACK, and window scaling disabled** via `sysctl` — many
  embedded/RTOS stacks (including older Siemens firmware) lack these, and
  having them enabled is itself a passive Linux signal to `p0f` and `nmap -O`.
- **SYN-ACK window and options rewrite** via an NFQUEUE handler
  (`syn_ack_spoofer.py`), reaching the two signals sysctl tuning can't:
  a fixed window value and MSS-only options.

**Closed-not-filtered port hygiene.** Ports the honeypot blocks (the loopback
backend on 1102, and OpenPLC's Docker ports) are rejected with a TCP reset,
not silently dropped. `DROP` makes `nmap` report `filtered` — which announces
"a firewall is deliberately hiding something here". A real PLC's unused ports
return a RST from the kernel, so `nmap` reports `closed`. `REJECT
--reject-with tcp-reset` produces that same RST, making the blocked port
indistinguishable from any other closed port. (The one exception is Docker
*egress* containment, which uses DROP deliberately — a compromised container
should get no feedback.)

**Known gap:** TCP options *ordering* in the SYN-ACK, the strongest passive
`p0f`/`nmap -O` signal, is only partially addressed. Fully defeating it needs
a raw-socket rebuild of the handshake response and is scoped as separate work.

**IPv6 disabled.** A real S7-300 (CPU 315-2 PN/DP and its generation) is
IPv4-only — its firmware predates IPv6 support in that CPU class. Modern Linux
auto-configures an IPv6 link-local address, answers Neighbor Discovery, and
responds to `ping6` by default, so a host that responds on IPv6 *at all* is
immediately inconsistent with claiming to be an S7-300 — a binary tell.
`fingerprint_harden.sh` disables IPv6 entirely (sysctl plus an ip6tables
backstop), which is the realistic behavior: the device is simply absent from
IPv6. The web portal, SNMP agent, and S7 proxy also bind IPv4-only sockets, so
even if IPv6 were re-enabled the services wouldn't answer on it.

---

## Layer 3 — SNMP (`snmp_agent.py`, `ber.py`)

A hand-rolled SNMP v1/v2c GET/GETNEXT responder (a minimal BER/ASN.1 codec,
avoiding a version-uncertain `pysnmp` dependency) answering the identity
fields SNMP-based scanning reads.

- **`sysUpTime` correctly tagged `TimeTicks` (0x43), not `INTEGER`** — a bug
  caught by the BER round-trip self-test; a type-strict parser would have
  flagged the wrong tag.
- **IPv4 addresses encoded as `IpAddress` (APPLICATION 0, tag 0x40)**, not
  `OCTET STRING` — another bug caught against a real `snmpwalk`, which reported
  "Wrong Type (should be IpAddress)".
- **`ifDescr` returns a Siemens module string**, not the Linux kernel
  interface name (`eth0`), which the first version leaked.
- **Seeded, restart-resilient `sysUpTime`.** Rather than counting from process
  start (an obvious "just rebooted as you scanned me" tell, and one that would
  reset every time systemd restarted the agent), a random point up to a year
  in the past is chosen once per real host boot and stored as an absolute
  timestamp. Uptime is computed from wall-clock against that point, so it keeps
  advancing correctly across process restarts and only resets on an actual
  reboot.
- **Dynamic IP/MAC.** `boot_ip_writer.py` records the real interface
  IP/netmask/MAC at boot into a state file the agent re-reads on *every*
  request, so the SNMP-reported address can never drift from the address a
  scanner actually connected to.

---

## Layer 4 — MAC address (`mac_spoof.py`)

L2 recon (an ARP scan from the same segment) would otherwise reveal the real
hardware vendor — a Raspberry Pi Foundation OUI — regardless of how convincing
everything above it is. `mac_spoof.py` sets a real, currently-registered
Siemens AG OUI (`28:63:36`, `AC:64:17`, or `88:3F:99` — registered to
Siemens' Amberg facility, the actual SIMATIC S7 manufacturing site). The full
address is generated once and persisted, then reapplied identically every boot
— randomizing each boot would itself be a tell, since real NICs never change
their MAC. A systemd unit orders this before the network comes up and before
the IP writer, so recorded state reflects the spoofed MAC.

---

## Layer 5 — Behavioral realism

Static banners are not enough; the device has to *act* right under repeated
and interactive probing.

- **Process values that drift plausibly.** Repeated `db_read` polls return
  values that change gradually within bounds, not static numbers (a tell on
  the second poll) or teleporting noise (a tell because real process values
  don't jump). The built-in simulator uses a real pump/heat-exchanger state
  machine (idle → start → run → stop, with an alarm path) so its diagnostic
  events follow a coherent industrial sequence. With OpenPLC enabled, the
  values come from actual IEC 61131-3 execution.
- **No-authentication block transfer and PLC STOP.** A real S7-300 has no
  protocol-level auth on program upload/download or STOP (the mechanism
  Stuxnet used). Every such request is accepted and genuinely stored/served
  back. A honeypot that rejected or challenged these would be the anomaly.
- **CPU STOP propagates across the whole stack, with correct per-area
  behavior.** A STOP command freezes the process values, the OB1 scan counter
  stops advancing, the web portal shows a STOP banner, and SZL 0x0424 reports
  STOP — all consistently, because they read one shared state file. Crucially,
  STOP is *not* a uniform freeze: the Q (output) area and output coils
  de-energize to zero, exactly as real S7-300 hardware drives its outputs to
  the substitute state when the CPU stops running them, while DB, M, and I
  areas hold their last value (DBs stay readable in STOP; non-retentive markers
  are only cleared by a subsequent restart). Freezing outputs at their last
  RUNNING value would show a pump reading ON while the CPU reports STOP — a
  physical impossibility an attentive attacker would catch. A device claiming
  RUN on one surface and STOP on another, or showing energized outputs under a
  stopped CPU, is an easy catch; neither happens here.
- **Diagnostic buffer with real event history.** The buffer records genuine
  operational events — mode transitions, pump cycles, alarms — with correct
  S7-300 record layout (event ID, priority, timestamp as 8-byte BCD at the
  right offset). Entries roll at 100 (FIFO) as real hardware does, and the
  S7comm response is capped to fit the negotiated PDU (a real S7-315 returns
  what fits and pages the rest).

---

## Layer 6 — Cross-protocol consistency (web portal)

The web portal (`web_portal.py`, plain stdlib `http.server`, no third-party
dependency) is a fourth fingerprint surface, deliberately sourcing the same
identity the other three use.

- **One device story.** Order code, firmware, serial, IP, MAC on the web page
  match the S7comm SZL data and the SNMP `sysDescr`.
- **Tuned for S7-300 fidelity.** `require_login` defaults to `false` (a
  read-only diagnostics page, no form) because plain S7-300 PN CPUs likely
  don't run a login-gated web server the way S7-1200/1500 do. The login form
  remains an opt-in for its credential-capture value.
- **`Server:` header** set to a plausible embedded value rather than Python's
  default `BaseHTTP/x.x Python/x.x.x`, which would be an immediate tell. (An
  early bug produced a literal *empty* header — worse than a normal one — when
  the naive suppression approach was used; fixed by overriding the response
  writer directly.)
- **The diagnostic buffer shown on the portal matches the one served over
  S7comm** — same source, with the portal able to show all 100 entries while
  S7comm is PDU-limited, exactly as a real device with the web-server option
  behaves.

---

## Layer 7 — Keeping the machinery invisible

Two internal concerns that, leaked, would give the whole thing away:

- **The diagnostic buffer never names the machinery.** Events written to the
  buffer — which is attacker-readable via both SZL 0x00A0 and the web portal —
  are filtered against a forbidden-term list (`honeypot`, `snap7`, `python`,
  `simulator`, `openplc`, `modbus`, `database`, `debug`, ...). An early build
  wrote "Honeypot software updated — diagnostic database ready" into it; that
  single line announced everything. The filter rejects any such entry and logs
  it to the operator journal instead.
- **S7 read events are analyst-only.** The honeypot records which client read
  which data block, for your analysis — but a real S7-300 diagnostic buffer
  does not log routine reads, and showing an attacker "[your.ip] read DB200"
  would tell them they're being watched. Those events stay in the database for
  querying and never appear on either attacker-facing surface.
- **OpenPLC is bound to loopback.** When enabled, OpenPLC runs in Docker with
  its Modbus (502) and IDE (8080) ports published only to `127.0.0.1`, backed
  by a `DOCKER-USER` firewall rule. The external scan sees only 102 and 80 —
  no Modbus, which a real S7-300 (with no CP module) would not have anyway. A
  data-acquisition watchdog reports a plant-agnostic "Process data acquisition
  fault" if the bridge stops, so an outage looks like a device fault rather
  than exposing that a bridge exists.

---

## What is deliberately NOT hidden

Stated plainly so the boundaries are clear:

- **TCP options ordering in the SYN-ACK** — see Layer 2. The remaining passive
  `p0f`/`nmap -O` signal, scoped as future raw-socket work.
- **TLS/JA3S** — nothing in the stack speaks TLS, so there is nothing to
  fingerprint yet; relevant only if an HTTPS portal or OPC UA endpoint is
  added.
- **Real MC7 ladder bytecode** — read-back blocks have realistic headers but
  are not decompilable working logic. A sophisticated attacker who disassembles
  one would notice.
- **Response timing** — the pure-Python stack responds faster and more
  consistently than a real PLC's scan-cycle-bound timing. Rarely fingerprinted,
  not addressed.

None of these are oversights; each is a bounded, named trade-off.
