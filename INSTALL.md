# Deployment Guide

Deploying honeypot-s7 on a Debian-based Raspberry Pi (or similar SBC). Assumes
Raspberry Pi OS or plain Debian, a dedicated NIC, and — recommended — a
removable drive for capture storage.

> **Before you start:** read the responsible-use section of the
> [README](README.md). This deceives connecting systems into believing they
> are a real PLC and accepts unauthenticated STOP/block-transfer commands.
> Deploy only where you are authorized to, and never where it could be
> mistaken for a real control system.

---

## The fast path

Do these steps in this order. Each one depends on the step before it.

### Step 1 — Configure *before* installing

```bash
git clone <your-repo-url> honeypot-s7
cd honeypot-s7
cp config.yaml.example config.yaml
nano config.yaml
```

At minimum, set:

| Key | What to set |
|---|---|
| `x-interface` | The NIC that faces the network, e.g. `eth0`. Check with `ip -br link`. The example default (`ens33`) is almost certainly wrong for a Pi. |
| `x-data-dir` | Where pcaps and `commands.jsonl` go — your removable drive mount point. |
| `identity.serial_number` | A **unique** serial. Never ship the placeholder. |

> **Why before installing:** `install.sh` generates the systemd units and
> writes the interface name into `fingerprint_harden.sh` from this file. If you
> install first and edit afterwards, the TTL and Docker firewall rules are
> attached to the wrong interface. They will look applied but do nothing.
> If you've already done it in the wrong order, see
> [Changed config after installing](#changed-config-after-installing) below.

### Step 2 — Install

```bash
sudo bash deploy/install.sh
```

This checks for Python 3.9+, installs dependencies into a virtualenv, deploys to
`/opt/s7honeypot`, generates the units from your config, and **enables** all
eight. It does **not start** them.

### Step 3 — (Optional) OpenPLC

Skip this if you're using the built-in simulator.

```bash
sudo bash /opt/s7honeypot/deploy/install_openplc.sh
```

Do this before the first start: it installs Docker, and the hardening step
only adds the Docker firewall rules (ports 502/8080) if Docker is already
present. It also adds a ninth unit, `s7honeypot-openplc`.

### Step 4 — Start everything

**Option A — reboot (recommended).**

```bash
sudo reboot
```

The MAC spoof is designed to run at boot, before the network comes up. A reboot
brings everything up in the right order with no SSH disruption. Reconnect using
the **new** IP if your DHCP server hands one out for the spoofed MAC (check your
router or the Pi's console).

**Option B — start now without rebooting.** Run these lines in order. Don't
just start the proxy: that only pulls in the backend, and the MAC spoof,
IP writer, hardening, SNMP, web portal and SYN-ACK spoofer stay stopped.

```bash
# 1. MAC spoof. The link resets and DHCP may hand out a NEW IP —
#    over SSH your session may drop. Reconnect on the new address.
sudo systemctl start s7honeypot-mac-spoof

# 2. Record the current IP/MAC (SNMP + web read this). Run AFTER the IP settles.
sudo systemctl start s7honeypot-ip-writer

# 3. Firewall/TTL/sysctl hardening — must come before the proxy and spoofer.
sudo systemctl start s7honeypot-harden

# 4. OpenPLC container — only if you did Step 3.
sudo systemctl start s7honeypot-openplc

# 5. snap7 backend, then the public proxy and SYN-ACK spoofer.
sudo systemctl start s7honeypot-backend
sudo systemctl start s7honeypot-proxy s7honeypot-synack-spoof

# 6. SNMP and the web portal.
sudo systemctl start s7honeypot-snmp s7honeypot-web
```

The boot dependency order the units enforce is:

```
mac-spoof → (network up) → ip-writer ─┬─→ snmp
                                      └─→ web
            (network up) → harden ────┬─→ proxy (requires backend)
                                      └─→ synack-spoof
            docker → openplc ────────────→ backend → proxy
```

### Step 5 — Confirm it's working

Run each check on the Pi unless it says otherwise. Every check lists the
expected result; anything different has a fix in
[If a check fails](#if-a-check-fails).

**5a. Services**

```bash
systemctl list-units 's7honeypot-*' --all --no-pager
```

| Unit | Expected state | Kind |
|---|---|---|
| `s7honeypot-mac-spoof` | `active (exited)` | one-shot at boot |
| `s7honeypot-ip-writer` | `active (exited)` | one-shot at boot |
| `s7honeypot-harden` | `active (exited)` | one-shot at boot |
| `s7honeypot-openplc` | `active (exited)` | one-shot (OpenPLC only) |
| `s7honeypot-backend` | `active (running)` | daemon |
| `s7honeypot-proxy` | `active (running)` | daemon |
| `s7honeypot-synack-spoof` | `active (running)` | daemon |
| `s7honeypot-snmp` | `active (running)` | daemon |
| `s7honeypot-web` | `active (running)` | daemon |

For the one-shots, `active (exited)` is correct — they did their job and
finished. `failed` or `inactive` is a problem. To list just the failures:

```bash
systemctl --failed 's7honeypot-*' --no-pager
```

**5b. Listening ports**

```bash
sudo ss -tulnp | grep -E ':(102|80|161|1102|502|8080)\b'
```

| Port | Expected bind | Owner |
|---|---|---|
| `102/tcp` | `0.0.0.0:102` | proxy (public S7comm) |
| `80/tcp` | `0.0.0.0:80` | web portal |
| `161/udp` | `0.0.0.0:161` | SNMP agent |
| `1102/tcp` | `0.0.0.0:1102` | snap7 backend — **this is expected**; snap7 can't bind loopback-only, so the firewall REJECT rule in 5c is what hides it |
| `502/tcp`, `8080/tcp` | `127.0.0.1` only | OpenPLC (Docker) — only if installed |

Nothing should listen on `:::` (IPv6).

**5c. Firewall rules**

```bash
sudo iptables -t mangle -S POSTROUTING | grep s7honeypot
sudo iptables -S INPUT  | grep s7honeypot
sudo iptables -S OUTPUT | grep s7honeypot
sudo iptables -S DOCKER-USER 2>/dev/null | grep s7honeypot   # OpenPLC only
sudo ip6tables -S | head -3
```

You should see each of these **exactly once**, with your interface (shown here
as `eth0`) in place of the placeholder:

| Table / chain | Rule (key parts) | Purpose |
|---|---|---|
| mangle `POSTROUTING` | `-o eth0 -p tcp … -j TTL --ttl-set 30` | TCP leaves with S7-300 TTL |
| mangle `POSTROUTING` | `-o eth0 -p icmp … -j TTL --ttl-set 30` | `ping` shows TTL 30, not Linux's 64 |
| filter `INPUT` | `! -i lo -p tcp --dport 1102 … -j REJECT --reject-with tcp-reset` | hides backend (nmap says *closed*) |
| filter `OUTPUT` | `--sport 102 --tcp-flags SYN,ACK SYN,ACK … -j NFQUEUE --queue-num 42 --queue-bypass` | SYN-ACK window/options rewrite |
| `DOCKER-USER` | `-i eth0 … --dport 502 -j REJECT` | hides OpenPLC Modbus |
| `DOCKER-USER` | `-i eth0 … --dport 8080 -j REJECT` | hides OpenPLC web IDE |
| `DOCKER-USER` | `-i docker0 -o eth0 -j DROP` | container can't reach the plant network |
| ip6tables | `-P INPUT DROP`, `-P FORWARD DROP`, `-P OUTPUT DROP` | IPv6 off |

Then check the sysctls and IPv6 in one go:

```bash
sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh status
ip -6 addr show            # should print nothing
```

Expected: `tcp_timestamps = 0`, `tcp_sack = 0`, `tcp_window_scaling = 0`,
`disable_ipv6 = 1`.

**5d. Recorded network state matches reality**

```bash
cat /var/lib/s7honeypot/network_state.json
ip -br addr show eth0
ip -br link show eth0
```

The `ip_address` and `mac_address` in the JSON must match the live interface,
and the MAC should start with the Siemens OUI from your config. If they don't
match, SNMP and the web portal will report the wrong address — a giveaway.

**5e. From another machine on the network**

```bash
nmap -p 102,80,1102,502,8080 <honeypot-ip>
sudo nmap -sU -p 161 <honeypot-ip>
nmap --script s7-info -p 102 <honeypot-ip>
ping -c 3 <honeypot-ip>
python3 tools/s7_repl.py <honeypot-ip> --rack 0 --slot 2
```

| Check | Expected |
|---|---|
| `102`, `80` | `open` |
| `1102`, `502`, `8080` | `closed` (not `filtered` — *filtered* means a DROP rule, which is a tell) |
| `161/udp` | `open` or `open\|filtered` |
| `s7-info` | your configured order code, firmware and serial — not library defaults |
| `ping` | `ttl=30` on the same subnet (one lower per router hop) |
| `s7_repl.py` | `Negotiated PDU length: 240` |

### If a check fails

| Symptom | Likely cause | Fix |
|---|---|---|
| A daemon is `failed` | Crash at start | `sudo journalctl -u s7honeypot-<name> -n 50 --no-pager` |
| `proxy` failed, `backend` failed | Proxy requires backend | Fix the backend first (usually its journal shows a Python import error — see the venv rule in [TROUBLESHOOTING](docs/TROUBLESHOOTING.md#0-the-venv-rule--read-this-first)) |
| Only `proxy` and `backend` running; others `inactive` | Started with `systemctl start s7honeypot-proxy` only | Run Step 4 Option B in full, or reboot |
| Rules show `ens33` (or another wrong NIC), or no TTL rules | Edited config after installing | See [Changed config after installing](#changed-config-after-installing) |
| A rule appears **twice or more** | `fingerprint_harden.sh apply` run on top of rules that were already there | Re-apply cleanly (see below the table) |
| `DOCKER-USER` rules missing after a reboot, others present | Hardening ran before Docker created the chain | Re-apply cleanly (see below the table) |
| `1102`, `502` or `8080` show `filtered` from nmap | An old DROP rule is present | Re-apply cleanly (see below the table) |
| `1102` shows `open` from nmap | Hardening not applied at all | `sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh apply`, then re-check 5c |
| JSON IP/MAC doesn't match `ip addr` | IP changed after the MAC spoof | `sudo systemctl restart s7honeypot-ip-writer` |
| `ping` shows `ttl=64` | ICMP TTL rule missing or on wrong NIC | Check 5c; if the NIC is wrong, see [Changed config after installing](#changed-config-after-installing) |
| `ip -6 addr` shows addresses | Hardening not applied, or reverted | Check 5c; if rules are missing, `fingerprint_harden.sh apply` |
| `s7-info` shows library default identity | Backend not reading your config | `sudo journalctl -u s7honeypot-backend \| grep "Identity patch"` |

**Re-applying hardening.** Check first, then pick the matching command:

```bash
sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh status
```

- **No rules at all** → `sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh apply`
- **Some rules missing, or any rule duplicated** → remove everything, then apply once:
  ```bash
  sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh revert
  sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh apply
  ```

Don't run `apply` on top of rules that are already there. The script appends,
so a second run leaves duplicates.

Don't restart `s7honeypot-harden` or `s7honeypot-mac-spoof` while
troubleshooting. Restarting harden briefly leaves the honeypot unhardened, and
restarting mac-spoof can change the IP. See [TROUBLESHOOTING §2](docs/TROUBLESHOOTING.md#2-restarting-services-safely).

### Changed config after installing

If you edit `x-interface`, the ports, or the install/data paths after
`install.sh` has run, remove the old rules **first**, then regenerate and reboot:

```bash
# 1. Remove the rules while the script still knows the OLD interface.
#    (Stopping the harden unit runs `fingerprint_harden.sh revert`.)
sudo systemctl stop s7honeypot-harden

# 2. Regenerate the units and re-patch fingerprint_harden.sh from config.
sudo /opt/s7honeypot/venv/bin/python /opt/s7honeypot/deploy/generate_services.py \
    --config /opt/s7honeypot/config.yaml --install-dir /opt/s7honeypot
sudo cp /opt/s7honeypot/deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# 3. Bring everything up on the new settings.
sudo reboot
```

The order matters. `revert` finds rules by interface name. If you regenerate
first, the script looks for rules on the new interface, can't find the old
ones, and leaves them in place. After the reboot, re-run the Step 5 checks.

For identity-only changes (serial, order code, firmware), skip the regeneration:
`sudo systemctl restart s7honeypot-backend s7honeypot-proxy s7honeypot-web s7honeypot-snmp`.

The rest of this document is the manual, step-by-step version — useful for
understanding what `install.sh` does, or for a non-standard deployment.

---

## 1. Prepare the OS

honeypot-s7 needs **Python 3.9 or newer** (it uses PEP 604 `X | None` unions
and PEP 585 `list[...]` generics). Raspberry Pi OS Bookworm ships 3.11 and
Bullseye ships 3.9 — both fine. `install.sh` checks the version and stops with
a clear message if it's too old, rather than failing cryptically at runtime.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv python-is-python3 \
    python3-yaml python3-netfilterqueue build-essential \
    tshark macchanger iptables iproute2 net-tools curl git
```

`python-is-python3` provides the `python` command Debian no longer ships by
default (scripts and services call `python3`/the venv explicitly, so this is
for interactive use). `macchanger` is used by the MAC-spoof service;
`build-essential` covers any pip source build. `tshark` needs permission to
capture — allow non-root capture when prompted, or run the capture service as
root.

## 2. Get the files onto the Pi

Clone the repo (or copy it across). `install.sh` deploys the `src/`, `deploy/`,
`tools/`, and `openplc_program/` directories to `/opt/s7honeypot`.

## 3. Python dependencies (virtualenv)

`install.sh` creates an isolated virtualenv at `/opt/s7honeypot/venv` and
installs the pip packages there — keeping them out of the system Python, which
modern Debian (PEP 668) protects. The venv is created with
`--system-site-packages` so it can use the apt-built `netfilterqueue` without
recompiling.

To do it manually:

```bash
cd /opt/s7honeypot
python3 -m venv --system-site-packages venv
venv/bin/pip install -r requirements.txt
```

The systemd units run under `venv/bin/python3`, not the system Python. Do
**not** use `pip install --break-system-packages` into the system Python — the
venv is the supported path.

## 4. Removable capture drive (recommended)

Attacker pcaps grow. Point capture at a mounted drive rather than the SD card:

```bash
sudo mkdir -p /mnt/s7honeypot-data
sudo mount /dev/sda1 /mnt/s7honeypot-data
# persist across reboots — nofail so the box still boots if the drive is absent:
echo 'UUID=xxxx-xxxx /mnt/s7honeypot-data ext4 defaults,nofail 0 2' | sudo tee -a /etc/fstab
```

Set `x-data-dir` in config to this path. The capture layer refuses to write
unless the path is a currently-mounted filesystem — so an unplugged drive
fails loudly instead of silently filling the SD card.

## 5. Edit `config.yaml`

At minimum, set the quick-setup anchors at the top:

```yaml
x-interface:   "eth0"                    # your NIC — check with: ip a
x-data-dir:    "/mnt/s7honeypot-data"    # capture drive
x-state-dir:   "/var/lib/s7honeypot"     # runtime state (persistent, not /tmp)
x-siemens-oui: "28:63:36"                # MAC prefix
```

And **change the serial number** in the `identity:` block — a shared serial
across deployments becomes a fingerprint. Adjust `plc_name`, `plant_id`, and
other identity fields to suit the device you're impersonating.

## 6. Spoof the MAC to a Siemens OUI

The MAC-spoof service does this at boot, but verify `macchanger` is installed
and the OUI in config is one of the confirmed Siemens Amberg OUIs (`28:63:36`,
`AC:64:17`, `88:3F:99`). L2 recon would otherwise reveal the real SBC vendor.

## 7. Generate initial network state

The IP-writer service records the real interface IP/netmask/MAC and seeds the
fake uptime at boot. It runs automatically via systemd ordering; no manual step
needed unless you're testing components individually.

## 8. Apply network / TCP-stack fingerprint hardening

```bash
sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh apply
```

This sets the TTL rewrite, sysctl tuning, SYN-ACK spoofing queue, and the
loopback-only REJECT rule for the backend port. **This is applied
automatically at every boot** by the `s7honeypot-harden.service` unit that
`install.sh` enables, so a reboot no longer leaves the honeypot unhardened.
The script appends rules, so don't run `apply` while the rules are already in
place — check with `status` first. To re-apply cleanly, run `revert` then
`apply` (see [If a check fails](#if-a-check-fails)). `revert` removes
everything. If you prefer to
manage the rules yourself instead, disable the service
(`systemctl disable s7honeypot-harden`) and persist them with
`netfilter-persistent save` plus a sysctl drop-in.

## 9. Install and order the systemd units

`install.sh` and `generate_services.py` handle this — the units are generated
from `config.yaml` (interface, data dir, install dir) and enabled in the right
boot order:

```
mac-spoof → ip-writer → snmp, web
harden → backend → proxy, synack-spoof
(openplc → backend, when OpenPLC is installed)
```

See [Step 4 of the fast path](#step-4--start-everything) for the full
dependency picture.

If doing it manually:

```bash
cd /opt/s7honeypot && sudo python3 deploy/generate_services.py --install-dir /opt/s7honeypot
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable s7honeypot-{mac-spoof,ip-writer,harden,backend,proxy,snmp,web,synack-spoof}
```

## 10. Start and verify each service

Start the units in dependency order (or reboot), then run the checks — both
are covered in the fast path:

- [Step 4 — Start everything](#step-4--start-everything)
- [Step 5 — Confirm it's working](#step-5--confirm-its-working) (services,
  ports, firewall rules, network state)
- [If a check fails](#if-a-check-fails)

## 11. Test from another machine

```bash
nmap -p 102,80,161 <honeypot-ip>
nmap --script s7-info -p 102 <honeypot-ip>
snmpwalk -v2c -c public <honeypot-ip>
# and the client REPL in tools/:
python3 tools/s7_repl.py --scan <honeypot-ip>
```

`s7-info` should report your configured identity (order code, firmware,
serial), not library defaults. Port 1102 should read `closed`, not `filtered`.

---

## Optional: OpenPLC process engine

For process values driven by a real IEC 61131-3 program rather than the
built-in simulator.

**Requires Docker** — but you don't need to install it yourself. The base
`install.sh` intentionally does not install Docker (it's only needed for this
optional path); `install_openplc.sh` installs the full official Docker stack
(`docker-ce`, `containerd.io`, `buildx`, and the `compose` plugin) via
Docker's `get.docker.com` script if it isn't already present. Debian's older
`docker.io` package is *not* used — it lacks the compose plugin and buildx that
the OpenPLC image build needs.

```bash
sudo bash /opt/s7honeypot/deploy/install_openplc.sh
```

This installs Docker (if needed), builds the OpenPLC v3 image, uploads the
process program from `openplc_program/process_sim.st`, binds OpenPLC's ports to
loopback only, sets `x-openplc`/`x-modbus-bridge` true in config, and restarts
the backend.

**The program must be started in OpenPLC.** After install, confirm it's
running:

```bash
sudo python3 /opt/s7honeypot/tools/check_openplc.py /opt/s7honeypot/config.yaml
```

This reads the Modbus registers and confirms the scan counter is advancing. If
it reports STOPPED, start the program via the OpenPLC web UI
(`http://127.0.0.1:8080`, login `openplc`/`openplc`) — and enable "start on
boot" in its settings so it survives container restarts.

Verify OpenPLC's ports are **not** externally visible:

```bash
nmap -p 502,8080 <honeypot-ip>    # both should be closed/absent
```

---

## Ongoing operation

- **Capture data** lands in `x-data-dir`: one pcap per session plus
  `commands.jsonl`. Rotate/archive it; attacker traffic can contain sensitive
  material.
- **The diagnostic database** (`honeypot.db`) holds the event history shown on
  the portal and over S7comm. Keep it on a persistent path (`x-state-dir`), not
  `/tmp` — the honeypot warns if it's on `/tmp`, which systemd `PrivateTmp`
  makes per-service and which clears on reboot.
- **Hardening re-applies automatically at boot** via `s7honeypot-harden.service`.
  Check it after a reboot with `sudo bash .../fingerprint_harden.sh status` if
  you want to confirm the rules are in place.
- **Watch the journal** for the resolved paths and any warnings:
  ```bash
  sudo journalctl -u s7honeypot-backend -u s7honeypot-web --since "5 min ago"
  ```
