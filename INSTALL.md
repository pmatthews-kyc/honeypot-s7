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

```bash
git clone <your-repo-url> honeypot-s7
cd honeypot-s7
cp config.yaml.example config.yaml
sudo bash deploy/install.sh
```

`install.sh` installs all dependencies into an isolated virtualenv (checking
Python is 3.9+ first, and installing `python-is-python3`, `macchanger`,
`build-essential` and the rest), deploys to `/opt/s7honeypot`, generates and
enables the systemd units, and prints the next steps. Then edit config,
harden, and start:

```bash
nano /opt/s7honeypot/config.yaml
sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh apply
sudo systemctl start s7honeypot-proxy
```

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
You can still run it by hand to apply changes immediately, and
`fingerprint_harden.sh revert` cleanly removes everything. If you prefer to
manage the rules yourself instead, disable the service
(`systemctl disable s7honeypot-harden`) and persist them with
`netfilter-persistent save` plus a sysctl drop-in.

## 9. Install and order the systemd units

`install.sh` and `generate_services.py` handle this — the units are generated
from `config.yaml` (interface, data dir, install dir) and enabled in the right
boot order:

```
mac-spoof → ip-writer → backend → proxy → snmp → web → synack-spoof
```

If doing it manually:

```bash
cd /opt/s7honeypot && sudo python3 deploy/generate_services.py --install-dir /opt/s7honeypot
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable s7honeypot-{mac-spoof,ip-writer,backend,proxy,snmp,web,synack-spoof}
```

## 10. Verify each service

```bash
sudo systemctl start s7honeypot-proxy   # pulls in the dependency chain
for s in mac-spoof ip-writer backend proxy snmp web; do
    systemctl is-active s7honeypot-$s
done
sudo ss -tlnp | grep -E ':(102|80|1102)'   # 102/80 external, 1102 loopback only
```

`1102` must show `127.0.0.1:1102`, not `0.0.0.0`. If it binds `0.0.0.0`, the
`fingerprint_harden.sh` REJECT rule is the backstop — confirm it's applied.

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
