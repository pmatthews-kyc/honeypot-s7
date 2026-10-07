#!/usr/bin/env python3
"""
generate_services.py
---------------------
Reads config.yaml and writes all seven systemd unit files into
systemd/ with the correct NIC, storage path, OUI, and port values
substituted in.

Usage:
    python3 generate_services.py [--config config.yaml] [--install-dir /opt/s7honeypot]

Run this whenever you change any of these config.yaml fields:
    x-interface      (NIC name — eth0, ens33, enp3s0 ...)
    x-data-dir       (capture storage mount point)
    x-require-mount  (true = services refuse to start if data-dir not mounted)
    x-siemens-oui    (first three octets of spoofed Siemens MAC)
    x-port-snmp      (SNMP listen port, normally 161)
    x-port-web       (web portal port, normally 80)

The generated files are written to systemd/ and must then be installed
with the usual:
    sudo cp systemd/*.service /etc/systemd/system/
    sudo systemctl daemon-reload

fingerprint_harden.sh is also updated in-place with the correct
interface and port values.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml


# ── templates ─────────────────────────────────────────────────────────────────
# Each template uses {var} placeholders filled from config.yaml.
# {REQUIRES_MOUNT} is replaced with a RequiresMountsFor= line or left empty.

_TEMPLATES: dict[str, str] = {

"s7honeypot-mac-spoof.service": """\
[Unit]
Description=S7 Honeypot - spoof NIC MAC to a Siemens OUI
# Must run BEFORE the network comes up so the spoofed MAC is what the
# DHCP client uses on the wire.  Adjust 'Before=' if your network
# manager orders itself differently (check: systemctl status | grep -i network).
Before=network-pre.target
Before=s7honeypot-ip-writer.service
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart={PYTHON} {SRC_DIR}/mac_spoof.py {IFACE} {OUI}
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
""",

"s7honeypot-ip-writer.service": """\
[Unit]
Description=S7 Honeypot - write boot network state (IP/MAC/gateway)
After=s7honeypot-mac-spoof.service network-online.target
Requires=s7honeypot-mac-spoof.service
Wants=network-online.target
Before=s7honeypot-snmp.service

[Service]
Type=oneshot
# Settle {BOOT_SETTLE}s for the post-MAC-spoof link flap, then poll up to
# {BOOT_IP_WAIT}s for an IPv4 address (x-boot-settle-seconds /
# x-boot-ip-wait-seconds in config.yaml). If it still gives up, retry rather
# than staying failed for the rest of the boot -- network-online.target is
# unreliable on boxes without a wait-online unit.
ExecStart={PYTHON} {SRC_DIR}/boot_ip_writer.py {IFACE} --settle {BOOT_SETTLE} --wait {BOOT_IP_WAIT}
Restart=on-failure
RestartSec=10
TimeoutStartSec={IP_WRITER_TIMEOUT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""",

"s7honeypot-backend.service": """\
[Unit]
Description=S7 Honeypot - snap7 backend (loopback only, port {BACKEND_PORT})
After=s7honeypot-ip-writer.service network-online.target
Wants=s7honeypot-ip-writer.service network-online.target

[Service]
Type=simple
WorkingDirectory={INSTALL_DIR}
ExecStart={PYTHON} {SRC_DIR}/backend_server.py config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
""",

"s7honeypot-proxy.service": """\
[Unit]
Description=S7 Honeypot - public precheck proxy + session capture (port {S7_PORT})
After=s7honeypot-backend.service network-online.target
Requires=s7honeypot-backend.service
Wants=network-online.target
{REQUIRES_MOUNT}
[Service]
Type=simple
WorkingDirectory={INSTALL_DIR}
ExecStart={PYTHON} {SRC_DIR}/honeypot.py config.yaml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
""",

"s7honeypot-snmp.service": """\
[Unit]
Description=S7 Honeypot - SNMP agent (port {SNMP_PORT})
After=s7honeypot-ip-writer.service network-online.target
# Wants, not Requires: these services start fine without
# network_state.json (they re-read it on every request), so a slow DHCP
# lease should delay the recorded IP, not take the whole surface down.
Wants=s7honeypot-ip-writer.service
Wants=network-online.target
{REQUIRES_MOUNT}
[Service]
Type=simple
WorkingDirectory={INSTALL_DIR}
ExecStart={PYTHON} {SRC_DIR}/snmp_agent.py config.yaml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
""",

"s7honeypot-web.service": """\
[Unit]
Description=S7 Honeypot - Siemens web diagnostic portal (port {WEB_PORT})
After=s7honeypot-ip-writer.service network-online.target
# Wants, not Requires: these services start fine without
# network_state.json (they re-read it on every request), so a slow DHCP
# lease should delay the recorded IP, not take the whole surface down.
Wants=s7honeypot-ip-writer.service
Wants=network-online.target
{REQUIRES_MOUNT}
[Service]
Type=simple
WorkingDirectory={INSTALL_DIR}
ExecStart={PYTHON} {SRC_DIR}/web_portal.py config.yaml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
""",

"s7honeypot-synack-spoof.service": """\
[Unit]
Description=S7 Honeypot - SYN-ACK fingerprint spoofer (NFQUEUE {SYNACK_QUEUE})
# s7honeypot-harden (Before= this unit) adds the NFQUEUE rule first.
After=s7honeypot-ip-writer.service network-online.target
Wants=s7honeypot-ip-writer.service network-online.target

[Service]
Type=simple
WorkingDirectory={INSTALL_DIR}
ExecStart={PYTHON} {SRC_DIR}/syn_ack_spoofer.py config.yaml
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
""",

"s7honeypot-harden.service": """\
[Unit]
Description=S7 Honeypot - apply network/TCP fingerprint hardening at boot
# Applies the TTL rewrite, sysctl tuning, SYN-ACK NFQUEUE rule, and the
# loopback-only REJECT for the backend port. Without this, a reboot leaves
# the honeypot running but UNHARDENED and silently more detectable until
# someone re-runs fingerprint_harden.sh by hand. Ordered before the proxy
# and the SYN-ACK spoofer so their required iptables rules exist first.
After=s7honeypot-ip-writer.service network-online.target
Wants=s7honeypot-ip-writer.service network-online.target
Before=s7honeypot-proxy.service s7honeypot-synack-spoof.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash {DEPLOY_DIR}/fingerprint_harden.sh apply
ExecStop=/bin/bash {DEPLOY_DIR}/fingerprint_harden.sh revert

[Install]
WantedBy=multi-user.target
""",

}  # end _TEMPLATES


# ── fingerprint_harden.sh config block ────────────────────────────────────────

_HARDEN_CONFIG_BLOCK = """\
# ---- Config: values read from config.yaml by generate_services.py ---------
S7_PORT={S7_PORT}
BACKEND_PORT={BACKEND_PORT}
TARGET_TTL={TARGET_TTL}   # IP TTL the honeypot presents. Real S7-300 = 30.
                        # (Linux default is 64, so leaving this at 64 would
                        # present a Linux TTL — a fingerprint.) Set via
                        # x-target-ttl in config.yaml.
IFACE="{IFACE}"        # NIC serving the honeypot  (x-interface in config.yaml)

MANGLE_COMMENT="s7honeypot-fingerprint"
FILTER_COMMENT="s7honeypot-backend-isolation"
SYNACK_COMMENT="s7honeypot-synack-spoof"
SYNACK_QUEUE={SYNACK_QUEUE}
"""


def _patch_harden_script(script_path: Path, subs: dict) -> None:
    """Replace the config block in fingerprint_harden.sh with generated values."""
    if not script_path.exists():
        print(f"  [skip] {script_path} not found")
        return

    src = script_path.read_text()

    # Find the boundaries of the config block
    start_marker = "# ---- Config:"
    end_marker   = "\napply()"
    start_idx = src.find(start_marker)
    end_idx   = src.find(end_marker)

    if start_idx == -1 or end_idx == -1:
        # Fall back: try to replace the IFACE= line only
        import re
        new_src = re.sub(r'^IFACE=.*$', f'IFACE="{subs["IFACE"]}"',
                         src, flags=re.MULTILINE)
        new_src = re.sub(r'^S7_PORT=\d+', f'S7_PORT={subs["S7_PORT"]}',
                         new_src, flags=re.MULTILINE)
        script_path.write_text(new_src)
        print(f"  [patched] {script_path} (IFACE/S7_PORT line only)")
        return

    new_block = _HARDEN_CONFIG_BLOCK.format(**subs)
    new_src   = src[:start_idx] + new_block + src[end_idx:]
    script_path.write_text(new_src)
    print(f"  [patched] {script_path}")


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config",      default="config.yaml",
                    help="Path to config.yaml (default: config.yaml)")
    ap.add_argument("--install-dir", default="/opt/s7honeypot",
                    help="Where the honeypot code lives on the target Pi "
                         "(default: /opt/s7honeypot)")
    ap.add_argument("--out-dir",     default=None,
                    help="Where to write service files (default: systemd/ "
                         "next to this script)")
    ap.add_argument("--python",      default=None,
                    help="Python interpreter the services run under. "
                         "Default: <install-dir>/venv/bin/python3 (the "
                         "virtualenv install.sh creates). Pass /usr/bin/python3 "
                         "to run against the system Python instead.")
    args = ap.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"ERROR: {config_path} not found", file=sys.stderr)
        sys.exit(1)

    cfg = yaml.safe_load(config_path.read_text())

    # Extract values — support both x-* anchor style and flat style
    iface        = cfg.get("x-interface",    cfg.get("interface",     "ens33"))
    data_dir     = cfg.get("x-data-dir",    cfg.get("data_dir",       "/mnt/s7honeypot-data"))
    require_mount= cfg.get("x-require-mount",cfg.get("require_mount",  True))
    oui          = cfg.get("x-siemens-oui", cfg.get("siemens_oui",    "28:63:36"))
    target_ttl   = cfg.get("x-target-ttl",  cfg.get("target_ttl",       30))
    boot_settle  = int(cfg.get("x-boot-settle-seconds",  cfg.get("boot_settle_seconds",   5)))
    boot_ip_wait = int(cfg.get("x-boot-ip-wait-seconds", cfg.get("boot_ip_wait_seconds", 90)))
    s7_port      = cfg.get("x-port-s7",     cfg.get("s7_port",         102))
    snmp_port    = cfg.get("x-port-snmp",   cfg.get("snmp_port",       161))
    web_port     = cfg.get("x-port-web",    cfg.get("web_port",         80))
    backend_port = 1102
    synack_queue = 42

    # Build RequiresMountsFor line (conditional)
    if require_mount:
        requires_mount_line = f"RequiresMountsFor={data_dir}\n"
    else:
        requires_mount_line = (
            f"# RequiresMountsFor={data_dir} -- disabled (x-require-mount: false)\n"
        )

    # The services run under the virtualenv interpreter by default, and the
    # honeypot modules live in <install-dir>/src. Both are overridable.
    python_bin = args.python or f"{args.install_dir}/venv/bin/python3"
    src_dir    = f"{args.install_dir}/src"
    deploy_dir = f"{args.install_dir}/deploy"

    subs = {
        "INSTALL_DIR":   args.install_dir,
        "PYTHON":        python_bin,
        "SRC_DIR":       src_dir,
        "DEPLOY_DIR":    deploy_dir,
        "IFACE":         iface,
        "OUI":           oui,
        "DATA_DIR":      data_dir,
        "REQUIRES_MOUNT":requires_mount_line,
        "S7_PORT":       s7_port,
        "SNMP_PORT":     snmp_port,
        "WEB_PORT":      web_port,
        "BACKEND_PORT":  backend_port,
        "SYNACK_QUEUE":  synack_queue,
        "TARGET_TTL":    target_ttl,
        "BOOT_SETTLE":   boot_settle,
        "BOOT_IP_WAIT":  boot_ip_wait,
        # settle + wait + margin, so systemd doesn't kill a still-polling run
        "IP_WRITER_TIMEOUT": boot_settle + boot_ip_wait + 30,
    }

    # Determine output directory
    script_dir = Path(__file__).parent
    out_dir = Path(args.out_dir) if args.out_dir else script_dir / "systemd"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating service files → {out_dir}/")
    print(f"  Interface:    {iface}")
    print(f"  Siemens OUI:  {oui}")
    print(f"  Data dir:     {data_dir}  (require_mount={require_mount})")
    print(f"  S7 port:      {s7_port}   SNMP: {snmp_port}   Web: {web_port}")
    print(f"  Install dir:  {args.install_dir}")
    print()

    for filename, template in _TEMPLATES.items():
        content = template.format(**subs)
        path    = out_dir / filename
        path.write_text(content)
        print(f"  [write] {path}")

    # Patch fingerprint_harden.sh in-place
    print()
    harden = script_dir / "fingerprint_harden.sh"
    _patch_harden_script(harden, subs)

    print()
    print("To activate the regenerated units:")
    print(f"  sudo cp {out_dir}/*.service /etc/systemd/system/")
    print( "  sudo systemctl daemon-reload")
    print( "  (install.sh does this for you; see INSTALL.md → The fast path)")


if __name__ == "__main__":
    main()
