"""
boot_ip_writer.py
------------------
Run once at boot (before the SNMP agent starts) to detect the honeypot's
actual IP/netmask/MAC on the configured interface and write it to a small
JSON state file. snmp_agent.py reads that file at startup instead of
having any address hardcoded.

Why this matters: if the box's IP changes (new DHCP lease, redeployed to a
different network/VLAN) but the SNMP agent's ipAddrTable/ifTable data is
stale, you get a directly observable inconsistency -- the IP a scanner
connected to doesn't match the IP the device claims about itself over
SNMP. That mismatch is a much bigger tell than any single field being
slightly off, because it's trivial to check and immediately suspicious.
snmp_agent.py re-reads this state file on every request (see
SNMPIdentity.build_oid_table), so an IP change takes effect without
restarting the agent -- not just at boot.

No third-party dependencies (no `netifaces`) -- uses the `ip` command via
subprocess, which is present on any Ubuntu/Debian box already, so this
doesn't add another version-uncertain dependency to the stack.
"""

from __future__ import annotations

import json
import random
import re
import subprocess
import sys
import time
from pathlib import Path

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import Paths as _Paths
STATE_PATH = _Paths.load().network_state

ONE_YEAR_SECONDS = 365 * 24 * 3600


def get_interface_info(iface: str) -> dict:
    """Parse `ip addr show <iface>` for IPv4 address, netmask (as CIDR ->
    dotted quad), and MAC address. Raises RuntimeError if the interface
    isn't found or has no IPv4 address yet (e.g. called too early at boot
    before DHCP completes -- see systemd unit ordering in README)."""

    result = subprocess.run(
        ["ip", "-o", "addr", "show", iface],
        capture_output=True, text=True, check=True,
    )
    output = result.stdout

    ipv4_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", output)
    if not ipv4_match:
        raise RuntimeError(f"No IPv4 address found on interface {iface} "
                            f"(is it up / has DHCP completed?)")
    ip_addr, prefix_len = ipv4_match.group(1), int(ipv4_match.group(2))
    netmask = _prefix_to_netmask(prefix_len)

    mac_result = subprocess.run(
        ["ip", "-o", "link", "show", iface],
        capture_output=True, text=True, check=True,
    )
    mac_match = re.search(r"link/ether ([0-9a-fA-F:]{17})", mac_result.stdout)
    mac_addr = mac_match.group(1) if mac_match else "00:00:00:00:00:00"

    return {
        "interface": iface,
        "ip_address": ip_addr,
        "netmask": netmask,
        "prefix_len": prefix_len,
        "mac_address": mac_addr,
    }


def _prefix_to_netmask(prefix_len: int) -> str:
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return ".".join(str((mask >> shift) & 0xFF) for shift in (24, 16, 8, 0))


# How long to wait for the interface to get an IPv4 address before giving
# up. At boot this unit is ordered After=network-online.target, but on a
# box without NetworkManager-wait-online / systemd-networkd-wait-online
# that target is reached immediately -- before DHCP has answered. The MAC
# spoof that runs just before us makes this worse (new MAC = fresh DHCP
# exchange). Seen in the field: ip-writer failed at boot, a manual restart
# 84 s later succeeded. So poll instead of failing on the first look.
DEFAULT_WAIT_SECONDS = 90
POLL_INTERVAL_SECONDS = 2


def wait_for_interface_info(iface: str,
                            timeout: float = DEFAULT_WAIT_SECONDS) -> dict:
    """get_interface_info(), retried until the interface has an IPv4
    address or `timeout` seconds have passed. Re-raises the last error."""
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while True:
        try:
            return get_interface_info(iface)
        except (RuntimeError, subprocess.CalledProcessError) as e:
            last_err = e
            if time.monotonic() >= deadline:
                raise
            print(f"Waiting for IPv4 address on {iface}... ({e})",
                  file=sys.stderr)
            time.sleep(POLL_INTERVAL_SECONDS)


def write_state(iface: str, path: Path = STATE_PATH,
                wait_seconds: float = DEFAULT_WAIT_SECONDS) -> dict:
    info = wait_for_interface_info(iface, wait_seconds)

    # Fake uptime baseline: pick a random point in the last year and treat
    # it as this device's "boot time" for sysUpTime purposes, rather than
    # starting the counter at zero. A freshly-scanned device reporting
    # sysUpTime of a few seconds looks like it rebooted right as someone
    # started looking at it -- a random, older baseline avoids that tell.
    #
    # Stored as an absolute epoch timestamp (not just an offset) so
    # sysUpTime keeps advancing correctly across snmp_agent.py restarts
    # within the same host boot -- it's derived purely from wall-clock
    # time at read time, with no dependency on how long the agent
    # *process* has been running.
    #
    # This regenerates on every real boot of the host (this script is
    # meant to run once per boot via systemd, see systemd/). That's a
    # deliberate choice: it's a fresh fake-uptime "backstory" per
    # deployment/boot cycle, not a persistent identity across reboots --
    # if you redeploy this box or it genuinely reboots, getting a new
    # baseline is fine and arguably more realistic than an unchanging one.
    info["fake_boot_epoch"] = time.time() - random.uniform(0, ONE_YEAR_SECONDS)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(info, indent=2))
    return info


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(
        description="Record the honeypot NIC's IP/netmask/MAC to network_state.json")
    ap.add_argument("interface")
    ap.add_argument("--settle", type=float, default=0.0, metavar="SEC",
                    help="sleep this long first (post-MAC-spoof link flap); "
                         "x-boot-settle-seconds in config.yaml")
    ap.add_argument("--wait", type=float, default=DEFAULT_WAIT_SECONDS, metavar="SEC",
                    help="then poll up to this long for an IPv4 address; "
                         "x-boot-ip-wait-seconds in config.yaml")
    args = ap.parse_args()

    if args.settle > 0:
        print(f"Settling {args.settle:g}s before reading {args.interface}...",
              file=sys.stderr)
        time.sleep(args.settle)

    try:
        info = write_state(args.interface, wait_seconds=args.wait)
    except (subprocess.CalledProcessError, RuntimeError) as e:
        print(f"ERROR: {e} -- gave up after {args.wait:g}s; "
              f"systemd will retry (Restart=on-failure)", file=sys.stderr)
        sys.exit(1)

    print(f"Wrote network state to {STATE_PATH}:")
    print(json.dumps(info, indent=2))
