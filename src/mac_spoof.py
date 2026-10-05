"""
mac_spoof.py
-------------
Changes the honeypot's real NIC MAC address (a Raspberry Pi Foundation
or other SBC-vendor OUI by default) to a real, registered Siemens AG
OUI, using `macchanger`. This closes a gap that was otherwise sitting
completely unaddressed: boot_ip_writer.py records whatever MAC is
actually on the interface into network_state.json, and that value gets
served back via SNMP's ifPhysAddress and shown on the web portal --
without this, anyone doing L2-level recon (ARP scan, same-segment
lookup) would immediately see "Raspberry Pi Foundation" as the vendor,
regardless of how convincing the S7comm/SNMP/HTTP fingerprint is.

MUST run BEFORE boot_ip_writer.py at boot (see systemd/ ordering) so the
network state it records reflects the spoofed MAC, not the original one.

OUI SOURCE: the default OUIs below (28:63:36, AC:64:17, 88:3F:99) are
real, currently-registered Siemens AG prefixes, confirmed via a MAC
vendor lookup database at build time -- specifically registered to
Siemens' Amberg, Germany facility, which is the actual manufacturing
site for SIMATIC S7 controllers. Not fabricated, but OUI registrations
can change over time -- worth re-verifying against a current IEEE OUI
registry lookup before a long-lived deployment.

PERSISTENCE: the chosen full MAC (OUI + a random locally-generated
suffix) is generated ONCE and saved to a state file, then reapplied
identically on every subsequent boot. Randomizing the suffix fresh on
every boot would itself be a significant tell -- real hardware NICs
have a MAC burned in at manufacture time, and it never changes.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
from pathlib import Path

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import Paths as _Paths
STATE_PATH = _Paths.load().mac_spoof_state

# Confirmed, currently-registered Siemens AG OUIs (see module docstring).
# 28:63:36, AC:64:17, and 88:3F:99 are all registered to Siemens' Amberg
# plant -- the actual SIMATIC S7 manufacturing site.
SIEMENS_OUIS = ["28:63:36", "AC:64:17", "88:3F:99", "00:0E:8C"]
DEFAULT_OUI = SIEMENS_OUIS[0]


class MacSpoofError(Exception):
    pass


def _generate_suffix() -> str:
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))


def load_or_generate_mac(oui: str, state_path: Path = STATE_PATH) -> str:
    """
    Return the persisted spoofed MAC if one already exists for this OUI,
    otherwise generate a new one (once) and save it. Re-running this
    with the same OUI on every boot returns the SAME MAC every time --
    that's the point, not a bug.
    """
    if state_path.exists():
        try:
            data = json.loads(state_path.read_text())
            if data.get("oui", "").upper() == oui.upper():
                return data["mac"]
        except (json.JSONDecodeError, OSError):
            pass  # fall through and regenerate

    mac = f"{oui}:{_generate_suffix()}"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"oui": oui, "mac": mac}))
    return mac


def apply_mac(interface: str, mac: str) -> None:
    """
    Bring the interface down, set the MAC via macchanger, bring it back
    up. Requires root and the `macchanger` package installed.
    """
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["macchanger", "-m", mac, interface], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
    except subprocess.CalledProcessError as e:
        raise MacSpoofError(
            f"Failed to apply MAC {mac} to {interface}: {e}. "
            f"Confirm `macchanger` is installed (apt install macchanger) "
            f"and this is running as root."
        ) from e
    except FileNotFoundError as e:
        raise MacSpoofError(
            f"Required command not found ({e}). Install `macchanger` "
            f"(apt install macchanger) and ensure `ip` (iproute2) is "
            f"available -- both should be present on any Debian-based system."
        ) from e


def spoof_interface(interface: str, oui: str = DEFAULT_OUI,
                     state_path: Path = STATE_PATH) -> str:
    mac = load_or_generate_mac(oui, state_path)
    apply_mac(interface, mac)
    return mac


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <interface> [siemens_oui]", file=sys.stderr)
        print(f"  Known Siemens OUIs: {', '.join(SIEMENS_OUIS)}", file=sys.stderr)
        sys.exit(1)

    iface = sys.argv[1]
    oui = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUI

    try:
        applied_mac = spoof_interface(iface, oui)
    except MacSpoofError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Applied MAC {applied_mac} ({oui} = Siemens AG) to {iface}")
