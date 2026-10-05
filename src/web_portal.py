"""
web_portal.py
--------------
Fake Siemens S7-300-style web diagnostics page, serving on port 80.
Two purposes:

  1. Consistency -- the identity shown here (order code, module name,
     firmware, IP/MAC) is sourced from the same identity.py/config.yaml
     and boot_ip_writer.py state file the S7comm and SNMP fingerprints
     use, so a careful attacker cross-referencing all three protocols
     sees the same device, not three different stories.
  2. Credential capture -- if `web_portal.require_login` is enabled, the
     login form NEVER succeeds (there's nothing behind it to log into),
     but every submitted username/password is logged. That's real
     intelligence value: what credentials an attacker tries against this
     device class, independent of whether they're "correct" for
     anything.

REALISM CAVEAT (see config.yaml comment): real S7-300 PN CPUs' web
diagnostics are generally simpler and more read-only than the fully
configurable web server on S7-1200/1500. Whether a real S7-300 PN
diagnostics page gates anything behind a login form at all isn't
something I have verified certainty on. `require_login: false` in
config.yaml switches this to a read-only page with no form, which is
the more conservative/higher-fidelity choice for this specific device
class if that matters more to you than credential-capture value.

Built on Python's stdlib http.server -- deliberately no third-party HTTP
framework dependency, consistent with avoiding version-uncertain
libraries elsewhere in this project (ber.py, s7_header.py).

NOT a real web server in any functional sense: no real authentication
exists to bypass, no real backend to reach, nothing here can be
"exploited" into doing anything beyond what's explicitly coded -- every
response is static/templated and every input is captured for logging
only.
"""

from __future__ import annotations

import html
import json
import logging
import socket
import socketserver
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

from command_logger import CommandLogger
from identity import S7Identity
from storage import resolve_and_verify, substitute_data_dir, StorageError
import cpu_state

log = logging.getLogger("web_portal")

# Path to the process snapshot written by process_simulator / modbus_bridge.
# Overridden from config in run() so the portal reads the same file the
# writer uses when the data directory is not the /var/lib default.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import sys
from paths import Paths as _Paths
_PROCESS_STATE_PATH = str(_Paths.load().process_state)

NETWORK_STATE_PATH = _Paths.load().network_state  # refined per-config in run()


def _load_network_state() -> dict:
    if not NETWORK_STATE_PATH.exists():
        return {"ip_address": "unknown", "mac_address": "unknown", "interface": "unknown"}
    return json.loads(NETWORK_STATE_PATH.read_text())



# ── page routing constants ────────────────────────────────────────────────────

_PAGES = {
    "0": "Start Page",
    "disabled": "Disabled",
    "1": "Module Identification",
    "2": "CPU Information",
    "3": "Module Status",
    "4": "Ethernet",
    "5": "Connections",
    "6": "Diagnostic Buffer",
    "7": "Performance Data",
    "8": "Scan Cycle",
    "9": "Variable Table",
    "10": "Data Records",
}

# ── shared CSS + chrome ───────────────────────────────────────────────────────

_FAVICON_ICO: bytes = (lambda: (lambda W,H,R,G,B: (
    lambda bmp_hdr, pixel_data, mask_data: (
        lambda bmp_total: (
            b'\x00\x00\x01\x00\x01\x00'          # ICO file header
            + __import__('struct').pack('<BBBBHHII',
                W, H, 0, 0, 1, 32,
                len(bmp_hdr) + len(pixel_data) + len(mask_data), 22)
            + bmp_hdr + pixel_data + mask_data
        )
    )(bmp_hdr + pixel_data + mask_data)
)(
    __import__('struct').pack('<IIIHHIIIIII',
        40, W, H*2, 1, 32, 0, 0, 0, 0, 0, 0),
    bytes([B, G, R, 255]) * (W * H),
    b'\x00' * (H * 4),
))(16, 16, 0, 153, 153))()

_BASE_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Verdana,Arial,sans-serif;font-size:11px;background:#ffffff;color:#000}
#shell{display:flex;flex-direction:column;height:100vh}
#hdr{flex:0 0 auto}
#body{display:flex;flex:1 1 auto;overflow:hidden}
#nav{flex:0 0 148px;overflow-y:auto;border-right:1px solid #999;background:#eee}
#main{flex:1 1 auto;overflow-y:auto;padding:10px 14px}
#hdr{background:#009999;border-bottom:2px solid #006666}
#hdr-inner{display:flex;align-items:center;justify-content:space-between;padding:4px 10px}
.logo-text{color:#fff;font-size:18px;font-weight:bold;letter-spacing:1px;font-family:Arial,sans-serif}
.logo-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#fff;margin-left:3px;vertical-align:middle}
.plc-title{color:#fff;font-size:13px;font-weight:bold;text-align:center;flex:1;padding:0 12px}
.lang-bar{color:#fff;font-size:10px;white-space:nowrap}
.lang-bar a{color:#ccffff;text-decoration:none;margin-left:6px}
.lang-active{color:#fff;font-weight:bold;margin-left:6px}
#hdr-sub{background:#006666;padding:2px 10px;color:#ccffff;font-size:10px;border-bottom:1px solid #004444}
.nav-title{background:#ccc;border-bottom:1px solid #999;padding:5px 8px;font-weight:bold;font-size:11px;color:#333}
.nav-title2{background:#ddd;border-top:1px solid #bbb;border-bottom:1px solid #999;padding:4px 8px;font-weight:bold;font-size:10px;color:#333;margin-top:4px}
.nav-link{display:block;padding:4px 8px 4px 14px;color:#003366;text-decoration:none;font-size:11px;border-bottom:1px solid #ddd}
.nav-link:hover{background:#ddeeff}
.nav-link.active{background:#009999;color:#fff;font-weight:bold}
.section{margin-bottom:14px}
.sec-title{background:#009999;color:#fff;font-weight:bold;padding:4px 8px;font-size:12px;margin-bottom:6px}
table.info{border-collapse:collapse;width:100%;max-width:540px}
table.info td{border:1px solid #aaa;padding:3px 8px;vertical-align:top}
table.info td:first-child{background:#e8e8e8;font-weight:bold;width:190px;white-space:nowrap}
table.info td.val-run{color:#006600;font-weight:bold}
table.info td.val-stop{color:#cc0000;font-weight:bold}
table.info td.val-ok{color:#006600}
table.dbuf{border-collapse:collapse;width:100%}
table.dbuf th{background:#ccc;border:1px solid #aaa;padding:3px 8px;text-align:left;font-size:10px}
table.dbuf td{border:1px solid #ccc;padding:3px 8px;font-size:10px}
.dbuf-time{white-space:nowrap;color:#555}
table.conn{border-collapse:collapse;width:100%}
table.conn th{background:#ccc;border:1px solid #aaa;padding:3px 8px;text-align:left;font-size:10px}
table.conn td{border:1px solid #ccc;padding:3px 8px;font-size:10px;vertical-align:top}
.conn-active{color:#006600;font-weight:bold}
.conn-free{color:#888}
table.rack{border-collapse:collapse}
table.rack td{border:2px solid #999;padding:6px 10px;text-align:center;font-size:10px;min-width:60px}
.slot-cpu{background:#ccddff;font-weight:bold}
.slot-ps{background:#ddddcc}
.slot-empty{background:#f5f5f5;color:#aaa}
.slot-io{background:#ddf0dd}
table.perf{border-collapse:collapse;width:100%;max-width:400px}
table.perf td{border:1px solid #ccc;padding:3px 8px;font-size:11px}
table.perf td:first-child{background:#e8e8e8;font-weight:bold;width:200px}
table.perf td.num{text-align:right;font-family:Courier,monospace}
input[type=text],input[type=password]{border:1px solid #999;padding:2px 4px;font-size:11px;font-family:Verdana,Arial,sans-serif}
.btn-login{background:#009999;color:#fff;border:1px solid #006666;padding:3px 16px;font-size:11px;cursor:pointer}
.err{color:#cc0000;font-weight:bold;padding:4px 0 6px 0}
table.login-tbl td{padding:3px 8px}
p.hint{color:#555;font-size:10px;margin-top:6px;font-style:italic}
"""


def _nav_html(active_page: str, plc_name: str) -> str:
    """
    Left nav bar.  Start Page and Diagnostic Buffer work normally.
    Everything else shows the 'disabled by configuration' notice — consistent
    with a PLC that has web diagnostics restricted to overview + event log only.
    """
    def lk(pid, label):
        # Start Page (0) and Diagnostic Buffer (6) are fully functional.
        # All other pages route to the disabled notice.
        if pid in ("0", "6"):
            target = pid
        else:
            target = "disabled"
        active = (pid == active_page) or (pid != "0" and pid != "6" and active_page == "disabled")
        cls = "nav-link active" if (pid == active_page) else "nav-link"
        return f'<a class="{cls}" href="/Portal0000.htm?{target}">{label}</a>\n'

    return f"""
    <div class="nav-title">Navigation</div>
    {lk("0","Start Page")}
    {lk("1","Module Identification")}
    {lk("2","CPU Information")}
    {lk("3","Module Status")}
    <div class="nav-title2">Communication</div>
    {lk("4","Ethernet")}
    {lk("5","Connections")}
    <div class="nav-title2">Diagnostics</div>
    {lk("6","Diagnostic Buffer")}
    {lk("7","Performance Data")}
    {lk("8","Scan Cycle")}
    <div class="nav-title2">Services</div>
    {lk("9","Variable Table")}
    {lk("10","Data Records")}"""


def _shell(identity: S7Identity, active_page: str, content: str,
           auto_refresh: int = 0) -> str:
    """Full page chrome. auto_refresh > 0 adds a meta-refresh (seconds)."""
    plc = html.escape(identity.plc_name)
    refresh_tag = (f'\n<meta http-equiv="refresh" content="{auto_refresh}">'
                   if auto_refresh else "")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">{refresh_tag}
<title>{plc}</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>{_BASE_CSS}</style>
</head>
<body>
<div id="shell">
<div id="hdr">
  <div id="hdr-inner">
    <div><span class="logo-text">SIEMENS</span>
    <span class="logo-dot"></span><span class="logo-dot"></span><span class="logo-dot"></span></div>
    <div class="plc-title">{plc}</div>
    <div class="lang-bar">
      <a href="?{active_page}&amp;lang=de">Deutsch</a>
      <span class="lang-active">English</span>
      <a href="?{active_page}&amp;lang=fr">Fran&#231;ais</a>
      <a href="?{active_page}&amp;lang=it">Italiano</a>
      <a href="?{active_page}&amp;lang=es">Espa&#241;ol</a>
    </div>
  </div>
  <div id="hdr-sub">SIMATIC S7 &nbsp;&mdash;&nbsp; Web diagnostic interface</div>
</div>
<div id="body">
  <div id="nav">{_nav_html(active_page, plc)}</div>
  <div id="main">{content}</div>
</div>
</div>
</body>
</html>"""


# ── individual page content renderers ────────────────────────────────────────


def _load_process_state(state_path: str | None = None) -> tuple[dict, str]:
    """
    Read the latest process simulator / bridge snapshot.
    Returns (tags_dict, cpu_state_str), or ({}, "RUN") if missing or
    stale (>120s). state_path defaults to the module path set by run().
    """
    import json
    from pathlib import Path
    path = Path(state_path or _PROCESS_STATE_PATH)
    try:
        if not path.exists():
            log.debug("process_state.json not found at %s", path)
            return {}, "RUN"
        data = json.loads(path.read_text())
        age = time.time() - data.get('timestamp', 0)
        if age > 120:
            log.debug("process_state.json stale (%.0fs) at %s", age, path)
            return {}, "RUN"
        return data.get('tags', {}), data.get('cpu_state', 'RUN')
    except Exception as exc:
        log.debug("process_state.json read failed: %s", exc)
        return {}, "RUN"


def _ts(epoch: float) -> str:
    return time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(epoch))


def _build_diag_events(web_cfg: dict, limit: int = 20) -> list:
    """
    Build a realistic timestamped diagnostic buffer.
    Three sources merged newest-first:
    1. Persistent mode-transition events from diag_log.py (STOP/START commands)
    2. Synthetic boot sequence anchored to fake_boot_epoch
    3. User-configured lines from config.yaml
    """
    net        = _load_network_state()
    boot_epoch = net.get("fake_boot_epoch", time.time() - 7200)
    now_epoch  = time.time()
    uptime_s   = now_epoch - boot_epoch

    boot_seq = [
        (0,  "Power up"),
        (1,  "CPU startup – cold restart initiated"),
        (3,  "Memory test complete"),
        (4,  "Loading configuration from memory card"),
        (5,  "Cold restart complete"),
        (6,  "Operating mode: STOP → RUN"),
        (7,  "CPU in RUN mode"),
        (10, "PROFIBUS DP: cyclic data exchange active"),
        (12, "PN-IO: all devices operational"),
        (15, "OB1 scan cycle running"),
    ]

    events: list[tuple[float, str]] = list(
        (boot_epoch + dt, ev) for dt, ev in boot_seq
    )

    t = boot_epoch + 1800
    while t < now_epoch - 60:
        events.append((t, "Scan cycle monitoring: OK"))
        t += 1800

    if uptime_s > 3600:
        events.append((boot_epoch + uptime_s * 0.4, "Watchdog reset cleared"))

    # Persistent events from SQLite (process + operator + s7_read events)
    try:
        import diag_log as _dl
        for (fake_ts, desc) in _dl.load_events(limit=limit):
            events.append((fake_ts, desc))
    except Exception:
        pass

    # Configured lines are startup/commissioning messages ("Mode transition
    # from STARTUP to RUN", "PROFINET IO device established", ...). They were
    # stamped at now-5s, so they appeared as the NEWEST entries on every page
    # load and walked forward on refresh — a device reporting that it just
    # completed startup, continuously, while SZL 0x0424 reports days of
    # uptime. Anchor them to the boot sequence where they belong.
    for i, line in enumerate(web_cfg.get("diagnostic_buffer_lines", [])):
        events.append((boot_epoch + 11 + i, line))

    events.sort(key=lambda x: x[0], reverse=True)
    return [(_ts(ep), ev) for ep, ev in events[:limit]]




def _page_start(identity, web_cfg: dict, net: dict, error):
    state = cpu_state.read_cpu_state()
    scls  = "val-run" if state == "RUN" else "val-stop"

    diag_events = _build_diag_events(web_cfg, limit=20)
    diag_rows   = "".join(
        f'<tr><td class="dbuf-time">{ts}</td><td>{event}</td></tr>'
        for ts, event in diag_events
    ) or '<tr><td colspan="2" style="color:#888;font-style:italic">No entries</td></tr>'

    ps, sim_cpu_state = _load_process_state()
    if ps:
        step_names = {0:"Idle",1:"Starting",2:"Running",3:"Stopping",4:"Alarm"}
        step_val   = int(ps.get("marker_step", 2))
        def pv(key, fmt=".1f", unit=""):
            v = ps.get(key)
            return (f"{v:{fmt}}{unit}" if v is not None else "\u2014")
        if sim_cpu_state == "STOP":
            frozen_banner = (
                '<p style="color:#cc0000;font-weight:bold;margin-bottom:6px">'
                '&#9632; CPU in STOP \u2014 process values frozen</p>')
        elif sim_cpu_state == "COMM_FAULT":
            # Bridge stopped delivering data past the watchdog threshold.
            # Values are frozen at their last-known state (consistent with
            # S7comm DB reads, which also read the frozen snap7 memory).
            frozen_banner = (
                '<p style="color:#cc6600;font-weight:bold;margin-bottom:6px">'
                '&#9888; Process data acquisition fault \u2014 '
                'values frozen at last known state</p>')
        else:
            frozen_banner = ""
        process_html = f"""
<div class="section"><div class="sec-title">Process Overview</div>
{frozen_banner}
<table class="info">
<tr><td>OB1 step / state</td><td>{step_names.get(step_val, str(step_val))}</td></tr>
<tr><td>Temperature</td><td>{pv("db200_temperature", ".1f", " &deg;C")}</td></tr>
<tr><td>Flow rate</td><td>{pv("db200_flow", ".1f", " l/min")}</td></tr>
<tr><td>Pressure</td><td>{pv("db200_pressure", ".2f", " bar")}</td></tr>
<tr><td>Tank level</td><td>{pv("db200_level", ".1f", " %")}</td></tr>
<tr><td>Inputs (IB0)</td><td><tt>{int(ps.get("input_byte0", 0)):08b}b</tt></td></tr>
<tr><td>Outputs (QB0)</td><td><tt>{int(ps.get("output_byte0", 0)):08b}b</tt></td></tr>
<tr><td>OB1 cycle count</td><td>{int(ps.get("marker_cycle_count", 0)):,}</td></tr>
</table>
</div>"""
    else:
        process_html = ""

    login_html = ""
    if web_cfg.get("require_login", False):
        err = f'<div class="err">{html.escape(error)}</div>' if error else ""
        login_html = f"""<div class="section"><div class="sec-title">Login</div>
{err}<form method="POST" action="/login" autocomplete="off">
<table class="login-tbl">
<tr><td>User name:</td><td><input type="text" name="username" size="20"></td></tr>
<tr><td>Password:</td><td><input type="password" name="password" size="20"></td></tr>
<tr><td></td><td><input type="submit" value="Login" class="btn-login"></td></tr>
</table></form></div>"""

    return f"""
<div class="section"><div class="sec-title">Module Identification</div>
<table class="info">
<tr><td>Module</td><td>{html.escape(identity.module_name)}</td></tr>
<tr><td>Order number</td><td>{html.escape(identity.order_code)}</td></tr>
<tr><td>Firmware version</td><td>{html.escape(identity.firmware_version)}</td></tr>
<tr><td>Serial number</td><td>{html.escape(identity.serial_number)}</td></tr>
<tr><td>Plant designation</td><td>{html.escape(identity.plant_id or "\u2014")}</td></tr>
<tr><td>CPU state</td><td class="{scls}">{html.escape(state)}</td></tr>
</table></div>
<div class="section"><div class="sec-title">Ethernet Interface</div>
<table class="info">
<tr><td>IP address</td><td>{html.escape(net.get("ip_address",""))}</td></tr>
<tr><td>Subnet mask</td><td>{html.escape(net.get("netmask","255.255.255.0"))}</td></tr>
<tr><td>MAC address</td><td>{html.escape(net.get("mac_address",""))}</td></tr>
</table></div>
{process_html}
<div class="section">
  <div class="sec-title">Diagnostic Buffer
    <span style="font-size:10px;font-weight:normal;margin-left:8px">
      <a href="/Portal0000.htm?6" style="color:#fff">View all &rarr;</a>
    </span>
  </div>
<table class="dbuf">
<tr><th>Date / Time</th><th>Event</th></tr>{diag_rows}
</table></div>
{login_html}"""


def _page_module_id(identity) -> str:
    return f"""
<div class="section"><div class="sec-title">Module Identification</div>
<table class="info">
<tr><td>Module name</td><td>{html.escape(identity.module_name)}</td></tr>
<tr><td>Order number</td><td>{html.escape(identity.order_code)}</td></tr>
<tr><td>Hardware version</td><td>1</td></tr>
<tr><td>Firmware version</td><td>{html.escape(identity.firmware_version)}</td></tr>
<tr><td>Serial number</td><td>{html.escape(identity.serial_number)}</td></tr>
<tr><td>Plant designation</td><td>{html.escape(identity.plant_id)}</td></tr>
<tr><td>Location identifier</td><td>{html.escape(identity.plc_name)}</td></tr>
<tr><td>Profile</td><td>S7-300</td></tr>
</table></div>"""


def _page_cpu_info(identity) -> str:
    state = cpu_state.read_cpu_state()
    scls  = "val-run" if state == "RUN" else "val-stop"
    return f"""
<div class="section"><div class="sec-title">CPU Information</div>
<table class="info">
<tr><td>CPU state</td><td class="{scls}">{html.escape(state)}</td></tr>
<tr><td>Operating mode</td><td>{html.escape(state)}</td></tr>
<tr><td>Protection level</td><td>1 (no protection)</td></tr>
<tr><td>Key switch position</td><td>RUN</td></tr>
</table></div>
<div class="section"><div class="sec-title">Memory</div>
<table class="info">
<tr><td>Work memory (used)</td><td>22 KB</td></tr>
<tr><td>Work memory (free)</td><td>106 KB</td></tr>
<tr><td>Load memory (used)</td><td>36 KB</td></tr>
<tr><td>Load memory (free)</td><td>28 KB (integrated)</td></tr>
</table></div>
<div class="section"><div class="sec-title">Resources</div>
<table class="info">
<tr><td>S7 timers</td><td>256 (T0&ndash;T255)</td></tr>
<tr><td>S7 counters</td><td>256 (C0&ndash;C255)</td></tr>
<tr><td>Marker bytes</td><td>256 (MB0&ndash;MB255)</td></tr>
<tr><td>Process image I/O</td><td>128 bytes</td></tr>
<tr><td>Data blocks max</td><td>511</td></tr>
</table></div>"""


def _page_module_status(identity) -> str:
    state = cpu_state.read_cpu_state()
    scls  = "val-run" if state == "RUN" else "val-stop"
    return f"""
<div class="section"><div class="sec-title">Module Status \u2014 Rack 0</div>
<table class="rack">
<tr>
  <td class="slot-ps">Slot 1<br><small>PS 307 5A</small></td>
  <td class="slot-cpu">Slot 2<br><small>{html.escape(identity.module_name)}</small><br>
    <span class="{scls}" style="font-size:10px">{html.escape(state)}</span></td>
  <td class="slot-empty">Slot 3<br><small>\u2014</small></td>
  <td class="slot-io">Slot 4<br><small>DI16/DO16</small></td>
  <td class="slot-io">Slot 5<br><small>AI8</small></td>
  <td class="slot-empty">Slot 6<br><small>\u2014</small></td>
</tr></table></div>"""


def _page_ethernet(identity, net: dict) -> str:
    return f"""
<div class="section"><div class="sec-title">Ethernet Interface X1</div>
<table class="info">
<tr><td>IP address</td><td>{html.escape(net.get("ip_address",""))}</td></tr>
<tr><td>Subnet mask</td><td>{html.escape(net.get("netmask","255.255.255.0"))}</td></tr>
<tr><td>Default gateway</td><td>{html.escape(net.get("gateway","0.0.0.0"))}</td></tr>
<tr><td>MAC address</td><td>{html.escape(net.get("mac_address",""))}</td></tr>
<tr><td>Link status</td><td class="val-ok">Connected 100 Mbit/s full duplex</td></tr>
</table></div>"""


def _page_connections(identity, net: dict, visitor_ip: str) -> str:
    local_ip = net.get("ip_address","")
    scada_oct = local_ip.rsplit(".",1)[0] if "." in local_ip else "10.0.0"
    rows = [
        f'<tr><td>1</td><td>S7 connection</td><td>{html.escape(visitor_ip)}</td><td>TCP/102</td><td class="conn-active">Active</td><td>PG/PC</td></tr>',
        f'<tr><td>2</td><td>S7 connection</td><td>{scada_oct}.1</td><td>TCP/102</td><td class="conn-active">Active</td><td>HMI</td></tr>',
    ] + [
        f'<tr><td>{s}</td><td>\u2014</td><td>\u2014</td><td>\u2014</td><td class="conn-free">Free</td><td>\u2014</td></tr>'
        for s in range(3,9)
    ]
    return f"""
<div class="section"><div class="sec-title">Active Connections</div>
<table class="conn">
<tr><th>ID</th><th>Type</th><th>Remote IP</th><th>Port</th><th>Status</th><th>Partner type</th></tr>
{"".join(rows)}
</table></div>"""


def _page_diag_buffer(web_cfg: dict) -> str:
    # The web server reads the buffer internally, so unlike SZL 0x00A0
    # (limited to ~20 records by the 480-byte PDU) it can render all 100.
    # Same source, different transport limit - which is how real hardware
    # behaves and keeps the two surfaces consistent.
    events = _build_diag_events(web_cfg, limit=100)
    rows   = "".join(
        f'<tr><td class="dbuf-time">{ts}</td><td>{event}</td></tr>'
        for ts, event in events
    )
    return f"""
<div class="section"><div class="sec-title">Diagnostic Buffer</div>
<p class="hint" style="margin-bottom:6px">Buffer holds the last 100 events. Most recent first.</p>
<table class="dbuf">
<tr><th>Date / Time</th><th>Event</th></tr>
{rows}
</table></div>"""


def _page_disabled(identity) -> str:
    return f"""
<div class="section"><div class="sec-title">Function disabled</div>
<p style="margin:8px 0 6px 0">This function has been disabled&nbsp;(by configuration).</p>
<p style="color:#555;font-size:10px">
The requested diagnostic page is not available because web server access to this function
has been restricted in the configuration of module&nbsp;<strong>{html.escape(identity.module_name)}</strong>.
</p></div>"""


def _page_performance(identity) -> str:
    import random
    cycle = max(5.0, min(15.0, 8 + round(random.gauss(0, 0.4), 1)))
    load  = round(cycle / 20 * 100, 1)
    return f"""
<div class="section"><div class="sec-title">Cycle Time Statistics</div>
<table class="perf">
<tr><td>Shortest cycle (OB1)</td><td class="num">{cycle-1.2:.1f} ms</td></tr>
<tr><td>Longest cycle (OB1)</td> <td class="num">{cycle+2.8:.1f} ms</td></tr>
<tr><td>Current cycle (OB1)</td> <td class="num">{cycle:.1f} ms</td></tr>
<tr><td>CPU load</td>            <td class="num">{load:.1f} %</td></tr>
</table></div>"""


def _page_scan_cycle(identity) -> str:
    return """
<div class="section"><div class="sec-title">Scan Cycle \u2014 OB1</div>
<table class="perf">
<tr><td>Cycle monitoring time</td><td class="num">150 ms</td></tr>
<tr><td>Min. scan cycle time</td> <td class="num">6.8 ms</td></tr>
<tr><td>Max. scan cycle time</td> <td class="num">11.2 ms</td></tr>
<tr><td>Last scan cycle time</td> <td class="num">8.4 ms</td></tr>
</table></div>"""


def _page_vartable(web_cfg: dict, require_login: bool, error) -> str:
    return """
<div class="section"><div class="sec-title">Variable Table</div>
<p class="hint">Variable monitoring is not enabled on this device.</p>
</div>"""


def _page_datarecords() -> str:
    return """
<div class="section"><div class="sec-title">Data Records</div>
<p class="hint">No data records configured on this device.</p>
</div>"""


def _render_page(identity, web_cfg: dict, error=None,
                 page: str = "0", visitor_ip: str = "") -> str:
    net = _load_network_state()
    if page == "disabled":
        content = _page_disabled(identity)
    elif page == "1":
        content = _page_module_id(identity)
    elif page == "2":
        content = _page_cpu_info(identity)
    elif page == "3":
        content = _page_module_status(identity)
    elif page == "4":
        content = _page_ethernet(identity, net)
    elif page == "5":
        content = _page_connections(identity, net, visitor_ip)
    elif page == "6":
        content = _page_diag_buffer(web_cfg)
    elif page == "7":
        content = _page_performance(identity)
    elif page == "8":
        content = _page_scan_cycle(identity)
    elif page == "9":
        content = _page_vartable(web_cfg, web_cfg.get("require_login", False), error)
    elif page == "10":
        content = _page_datarecords()
    else:
        content = _page_start(identity, web_cfg, net, error)
    return _shell(identity, page, content,
                  auto_refresh=5 if page == "0" else 0)


def classify_request(path: str, user_agent: str, noise_cfg: dict) -> dict:
    """
    Best-effort tag for whether a request looks like generic internet
    background scanning (mass web-vuln sweepers hitting every host on
    port 80 regardless of what's actually running there) versus a
    request that shows some awareness this is a specific device. This
    does NOT filter or drop anything -- every request is logged
    regardless -- it only adds a tag for downstream analysis.

    Heuristic, not authoritative: a targeted attacker manually poking
    around with curl will also get flagged generic_scanner_signal=True
    here (curl's UA is in the default list), and a sophisticated
    ICS-aware scanner using a spoofed benign UA won't be flagged at all.
    Same limitation as s7_precheck.py's noise filter -- see README.
    """
    path_lower = path.lower()
    ua_lower = (user_agent or "").lower()

    matched_paths = [
        s for s in noise_cfg.get("generic_scanner_path_substrings", [])
        if s.lower() in path_lower
    ]
    matched_ua = next(
        (s for s in noise_cfg.get("generic_scanner_user_agent_substrings", [])
         if s.lower() in ua_lower),
        None,
    )

    return {
        "generic_scanner_signal": bool(matched_paths or matched_ua),
        "matched_path_substrings": matched_paths,
        "matched_user_agent_substring": matched_ua,
    }


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "S7Honeypot"  # overridden per-response below if configured

    def handle(self) -> None:
        """Override to suppress ConnectionResetError from TCP port scanners
        that connect to port 80 and immediately reset without completing
        an HTTP handshake -- completely normal internet background noise,
        not an error worth logging at all."""
        try:
            super().handle()
        except ConnectionResetError:
            pass

    def send_response(self, code: int, message: str | None = None) -> None:
        """
        Override stdlib's send_response() entirely rather than relying on
        version_string(), because BaseHTTPRequestHandler.send_response()
        unconditionally calls send_header('Server', self.version_string())
        -- returning an empty string from version_string() still results
        in a literal empty `Server:` header being sent, which is arguably
        a bigger tell than either a normal header or none at all. This
        skips that header entirely when server_header isn't configured.
        """
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())
        server_header = self.server.web_cfg.get("server_header", "")
        if server_header:
            self.send_header("Server", server_header)

    def _send_html(self, body: str, status: int = 200) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _session_id(self) -> str:
        return f"http-{self.client_address[0]}-{self.client_address[1]}-{int(time.time()*1000)}"

    def _log(self, event_type: str, raw: bytes, parsed: dict) -> None:
        session_id = self._session_id()
        self.server.cmd_logger.log_event(
            session_id, self.client_address[0], self.client_address[1],
            event_type, raw, parsed,
        )

    def do_GET(self) -> None:
        raw = f"GET {self.path} HTTP/1.1\r\n" + str(self.headers)
        user_agent = self.headers.get("User-Agent", "")
        noise_cfg = self.server.web_cfg.get("noise_filter", {})
        classification = classify_request(self.path, user_agent, noise_cfg)
        visitor_ip = self.client_address[0]

        self._log("http_request", raw.encode("utf-8", errors="replace"),
                   {"method": "GET", "path": self.path, "user_agent": user_agent,
                    **classification})

        # Parse path and query string.  Portal0000.htm?N routes to page N.
        parsed_url = urllib.parse.urlparse(self.path)
        base_path  = parsed_url.path
        qs         = parsed_url.query.split("&")[0]  # first param = page id
        page_id    = qs if qs in _PAGES else "0"

        portal_paths = {"/", "/index.html", "/portal",
                        "/Portal0000.htm", "/Portal0001.htm",
                        "/Portal0002.htm", "/Portal0003.htm",
                        "/startpage.htm", "/start.htm"}

        if base_path == "/favicon.ico":
            self.send_response(200)
            self.send_header("Content-Type",   "image/x-icon")
            self.send_header("Content-Length", str(len(_FAVICON_ICO)))
            self.send_header("Cache-Control",  "max-age=86400")
            server_hdr = self.server.web_cfg.get("server_header", "")
            if server_hdr:
                self.send_header("Server", server_hdr)
            self.end_headers()
            self.wfile.write(_FAVICON_ICO)
            return

        if base_path in portal_paths:
            rendered = _render_page(self.server.identity, self.server.web_cfg,
                                    page=page_id, visitor_ip=visitor_ip)
            self._send_html(rendered)
        else:
            log.info("404 for path %s from %s%s", self.path, visitor_ip,
                      " [generic scanner signal]" if classification["generic_scanner_signal"] else "")
            self._send_html("<html><body><h1>404 Not Found</h1></body></html>", status=404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        raw = (f"POST {self.path} HTTP/1.1\r\n" + str(self.headers)).encode("utf-8", errors="replace") + body
        user_agent = self.headers.get("User-Agent", "")
        noise_cfg = self.server.web_cfg.get("noise_filter", {})
        classification = classify_request(self.path, user_agent, noise_cfg)

        if self.path == "/login" and self.server.web_cfg.get("require_login", False):
            fields = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"))
            username = fields.get("username", [""])[0]
            password = fields.get("password", [""])[0]

            # CREDENTIAL CAPTURE -- the actual point of the login form.
            # Logged at INFO so it's visible live, not just in JSONL.
            log.info("Login attempt from %s: username=%r password=%r",
                      self.client_address[0], username, password)
            self._log("http_login_attempt", raw, {
                "username": username,
                "password": password,
                **classification,
            })

            # Always fails -- there's nothing behind this to log into.
            page = _render_page(self.server.identity, self.server.web_cfg,
                                 error="Invalid user name or password.",
                                 page="0",
                                 visitor_ip=self.client_address[0])
            self._send_html(page, status=200)
            return

        self._log("http_request", raw, {"method": "POST", "path": self.path,
                                         "user_agent": user_agent, **classification})
        self._send_html("<html><body><h1>404 Not Found</h1></body></html>", status=404)

    def log_message(self, format: str, *args) -> None:
        # Silence BaseHTTPRequestHandler's default stderr access logging --
        # everything meaningful already goes through self._log()/JSONL.
        pass


class WebPortalServer(ThreadingHTTPServer):
    allow_reuse_address = True
    # Force IPv4-only. A real S7-300 is IPv4-only, and IPv6 is disabled at the
    # host level by fingerprint_harden.sh; pinning the address family here means
    # the portal never binds :: even if IPv6 were re-enabled.
    address_family = socket.AF_INET

    def __init__(self, host: str, port: int, identity: S7Identity, web_cfg: dict,
                 cmd_logger: CommandLogger):
        super().__init__((host, port), PortalHandler)
        self.identity   = identity
        self.web_cfg    = web_cfg
        self.cmd_logger = cmd_logger

    def handle_error(self, request, client_address: tuple) -> None:
        """
        Suppress the noisy tracebacks that Python's socketserver prints when
        a scanner (nmap, masscan, etc.) opens a raw TCP connection on port 80
        and closes it without sending an HTTP request.  These generate
        ConnectionResetError / BrokenPipeError constantly and fill the
        journal with unreadable noise.

        Real errors (unexpected exceptions) are still logged at WARNING
        so genuine bugs aren't silently swallowed.
        """
        import sys
        exc_type = sys.exc_info()[0]
        silent = (
            exc_type is ConnectionResetError or
            exc_type is BrokenPipeError or
            exc_type is ConnectionAbortedError or
            # SSL probes on plain HTTP port produce this
            (exc_type is not None and
             exc_type.__name__ in ("SSLError", "RemoteDisconnected",
                                   "BadStatusLine"))
        )
        peer = client_address[0] if client_address else "unknown"
        if silent:
            log.debug("Connection noise from %s: %s (scanner/probe)",
                      peer, exc_type.__name__ if exc_type else "?")
        else:
            log.warning("HTTP handler exception from %s:", peer, exc_info=True)


def run(config_path: str = "config.yaml") -> None:
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    # Point diag_log at the configured database. Without this the web portal
    # keeps diag_log's module default while the proxy and backend (which do
    # call configure) write to logging.honeypot_db — two processes reading
    # and writing different files, so the diagnostic buffer renders empty
    # while events are being recorded correctly elsewhere.
    try:
        import diag_log as _dl
        _dl.configure(config_path)
        log.info("Diagnostic event database: %s", _dl._DB_PATH)
    except Exception as exc:
        log.warning("Could not configure diag_log (%s): the diagnostic "
                    "buffer may render empty", exc)

    # Resolve the process snapshot path from the same data dir the writer
    # uses. process_simulator writes to <data_dir>/process_state.json; if the
    # data dir is not the /var/lib default, the portal must follow it or the
    # Process Overview silently disappears.
    global _PROCESS_STATE_PATH, NETWORK_STATE_PATH
    try:
        from paths import Paths
        _p = Paths.load(config_path)
        _PROCESS_STATE_PATH = str(_p.process_state)
        NETWORK_STATE_PATH  = _p.network_state
        log.info("Process snapshot: %s   Network state: %s",
                 _PROCESS_STATE_PATH, NETWORK_STATE_PATH)
    except Exception as exc:
        log.warning("Could not resolve state paths (%s); using defaults", exc)

    web_cfg = cfg.get("web_portal", {})
    if not web_cfg.get("enabled", True):
        log.info("Web portal disabled in config, not starting")
        return

    try:
        data_dir = resolve_and_verify(cfg)
    except StorageError as e:
        log.error("Storage check failed: %s", e)
        raise

    jsonl_path = substitute_data_dir(cfg["logging"]["jsonl_path"], data_dir)
    cmd_logger = CommandLogger(jsonl_path)
    identity = S7Identity.from_config(config_path)

    host = web_cfg.get("listen_host", "0.0.0.0")
    port = web_cfg.get("listen_port", 80)

    server = WebPortalServer(host, port, identity, web_cfg, cmd_logger)
    log.info("Web portal listening on %s:%d (require_login=%s)",
              host, port, web_cfg.get("require_login", True))
    server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    run(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")
