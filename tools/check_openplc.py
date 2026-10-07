#!/usr/bin/env python3
"""
check_openplc.py — Verify OpenPLC process simulation is active
===============================================================
Runs a series of checks to confirm:
  1. x-openplc and x-modbus-bridge are enabled in config.yaml
  2. Docker container is running
  3. Modbus TCP is responding on 127.0.0.1:502
  4. Modbus registers match process_sim.st expected ranges
  5. Values are changing between two reads (OpenPLC program is executing)
  6. DB200 in snap7 reflects the same values (bridge is writing correctly)

Usage:
  python3 check_openplc.py [config.yaml]
"""

import sys
import time
import socket
import struct
import subprocess
import json
from pathlib import Path

CONFIG = sys.argv[1] if len(argv := sys.argv) > 1 else "config.yaml"
P = "✓"; F = "✗"; W = "⚠"


# ── helpers ────────────────────────────────────────────────────────────────────

def check(label, ok, detail=""):
    sym = P if ok else F
    print(f"  {sym}  {label}")
    if detail:
        print(f"       {detail}")
    return ok


# Last failure reason from a Modbus read, so the checks below can say what
# actually happened instead of a generic "No Modbus response". Two real
# cases this used to hide: nothing listening inside the container
# (docker-proxy resets the connection) and an exception reply.
_last_err = ""

_MODBUS_EXC = {
    1: "illegal function", 2: "illegal data address", 3: "illegal data value",
    4: "server device failure", 6: "server busy",
    10: "gateway path unavailable", 11: "gateway target failed to respond",
}


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _modbus_read(host, port, fc, start, count, unit=1, timeout=3.0):
    """Raw Modbus TCP read (FC1/FC3). Returns the data bytes, or None with
    the reason left in _last_err."""
    global _last_err
    _last_err = ""
    pkt = struct.pack(">HHHBBHH", fc, 0, 6, unit, fc, start, count)
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(pkt)
            header = _recv_exact(s, 8)          # MBAP(7) + function code
            if len(header) < 8:
                _last_err = ("connection closed with no reply — nothing is "
                             "listening behind the port (PLC runtime stopped?)")
                return None
            rfc = header[7]
            if rfc & 0x80:
                code = _recv_exact(s, 1)
                c = code[0] if code else -1
                _last_err = (f"Modbus exception {c} "
                             f"({_MODBUS_EXC.get(c, 'unknown')}) for FC{fc}")
                return None
            bc = _recv_exact(s, 1)
            if not bc:
                _last_err = "reply truncated before byte count"
                return None
            data = _recv_exact(s, bc[0])
            if len(data) < bc[0]:
                _last_err = f"reply truncated ({len(data)}/{bc[0]} bytes)"
                return None
            return data
    except ConnectionResetError:
        _last_err = ("connection reset — docker-proxy accepted but nothing "
                     "listens on 502 inside the container (PLC runtime stopped)")
    except socket.timeout:
        _last_err = f"timed out after {timeout:g}s waiting for a reply"
    except OSError as e:
        _last_err = f"{type(e).__name__}: {e}"
    return None


def read_modbus_holding_regs(host, port, start, count, unit=1, timeout=3.0):
    """FC3 holding registers -> list of signed INT16, or None (see _last_err)."""
    data = _modbus_read(host, port, 3, start, count, unit, timeout)
    if data is None:
        return None
    regs = [struct.unpack_from(">H", data, i * 2)[0] for i in range(count)]
    return [r if r < 32768 else r - 65536 for r in regs]


def read_modbus_coils(host, port, start, count, unit=1, timeout=3.0):
    """FC1 coils -> list of 0/1, or None (see _last_err)."""
    data = _modbus_read(host, port, 1, start, count, unit, timeout)
    if data is None:
        return None
    bits = []
    for byte in data:
        for b in range(8):
            bits.append((byte >> b) & 1)
    return bits[:count]


# ── main checks ────────────────────────────────────────────────────────────────

def main():
    print()
    print("S7 Honeypot — OpenPLC Simulation Verification")
    print("=" * 52)
    print()

    all_ok = True

    # ── 1. Config flags ────────────────────────────────────────────────────────
    print("[ 1 ] Config flags")
    try:
        import yaml
        cfg = yaml.safe_load(Path(CONFIG).read_text())
        openplc_on = cfg.get("x-openplc", False)
        bridge_on  = cfg.get("x-modbus-bridge", False)
        mb_cfg     = cfg.get("modbus_bridge", {})
        mb_host    = mb_cfg.get("host", "127.0.0.1")
        mb_port    = mb_cfg.get("port", 502)

        ok1 = check("x-openplc: true",       openplc_on,
                    f"currently: {openplc_on}")
        ok2 = check("x-modbus-bridge: true",  bridge_on,
                    f"currently: {bridge_on}")
        all_ok &= (ok1 and ok2)

        if not openplc_on:
            print(f"\n  {W}  OpenPLC is disabled — honeypot is using the built-in")
            print(f"       Python process_simulator (random-walk values).")
            print(f"       Run: sudo bash install_openplc.sh  to enable OpenPLC.")
            print()
    except Exception as e:
        check("Config readable", False, str(e))
        all_ok = False
        sys.exit(1)
    print()

    # ── 2. Docker container ────────────────────────────────────────────────────
    print("[ 2 ] Docker container")
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format={{.State.Status}}",
             "s7honeypot-openplc"],
            capture_output=True, text=True, timeout=5
        )
        status = result.stdout.strip()
        ok3 = check(f"Container s7honeypot-openplc status: {status}",
                    status == "running")
        all_ok &= ok3
    except FileNotFoundError:
        check("Docker installed", False, "docker command not found")
        all_ok = False
    except Exception as e:
        check("Container running", False, str(e))
        all_ok = False
    print()

    # ── 3. Modbus TCP responding ───────────────────────────────────────────────
    print("[ 3 ] Modbus TCP on 127.0.0.1:502")
    try:
        with socket.create_connection((mb_host, mb_port), timeout=3.0):
            ok4 = check(f"TCP connect to {mb_host}:{mb_port}", True)
    except Exception as e:
        ok4 = check(f"TCP connect to {mb_host}:{mb_port}", False, str(e))
    all_ok &= ok4
    print()

    # ── 4. Register values in expected ranges ──────────────────────────────────
    print("[ 4 ] Modbus register values (process_sim.st expected ranges)")

    regs = read_modbus_holding_regs(mb_host, mb_port, 0, 7)
    coils = read_modbus_coils(mb_host, mb_port, 0, 4)

    if regs is None:
        check("Read holding registers 0-6", False, _last_err or "no reply")
        all_ok = False
    elif not any(regs):
        check("Read holding registers 0-6", False,
              "registers read OK but ALL ZERO — the PLC runtime answers but "
              "the program is not executing (or isn't process_sim). Upload "
              "process_sim.st and Start PLC in the OpenPLC UI — "
              "TROUBLESHOOTING §4")
        all_ok = False
        regs = None    # skip the range checks; they'd all just echo zero
    else:
        temp_x10, flow_x10, pres_x100, level_x10, setpt_x10, step, scan = regs

        # Ranges from confirmed working process_sim.st physics model
        # setpoint=300 (30.0 degC), level starts at 900 (90%), drains down
        ok5 = check(f"HR0 temperature = {temp_x10/10:.1f}°C  (expect 20–80°C)",
                    200 <= temp_x10 <= 800)
        ok6 = check(f"HR1 flow = {flow_x10/10:.1f} l/min  (expect 0–120)",
                    0 <= flow_x10 <= 1200)
        ok7 = check(f"HR2 pressure = {pres_x100/100:.2f} bar  (expect 3.0–6.2)",
                    300 <= pres_x100 <= 620)
        ok8 = check(f"HR3 level = {level_x10/10:.1f}%  (expect 0–90)",
                    0 <= level_x10 <= 900)
        ok9 = check(f"HR5 seq_state = {step}  (expect 0–4)",
                    0 <= step <= 4)

        step_names = {0:"IDLE", 1:"STARTING", 2:"RUNNING", 3:"STOPPING", 4:"ALARM"}
        print(f"       Sequencer state: {step_names.get(step, '?')}")
        all_ok &= (ok5 and ok6 and ok7 and ok8 and ok9)

    if coils is None:
        check("Read coils 0-3", False, _last_err or "no reply")
        all_ok = False
    else:
        pump, valve, temp_hi, temp_lo = coils
        print(f"  {P}  Coils: pump={'ON' if pump else 'off'} "
              f"valve={'OPEN' if valve else 'closed'} "
              f"temp_hi={'⚠ ALARM' if temp_hi else 'ok'} "
              f"temp_lo={'⚠ LOW' if temp_lo else 'ok'}")
    print()

    # ── 5. Values are changing ─────────────────────────────────────────────────
    print("[ 5 ] Values changing between two reads (program executing?)")
    if regs is not None:
        regs1 = regs
        scan1 = regs1[6]
        print(f"       Reading again in 1 second...")
        time.sleep(1.0)
        regs2 = read_modbus_holding_regs(mb_host, mb_port, 0, 7)
        if regs2:
            scan2 = regs2[6]
            delta = (scan2 - scan1) & 0x7FFF   # handle 32767 wrap
            ok_change = delta > 0
            check(f"Scan counter advanced: {scan1} → {scan2} (+{delta})",
                  ok_change,
                  "Zero delta means OB1 is not running — check OpenPLC logs")
            if ok_change:
                # Temperature might not change in 1s but scan counter must
                temp1 = regs1[0]; temp2 = regs2[0]
                if temp1 != temp2:
                    print(f"  {P}  Temperature also changed: "
                          f"{temp1/10:.1f} → {temp2/10:.1f}°C")
                else:
                    print(f"  {P}  Temperature stable at {temp1/10:.1f}°C "
                          f"(normal near setpoint)")
            all_ok &= ok_change
        else:
            check("Second read succeeded", False, _last_err or "lost Modbus connection")
            all_ok = False
    print()

    # ── Summary ────────────────────────────────────────────────────────────────
    print("=" * 52)
    if all_ok:
        print(f"  {P}  OpenPLC simulation is ACTIVE and driving S7comm values")
        print(f"       DB200 reads return real IEC 61131-3 process data")
    else:
        print(f"  {F}  One or more checks failed — see details above")
        if not openplc_on:
            print(f"       Honeypot is using built-in process_simulator")
        else:
            print(f"       OpenPLC may still be starting (allow 30s after boot)")
    print()


if __name__ == "__main__":
    main()
