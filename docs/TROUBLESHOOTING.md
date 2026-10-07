# Troubleshooting

A command-first guide to confirming honeypot-s7 is working and diagnosing the
things that actually go wrong on a fresh deployment. Every section gives you a
command to run and what a healthy result looks like.

---

## 0. The venv rule — read this first

Every tool in `tools/` imports `python-snap7`, which lives in the honeypot's
**virtualenv**, not the system Python. Running a tool with `sudo python` or
`sudo python3` fails with a bare:

```
No module named 'snap7'
```

Always run tools under the venv interpreter:

```bash
sudo /opt/s7honeypot/venv/bin/python /opt/s7honeypot/tools/<tool>.py [args]
```

This is the single most common stumble after installation. If a tool fails on
import, this is almost always why.

---

## 1. Confirm it's working

### Are the core services up?

```bash
systemctl is-active s7honeypot-proxy s7honeypot-backend \
                    s7honeypot-web s7honeypot-snmp
```

Healthy: four lines of `active`.

### Is the full S7comm pipeline working end to end?

```bash
sudo /opt/s7honeypot/venv/bin/python /opt/s7honeypot/tools/verify_live_db_reads.py \
    --host 127.0.0.1 --port 102 --rack 0 --slot 2
```

Healthy: DB200 reads return process values (temperature around the configured
setpoint, e.g. ~30 °C) and the values **drift between the two samples**. This
proves the whole chain — OpenPLC/simulator → snap7 memory → S7comm on 102 — is
delivering live data.

`--port 102` routes through the full proxy (realistic). `--port 1102` talks to
the backend directly, bypassing the proxy, to isolate a backend problem.

### Is OpenPLC actually executing the program?

The most reliable check — read the scan counter (holding register 6) a few
times and confirm it advances:

```bash
for i in 1 2 3 4 5; do
  /opt/s7honeypot/venv/bin/python -c "
import socket, struct
p = struct.pack('>HHHBBHH', 1, 0, 6, 1, 3, 0, 7)
s = socket.create_connection(('127.0.0.1', 502), 5); s.sendall(p)
h = s.recv(9); d = s.recv(h[8]); s.close()
v = [struct.unpack_from('>h', d, j*2)[0] for j in range(7)]
print(f'  temp={v[0]/10:.1f}  flow={v[1]/10:.1f}  lvl={v[3]/10:.1f}  scan={v[6]}')
"
  sleep 1
done
```

Healthy: the scan counter climbs steadily (roughly +50 per second at the
default 20 ms scan cycle), temperature oscillates in a tight band around the
setpoint, flow and level move plausibly. If every value is `0` and the scan
counter does not move, OpenPLC is loaded but **not running** — see section 4.

### Is the web portal serving live values?

```bash
curl -s http://127.0.0.1/ | grep -iE "temperature|flow|acquisition fault"
```

Healthy: current temperature and flow appear. If you see "Process data
acquisition fault", the bridge has stopped receiving data — see section 6.

### Are the ports correct?

```bash
sudo ss -tlnp | grep -E ':(102|80|1102)'
```

Healthy: `102` and `80` on `0.0.0.0` (or your interface IP); `1102` on
`127.0.0.1` only. If `1102` shows `0.0.0.0`, the loopback bind didn't take and
the `fingerprint_harden.sh` REJECT rule is the backstop — confirm it's applied
(section 8).

---

## 2. Restarting services safely

Not all services are equal. Some are long-running and safe to bounce; some are
boot-time oneshots that touch network or firewall state and should be handled
with care.

### Tier 1 — safe to restart freely

The standard "it's stuck, restart it" fix. These are long-running and
stateless with respect to the network/firewall:

```bash
sudo systemctl restart s7honeypot-proxy
sudo systemctl restart s7honeypot-backend
sudo systemctl restart s7honeypot-web
sudo systemctl restart s7honeypot-snmp
```

Restarting `s7honeypot-proxy` pulls in its dependencies, so it's the usual
one-liner to bring the S7 surface back.

### Tier 2 — safe to re-run when the IP changed

```bash
sudo systemctl restart s7honeypot-ip-writer
```

`ip-writer` records the current interface IP / netmask / MAC into the network
state file that SNMP and the web portal read. **Re-run it any time the IP has
changed** — a new DHCP lease, a MAC change, moving networks — so those surfaces
report the real current address instead of a stale one. This is a legitimate,
safe troubleshooting action.

Verify afterward that SNMP reports the right address:

```bash
snmpwalk -v2c -c public 127.0.0.1 2>/dev/null | grep -i ipadent
```

### Tier 3 — re-run only with intent, understand the effect

**`s7honeypot-mac-spoof`** re-applies the spoofed MAC. Changing the MAC can
trigger a **new DHCP lease** (new IP). If you restart it, follow with
`ip-writer` so the recorded address stays correct:

```bash
sudo systemctl restart s7honeypot-mac-spoof
sudo systemctl restart s7honeypot-ip-writer     # re-sync after the MAC change
```

**`s7honeypot-harden`** reverts then re-applies the firewall/sysctl hardening
(`ExecStop` runs `fingerprint_harden.sh revert`, `ExecStart` runs `apply`).
During that window the honeypot is briefly **unhardened**, and a hiccup can
leave duplicate or missing iptables rules. Prefer running the script's
`status`/`apply` directly (section 8) over restarting the unit mid-operation.

---

## 3. Docker won't install / OpenPLC build fails

Symptom: `install_openplc.sh` fails during the image build, or `docker compose`
reports it isn't a recognized command.

Cause: an older `install_openplc.sh` installed Debian's `docker.io` package,
which ships **without** the compose plugin and buildx that the OpenPLC image
build needs.

Fix — install the official Docker stack:

```bash
curl -fsSL https://get.docker.com | sh
# or explicitly:
sudo apt install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
```

The current `install_openplc.sh` uses `get.docker.com` for all Debian-family
hosts and checks for the compose plugin specifically, so a fresh install no
longer hits this. Confirm you have compose:

```bash
docker compose version
```

---

## 4. OpenPLC is "up but not running"

Two variants of the same root cause — the container is running but the PLC
**runtime** inside it is not:

**A. After a reboot: portal shows "Process data acquisition fault", the backend
journal loops `OpenPLC Modbus connected` / `Connecting to OpenPLC Modbus…`
every 500 ms, and `poll failed … Connection reset by peer`.** `check_openplc.py`
passes the TCP connect but gets no Modbus response. The container restarted,
its web UI is up (the only thing in `docker logs` is the health-check's
`GET / → 302`), but OpenPLC v3 only starts the runtime — and with it the Modbus
server on 502 — if "Start OpenPLC in RUN mode" was saved in its settings.
`docker-proxy` on the host still accepts on `127.0.0.1:502`, then resets the
connection because nothing listens inside. Confirm with:

```bash
sudo docker exec s7honeypot-openplc sh -c 'ss -tln | grep :502 || echo "502 closed inside container"'
```

Since this was found, `s7honeypot-openplc.service` runs
`deploy/openplc_autostart.sh` after the container starts: it waits for the web
UI, logs in, sends `start_plc`, and fails the unit unless 502 is listening
inside the container **and** the program's scan counter (HR6) is advancing. So on a current install this variant shows up as the
**openplc unit failed** (`systemctl status s7honeypot-openplc`), which points at
the program itself (variant B / re-upload below). On an install that predates
the hook, start the program by hand once and enable run mode as described next.

**B. Runtime up, program not executing:** port 502 answers, every register
reads `0` and the scan counter never advances. `process_state.json` keeps
getting a fresh timestamp but every tag is `0.0`, and the backend journal is
silent — the bridge's reads *succeed*, they just return zeros. Seen after a
reboot when the runtime came up without a running program. On a current
install `s7honeypot-openplc` fails with `scan counter (HR6) stuck at 0`, and
`check_openplc.py` reports `registers read OK but ALL ZERO`. Fix: upload
`process_sim.st` and start it (below).

### Start the program

```bash
curl -s -c /tmp/plc.jar -L \
     -d "username=openplc&password=openplc" \
     http://127.0.0.1:8080/login -o /dev/null
curl -s -b /tmp/plc.jar http://127.0.0.1:8080/start_plc
sleep 8
# re-check with the scan-counter loop from section 1
```

### Make it permanent — auto-start on boot

This problem recurs after every container restart unless you tell OpenPLC to
start the program automatically. In the OpenPLC web console, go to
**Settings** and enable **"Start PLC in RUN mode at startup"**. Do this once and
the program runs whenever the container starts.

### Reaching the OpenPLC web console remotely

OpenPLC's web UI is bound to loopback only (it is never exposed externally —
that's deliberate). To reach it from your workstation, tunnel over SSH:

```bash
ssh -L 8080:localhost:8080 <user>@<honeypot-ip>
# then browse to:  http://localhost:8080
# login: openplc / openplc
```

### Check the container's own logs

```bash
sudo docker logs s7honeypot-openplc 2>&1 \
    | grep -iE "compil|error|running|start" | tail -15
```

If you see `Compilation finished with errors`, the loaded program is broken or
out of date — re-upload it through the web console (next subsection).

### Re-uploading the process program (if it's corrupt or out of date)

If the loaded ST program looks corrupt — compile errors, values that don't move
correctly, or an older version got deployed — you don't need to rebuild the
container. Re-upload the program through the OpenPLC web console and restart the
PLC:

1. **Get the current program file.** It ships on the honeypot at:

   ```
   /opt/s7honeypot/openplc_program/process_sim.st
   ```

   Copy it to the machine running your browser (the web upload is a
   browser file picker), e.g. from your workstation:

   ```bash
   scp <user>@<honeypot-ip>:/opt/s7honeypot/openplc_program/process_sim.st .
   ```

2. **Open the console** over the SSH tunnel (see above):
   `http://localhost:8080`, login `openplc` / `openplc`.

3. **Stop the PLC** if it's running (dashboard → Stop PLC).

4. **Upload the program.** Go to **Programs → Upload Program**, choose
   `process_sim.st`, and submit. OpenPLC compiles it — watch for a clean
   "Compilation finished" with no errors.

5. **Start the PLC** (dashboard → Start PLC).

6. **Verify** with the scan-counter loop from section 1 — the counter should
   advance and values should move.

This recompiles and reloads just the program, which is lighter than rebuilding
the OpenPLC image. If the upload itself won't take or the compile keeps failing,
fall back to restarting the whole container, which recompiles the
last-uploaded program on start:

```bash
cd /opt/s7honeypot && sudo docker compose -f deploy/docker-compose.yml restart openplc
sleep 25   # allow recompile + reload
```

Remember to re-enable **"Start PLC in RUN mode at startup"** (Settings) if this
is a fresh program load, so it auto-starts on the next container restart.

---

## 5. `check_openplc.py` shows a failure but the system looks fine

`check_openplc.py` opens a fresh connection per register group and reads once.
OpenPLC's Modbus server occasionally times out a single read under load, which
paints a scary red ✗ — even though the honeypot is working.

Confirm it's just transient tool fragility, not a real fault, with the
five-read loop from section 1. If consecutive direct reads succeed and the scan
counter is advancing, **the honeypot is healthy** and the check tool simply hit
one slow response. The bridge, which retries every 500 ms and reconnects on
failure, is far more resilient than the one-shot check tool.

---

## 6. Diagnostic buffer or process overview is empty

### The diagnostic buffer is empty

Almost always a database-path mismatch: the service writing events and the web
portal reading them resolved different paths. Check which database is actually
in use and that it holds events:

```bash
sudo /opt/s7honeypot/venv/bin/python -c "
import sys; sys.path.insert(0, '/opt/s7honeypot/src')
import diag_log, time
from paths import Paths
diag_log._DB_PATH = Paths.load('/opt/s7honeypot/config.yaml').honeypot_db
print('db:', diag_log._DB_PATH)
for ts, d in diag_log.load_events(15):
    print(time.strftime('%H:%M:%S', time.localtime(ts)), d)
"
```

If the database path is under `/tmp`, that's the problem — `/tmp` is cleared on
reboot and, under systemd `PrivateTmp`, is per-service so processes can't share
it. Set `x-state-dir` (and `x-honeypot-db`) in `config.yaml` to a persistent
path such as `/var/lib/s7honeypot`, then restart the services. The honeypot
logs a warning at startup if the database is on `/tmp`.

### The process overview is blank on the web portal

The portal shows the overview only when `process_state.json` is fresh
(< 120 s). Check its age:

```bash
sudo /opt/s7honeypot/venv/bin/python -c "
import json, time
from pathlib import Path
p = Path('/var/lib/s7honeypot/process_state.json')
d = json.loads(p.read_text())
print(f'age {time.time()-d[\"timestamp\"]:.0f}s  cpu_state={d[\"cpu_state\"]}  '
      f'temp={d[\"tags\"].get(\"db200_temperature\")}')
"
```

Fresh (age under a second or two): the writer is running; if the overview is
still blank, restart the web service. Stale (age > 120 s): nothing is writing
it — the bridge or simulator has stopped (section 4 for OpenPLC).

---

## 7. Portal shows "Process data acquisition fault" / values frozen

This is the **watchdog working correctly**, not a bug. In OpenPLC/bridge mode,
if the bridge stops receiving data (OpenPLC down, or its program in STOP) for
longer than the configured threshold (default 60 s), the honeypot freezes the
process values at their last-known state — consistently across the web portal
and S7comm DB reads — and raises this event so an operator monitoring the
device sees a plausible plant fault rather than an empty screen.

Fix the OpenPLC side (section 4). When data resumes, the fault clears
automatically and a "Process data acquisition restored" event is logged.

---

## 8. Fingerprint checks (run from a separate machine)

From your workstation, not the honeypot:

```bash
# Backend port must look like a normal closed port, NOT filtered:
nmap -p 1102 <honeypot-ip>          # expect: closed

# OpenPLC ports must be invisible externally:
nmap -p 502,8080 <honeypot-ip>      # expect: closed/absent

# The S7 identity must be YOUR configured values, not library defaults:
nmap --script s7-info -p 102 <honeypot-ip>
```

If `1102` shows **`filtered`** instead of `closed`, the REJECT rule isn't in
place (a `DROP` or a missing rule produces `filtered`, which itself signals a
firewall is hiding something). Check and re-apply on the honeypot:

```bash
sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh status
# if the 1102 rule is missing or a DROP version is present:
sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh revert
sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh apply
```

`apply` appends rules. Running it while rules are already present leaves
duplicates, so `revert` first whenever any rule is present.

---

## 9. Hardening after a reboot

Fingerprint hardening is applied automatically at boot by
`s7honeypot-harden.service`. Confirm the rules are present:

```bash
sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh status
```

If they're missing after a reboot, the harden service failed — check its
journal:

```bash
sudo journalctl -u s7honeypot-harden --since "10 min ago" --no-pager
```

Re-apply manually with the script, not by restarting the unit (section 2,
Tier 3). If no rules are present, run `apply`. If some rules are present but
others are missing (typically the `DOCKER-USER` ones, when hardening ran
before Docker finished starting), run `revert` then `apply` so nothing ends up
duplicated.

---

## Quick reference

| Symptom | First command |
|---|---|
| Tool says `No module named 'snap7'` | run it under `/opt/s7honeypot/venv/bin/python` |
| Is it working end to end? | `verify_live_db_reads.py --host 127.0.0.1 --port 102` |
| OpenPLC values all zero | scan-counter loop (§1); then start program (§4) |
| OpenPLC stops after every restart | enable "Start in RUN mode at startup" (§4) |
| ST program corrupt / wrong version | re-upload via web console, restart PLC (§4) |
| `check_openplc.py` fails but looks fine | five-read loop (§1) — tool fragility (§5) |
| Diagnostic buffer empty | database-path check (§6) |
| Process overview blank | `process_state.json` age (§6) |
| "acquisition fault" on portal | watchdog; fix OpenPLC (§7) |
| Port 1102 shows `filtered` | `fingerprint_harden.sh revert` then `apply` (§8) |
| Docker/compose build fails | `curl -fsSL https://get.docker.com \| sh` (§3) |
| IP changed, SNMP/web wrong | `systemctl restart s7honeypot-ip-writer` (§2) |
