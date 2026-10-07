#!/usr/bin/env bash
# =====================================================================
# openplc_autostart.sh — force the OpenPLC runtime into RUN after the
# container starts.
#
# WHY: OpenPLC v3 restarts its *web UI* when the container comes back up,
# but the PLC runtime (and with it the Modbus server on 502) only starts
# if "Start OpenPLC in RUN mode" was saved in its settings. After a reboot
# with that unset, the container is healthy, docker-proxy accepts on
# 127.0.0.1:502, and every bridge read gets "Connection reset by peer" —
# the honeypot portal shows "Process data acquisition fault" and nothing
# moves. Seen in the field on the first reboot after install_openplc.sh.
#
# Run by s7honeypot-openplc.service as ExecStartPost (install_openplc.sh
# writes that unit). Idempotent: starting an already-running PLC is a
# no-op. Exits non-zero unless BOTH (a) Modbus 502 is listening inside the
# container and (b) the program's scan counter (holding register 6 in
# process_sim.st) is advancing — so the unit fails loudly instead of
# leaving a silent fault. (b) matters: after one reboot in the field the
# runtime answered on 502 with every register at zero because no program
# was executing, and the portal froze with no error anywhere.
#
#   sudo bash openplc_autostart.sh            # manual run is fine too
# =====================================================================
set -uo pipefail

OPENPLC_URL="${OPENPLC_URL:-http://127.0.0.1:8080}"
OPENPLC_USER="${OPENPLC_USER:-openplc}"
OPENPLC_PASS="${OPENPLC_PASS:-openplc}"
CONTAINER="${OPENPLC_CONTAINER:-s7honeypot-openplc}"
UI_WAIT="${OPENPLC_UI_WAIT:-120}"      # seconds to wait for the web UI
MODBUS_WAIT="${OPENPLC_MODBUS_WAIT:-45}" # seconds to wait for 502 after start
SCAN_WAIT="${OPENPLC_SCAN_WAIT:-30}"   # seconds to wait for the scan counter to move
SCAN_REG="${OPENPLC_SCAN_REG:-6}"      # HR holding the scan counter (%QW6 in process_sim.st)
MB_HOST="${OPENPLC_MODBUS_HOST:-127.0.0.1}"
MB_PORT="${OPENPLC_MODBUS_PORT:-502}"
COOKIE_JAR="$(mktemp /tmp/openplc_autostart_XXXXXX)"
trap 'rm -f "$COOKIE_JAR"' EXIT

log() { echo "[openplc-autostart] $*"; }

# ── 1. Wait for the web UI ──────────────────────────────────────────
waited=0
until curl -sf --max-time 3 "$OPENPLC_URL" >/dev/null 2>&1; do
    if (( waited >= UI_WAIT )); then
        log "ERROR: OpenPLC web UI not answering on ${OPENPLC_URL} after ${UI_WAIT}s"
        exit 1
    fi
    sleep 5; (( waited += 5 ))
done
log "web UI up after ${waited}s"

# ── 2. Already running? (502 listening INSIDE the container) ───────
modbus_up() {
    # ss may be absent in the image; fall back to /proc/net/tcp (port 0x01F6)
    docker exec "$CONTAINER" sh -c \
        'command -v ss >/dev/null 2>&1 && ss -tln | grep -q ":502 " \
         || grep -qi ":01F6 " /proc/net/tcp' 2>/dev/null
}
# Read the scan-counter holding register over raw Modbus TCP (host side,
# through docker-proxy). Prints the value, or nothing on any failure.
scan_counter() {
    python3 - "$MB_HOST" "$MB_PORT" "$SCAN_REG" <<'PYEOF' 2>/dev/null
import socket, struct, sys
host, port, reg = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
try:
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(struct.pack(">HHHBBHH", 7, 0, 6, 1, 3, reg, 1))
        r = b""
        while len(r) < 11:
            c = s.recv(11 - len(r))
            if not c: break
            r += c
    if len(r) == 11 and r[7] == 3:
        print(struct.unpack(">H", r[9:11])[0])
except Exception:
    pass
PYEOF
}

# True if the scan counter changes across a 2 s window. Records the last
# value seen in SCAN_LAST for the error message.
SCAN_LAST=""
program_running() {
    local a b
    a="$(scan_counter)"; sleep 2; b="$(scan_counter)"
    SCAN_LAST="${b:-no reply}"
    [[ -n "$a" && -n "$b" && "$a" != "$b" ]]
}

if modbus_up && program_running; then
    log "PLC program already executing (scan counter ${SCAN_LAST}) — nothing to do"
    exit 0
fi

# ── 3. Log in and send start ───────────────────────────────────────
# -L follows the post-login redirect so the session cookie is captured.
if ! curl -sf --max-time 10 -L -c "$COOKIE_JAR" \
        -d "username=${OPENPLC_USER}&password=${OPENPLC_PASS}" \
        "${OPENPLC_URL}/login" -o /dev/null; then
    log "ERROR: login to OpenPLC failed"
    exit 1
fi
log "sending start_plc"
curl -sf --max-time 10 -b "$COOKIE_JAR" "${OPENPLC_URL}/start_plc" >/dev/null 2>&1 || true

# ── 4. Confirm the runtime actually came up ────────────────────────
waited=0
until modbus_up; do
    if (( waited >= MODBUS_WAIT )); then
        log "ERROR: sent start_plc but 502 never opened inside ${CONTAINER} after ${MODBUS_WAIT}s"
        log "       the uploaded program may be missing or failed to compile —"
        log "       see docs/TROUBLESHOOTING.md §4 (re-upload process_sim.st)"
        exit 1
    fi
    sleep 3; (( waited += 3 ))
done
log "PLC runtime running — Modbus 502 listening in container (${waited}s)"

# ── 5. Confirm the PROGRAM is executing, not just the Modbus server ─
waited=0
until program_running; do
    if (( waited >= SCAN_WAIT )); then
        log "ERROR: runtime is up but the program is NOT executing —"
        log "       scan counter (HR${SCAN_REG}) stuck at ${SCAN_LAST} for ${SCAN_WAIT}s."
        log "       The bridge would copy zeros and the portal would freeze."
        log "       Fix: OpenPLC UI -> Programs -> upload process_sim.st -> Launch,"
        log "       then Start PLC. See docs/TROUBLESHOOTING.md §4."
        exit 1
    fi
    (( waited += 2 ))
done
log "PLC program executing — scan counter advancing (now ${SCAN_LAST})"
exit 0
