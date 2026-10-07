#!/usr/bin/env bash
# ================================================================
# install_openplc.sh — OpenPLC v3 Docker Setup for S7 Honeypot
# ================================================================
#
# WHAT THIS SCRIPT DOES
# ---------------------
# 1. Verifies Docker is installed (installs if missing on Debian/RPi)
# 2. Builds the OpenPLC v3 Docker image from source
# 3. Starts the OpenPLC container via docker-compose
# 4. Waits for OpenPLC to be ready (polls web UI on port 8080)
#    and installs openplc_autostart.sh as ExecStartPost so the PLC
#    runtime is forced into RUN at every container start / reboot
# 5. Uploads the self-driven process_sim.st program via the
#    OpenPLC AJAX API
# 6. Starts the uploaded program
# 7. Updates config.yaml to enable x-openplc and x-modbus-bridge
# 8. Prints instructions for restarting the honeypot
#
# USAGE
# -----
#   cd /opt/s7honeypot          # or wherever you installed the honeypot
#   sudo bash install_openplc.sh
#
# REQUIREMENTS
# ------------
#   - Raspberry Pi or Debian/Ubuntu x86_64
#   - Root or sudo access
#   - Internet access (to clone OpenPLC v3 from GitHub)
#   - S7 honeypot already installed at INSTALL_DIR
#
# ================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────
# This script lives in <install-root>/deploy/. Resolve BOTH the deploy dir
# (where docker-compose.yml sits, next to this script) and the install root
# (where config.yaml and openplc_program/ live, one level up). Before the
# src/deploy/ restructure these were the same directory; they no longer are.
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$(cd "${DEPLOY_DIR}/.." && pwd)"
COMPOSE_FILE="${DEPLOY_DIR}/docker-compose.yml"
OPENPLC_REPO="https://github.com/thiagoralves/OpenPLC_v3.git"
OPENPLC_IMAGE="openplc:v3"
OPENPLC_URL="http://127.0.0.1:8080"
OPENPLC_USER="openplc"
OPENPLC_PASS="openplc"
PROGRAM_FILE="${INSTALL_DIR}/openplc_program/process_sim.st"
CONFIG_FILE="${INSTALL_DIR}/config.yaml"
COOKIE_JAR="/tmp/openplc_cookies_$$.txt"
PROGRAM_OK=0

# Colour output
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$*"; exit 1; }

# ── Prerequisite checks ────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use: sudo bash $0)"
    fi
}

check_files() {
    [[ -f "$PROGRAM_FILE" ]] || die "Program file not found: $PROGRAM_FILE"
    [[ -f "$CONFIG_FILE" ]]  || die "Config file not found: $CONFIG_FILE"
    [[ -f "${COMPOSE_FILE}" ]] \
        || die "docker-compose.yml not found at ${COMPOSE_FILE}"
}

# ── Docker installation ────────────────────────────────────────────
install_docker() {
    if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
        info "Docker + compose plugin already installed: $(docker --version)"
        return 0
    fi

    info "Installing Docker (official docker-ce stack)..."
    # Use Docker's official convenience script for ALL Debian-family platforms
    # (Raspberry Pi OS, Debian, Ubuntu). It installs the full, current stack:
    #   docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    #
    # The previous version installed Debian's `docker.io` package on non-Pi
    # hosts, which ships an older Docker WITHOUT the compose plugin or buildx —
    # so `docker compose build` (used to build the OpenPLC image) failed and
    # required a manual `apt install docker-ce ...` afterward. get.docker.com
    # avoids that on every Debian-family host, not just the Pi.
    if command -v curl &>/dev/null; then
        curl -fsSL https://get.docker.com | sh
    else
        apt-get update -qq && apt-get install -y curl
        curl -fsSL https://get.docker.com | sh
    fi

    # Sanity check: the compose plugin must be present (the OpenPLC build/run
    # both use `docker compose`). If get.docker.com somehow didn't provide it,
    # install the plugin explicitly rather than failing later mid-build.
    if ! docker compose version &>/dev/null 2>&1; then
        warn "compose plugin missing after install — adding docker-compose-plugin"
        apt-get install -y docker-compose-plugin 2>/dev/null || \
            warn "could not install docker-compose-plugin; install it manually: "\
                 "sudo apt install docker-compose-plugin"
    fi

    systemctl enable docker 2>/dev/null || true
    systemctl start docker  2>/dev/null || true
    info "Docker installed: $(docker --version)"

    # Harden: remove the invoking (non-root) user from the docker group so
    # /var/run/docker.sock can't be used for local privilege escalation if the
    # host is compromised. The OpenPLC service runs as root and doesn't need it.
    # get.docker.com adds the SUDO_USER to the docker group; undo that.
    if [[ -n "${SUDO_USER:-}" ]]; then
        gpasswd -d "${SUDO_USER}" docker 2>/dev/null || true
        info "Removed '${SUDO_USER}' from docker group (docker.sock hardening)"
    fi
    gpasswd -d pi docker 2>/dev/null || true
}

check_docker_compose() {
    # Prefer 'docker compose' (v2 plugin) over standalone 'docker-compose'
    if docker compose version &>/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        info "Installing docker-compose-plugin..."
        apt-get install -y docker-compose-plugin 2>/dev/null || \
            pip3 install docker-compose --break-system-packages 2>/dev/null || \
            die "Could not install docker-compose. Install it manually."
        COMPOSE_CMD="docker compose"
    fi
    # Always pass -f so the compose file is found regardless of cwd.
    COMPOSE_CMD="${COMPOSE_CMD} -f ${COMPOSE_FILE}"
    info "Using compose command: $COMPOSE_CMD"
}

# ── Build OpenPLC image ────────────────────────────────────────────
build_openplc_image() {
    if docker image inspect "$OPENPLC_IMAGE" &>/dev/null; then
        info "OpenPLC image '$OPENPLC_IMAGE' already exists — skipping build"
        info "To rebuild: docker rmi $OPENPLC_IMAGE && sudo bash $0"
        return 0
    fi

    info "Building OpenPLC v3 Docker image (this takes 5-15 minutes)..."
    warn "Cloning from: $OPENPLC_REPO"

    BUILD_DIR=$(mktemp -d)
    trap "rm -rf $BUILD_DIR" EXIT

    git clone --depth 1 "$OPENPLC_REPO" "$BUILD_DIR/OpenPLC_v3"

    docker build \
        --tag "$OPENPLC_IMAGE" \
        --build-arg INSTALL_PLATFORM=docker \
        --file "$BUILD_DIR/OpenPLC_v3/Dockerfile" \
        "$BUILD_DIR/OpenPLC_v3"

    info "OpenPLC image built successfully"
}

# ── Container lifecycle ────────────────────────────────────────────
start_container() {
    info "Starting OpenPLC container..."
    $COMPOSE_CMD up -d openplc
    info "Container started"
}

wait_for_openplc() {
    info "Waiting for OpenPLC web UI to be ready (up to 90 seconds)..."
    local max_wait=90
    local waited=0
    local interval=5

    while ! curl -sf --max-time 3 "$OPENPLC_URL" &>/dev/null; do
        if [[ $waited -ge $max_wait ]]; then
            error "OpenPLC did not start within ${max_wait}s"
            error "Check logs: $COMPOSE_CMD logs openplc"
            die "OpenPLC startup timeout"
        fi
        printf "."
        sleep $interval
        ((waited += interval))
    done
    echo ""
    info "OpenPLC web UI is up (${waited}s)"
}

# ── Program management via OpenPLC AJAX API ────────────────────────
openplc_login() {
    info "Logging in to OpenPLC..."
    # -L follows the redirect after POST /login so the session cookie
    # is captured from the final dashboard response, not the 302 itself
    curl -sf --max-time 10 -L \
        -c "$COOKIE_JAR" \
        -d "username=${OPENPLC_USER}&password=${OPENPLC_PASS}" \
        "${OPENPLC_URL}/login" -o /dev/null
    info "Logged in"
}

upload_program() {
    info "Uploading process_sim.st to OpenPLC..."

    local response
    response=$(curl -sf --max-time 30 \
        -b "$COOKIE_JAR" \
        -F "file=@${PROGRAM_FILE};type=text/plain" \
        -F "file_name=process_sim" \
        -F "file_description=S7 Honeypot self-driven process simulation" \
        "${OPENPLC_URL}/upload-program" 2>&1) || true

    info "Program upload submitted"
    # Give OpenPLC time to compile the ST program (~5-10 seconds)
    info "Waiting 15 seconds for compilation..."
    sleep 15
}

set_run_mode_setting() {
    # Persist "Start OpenPLC in RUN mode" inside the container's settings
    # DB so the runtime also auto-starts on its own, independent of
    # openplc_autostart.sh. Best effort: the autostart hook is the real
    # guarantee; this just makes the UI checkbox agree with it.
    info "Enabling 'Start OpenPLC in RUN mode' in OpenPLC settings..."
    docker exec s7honeypot-openplc python3 - <<'PYEOF' 2>/dev/null \
        && info "Run-mode setting enabled" \
        || warn "Could not set run-mode flag (openplc_autostart.sh still forces RUN at every start)"
import sqlite3, glob, sys
paths = glob.glob("/workdir/webserver/*.db") + glob.glob("/**/webserver/openplc.db", recursive=True)
for p in paths:
    try:
        c = sqlite3.connect(p)
        n = c.execute("UPDATE Settings SET Value='true' WHERE Key='Start_run_mode'").rowcount
        c.commit(); c.close()
        if n:
            sys.exit(0)
    except Exception:
        pass
sys.exit(1)
PYEOF
}

start_program() {
    info "Starting PLC program..."
    curl -sf --max-time 10 \
        -b "$COOKIE_JAR" \
        "${OPENPLC_URL}/start_plc" >/dev/null 2>&1 || true
    sleep 3
    info "PLC program start signal sent"
}

verify_modbus() {
    # Same check the boot unit runs: 502 listening inside the container AND
    # the scan counter advancing. An open port alone is not enough — the
    # runtime can answer with every register at zero when no program runs.
    info "Verifying the PLC program is executing (Modbus 502 + scan counter)..."
    if bash "${DEPLOY_DIR}/openplc_autostart.sh"; then
        PROGRAM_OK=1
        info "process_sim is executing — Modbus values are live"
    else
        PROGRAM_OK=0
        warn "The PLC program is NOT executing yet."
        warn "Follow 'FINISH IN THE OPENPLC UI' in the summary below."
    fi

    # Verify Docker daemon is NOT listening on TCP (would be a remote root)
    info "Verifying Docker daemon is NOT exposed on TCP..."
    if ss -tlnp 2>/dev/null | grep -q ':2375\|:2376'; then
        error "Docker daemon is listening on TCP (port 2375/2376)!"
        error "This gives remote root access. Fix /etc/docker/daemon.json:"
        error "  Remove any 'tcp://' entries from the 'hosts' key"
        error "  Then: systemctl restart docker"
    else
        info "Docker daemon: Unix socket only (no TCP exposure)"
    fi
}

cleanup_cookies() {
    rm -f "$COOKIE_JAR"
}

# ── Config.yaml update ─────────────────────────────────────────────
update_config() {
    info "Updating config.yaml to enable OpenPLC + Modbus bridge..."

    # Use Python for safe YAML-aware sed (handles anchors correctly)
    python3 - "$CONFIG_FILE" << 'PYEOF'
import sys
path = sys.argv[1]
content = open(path).read()

# Update x-openplc anchor
content = content.replace(
    "x-openplc:        &openplc_enabled        false",
    "x-openplc:        &openplc_enabled        true"
)
# Update x-modbus-bridge anchor
content = content.replace(
    "x-modbus-bridge:  &modbus_bridge_enabled  false",
    "x-modbus-bridge:  &modbus_bridge_enabled  true"
)

open(path, 'w').write(content)
print("config.yaml updated")
PYEOF

    # Verify the changes
    if grep -q "x-openplc:.*true" "$CONFIG_FILE" && \
       grep -q "x-modbus-bridge:.*true" "$CONFIG_FILE"; then
        info "config.yaml: x-openplc and x-modbus-bridge both set to true"
    else
        warn "Could not verify config.yaml changes — check manually"
        warn "Set x-openplc: true and x-modbus-bridge: true in $CONFIG_FILE"
    fi
}

# ── Systemd service management ─────────────────────────────────────
restart_honeypot() {
    info "Restarting honeypot services to pick up new config..."
    local services=("s7honeypot-backend" "s7honeypot-proxy")
    local any_restarted=false

    for svc in "${services[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl restart "$svc"
            info "Restarted: $svc"
            any_restarted=true
        fi
    done

    if [[ "$any_restarted" == "false" ]]; then
        warn "No honeypot systemd services are running"
        warn "Start them manually or re-run the honeypot setup"
    fi
}

# ── Docker startup service (survive reboot) ────────────────────────
install_docker_startup() {
    info "Creating systemd service for OpenPLC Docker container..."

    cat > /etc/systemd/system/s7honeypot-openplc.service << EOF
[Unit]
Description=S7 Honeypot OpenPLC Process Engine (Docker)
Documentation=https://github.com/thiagoralves/OpenPLC_v3
After=docker.service network-online.target
Requires=docker.service
Before=s7honeypot-backend.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${DEPLOY_DIR}
ExecStart=/usr/bin/docker compose -f ${COMPOSE_FILE} up -d openplc
# The container coming up does NOT start the PLC runtime (and so Modbus
# 502) unless OpenPLC's "start in RUN mode" setting is saved. Force it
# every start; fails the unit if 502 never opens inside the container.
ExecStartPost=/bin/bash ${DEPLOY_DIR}/openplc_autostart.sh
ExecStop=/usr/bin/docker compose -f ${COMPOSE_FILE} stop openplc
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable s7honeypot-openplc.service
    info "systemd service installed: s7honeypot-openplc.service"
    info "OpenPLC will start automatically on next boot"
}

# ── Summary ────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  OpenPLC installation complete                        ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    if [[ "${PROGRAM_OK}" -eq 1 ]]; then
        echo -e "  Program status: ${GREEN}process_sim EXECUTING${NC} (scan counter advancing)"
    else
        echo -e "  Program status: ${RED}NOT EXECUTING${NC} — do steps 1–3 below now"
    fi
    echo ""
    echo "  ── FINISH IN THE OPENPLC UI (do this once, even if status is OK) ──"
    echo ""
    echo "  The OpenPLC web UI listens on the Pi's loopback only. From your"
    echo "  workstation, open a tunnel and browse to it:"
    echo ""
    echo "      ssh -L 8080:localhost:8080 ${SUDO_USER:-<user>}@<honeypot-ip>"
    echo "      http://localhost:8080          login: openplc / openplc"
    echo ""
    echo "  1. Upload the process program (skip if the Dashboard already shows"
    echo "     'process_sim' and Status: Running):"
    echo "       Programs -> Upload Program -> choose process_sim.st"
    echo "       (copy it from ${PROGRAM_FILE}"
    echo "        or from openplc_program/ in the release zip)"
    echo "       -> Upload Program -> Launch program -> wait for"
    echo "       'Compilation finished successfully'."
    echo ""
    echo "  2. Start it:  Dashboard -> Start PLC"
    echo ""
    echo "  3. Make it start on every boot:"
    echo "       Settings -> tick 'Start OpenPLC in RUN mode' -> Save changes"
    echo "     (s7honeypot-openplc.service also forces RUN at each start via"
    echo "      openplc_autostart.sh, and FAILS the unit if the program isn't"
    echo "      executing — so a bad program shows up in systemctl, not as a"
    echo "      frozen portal.)"
    echo ""
    echo "  Confirm from the Pi:"
    echo "      sudo ${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/tools/check_openplc.py ${CONFIG_FILE}"
    echo "      sudo cat /var/lib/s7honeypot/process_state.json   # marker_cycle_count climbing"
    echo ""
    echo "  ── WHAT process_sim DOES ──"
    echo "    Temperature: heater holds ~30 °C (±0.5 °C hysteresis)"
    echo "    Flow:        0 -> 120 l/min while the pump runs, 0 when stopped"
    echo "    Pressure:    3.1 -> 6.2 bar following pump state"
    echo "    Level:       drains while pumping, refills when idle"
    echo "    Sequencer:   IDLE -> STARTING -> RUNNING -> STOPPING (HR5)"
    echo "    Scan count:  HR6, increments every scan"
    echo ""
    echo "  Modbus TCP: 127.0.0.1:502 (loopback only — absent from external scans)"
    echo "  Container logs: docker logs s7honeypot-openplc --tail 40"
    echo ""
    echo "  To disable OpenPLC and revert to the built-in simulator:"
    echo "    1. Set x-openplc: false and x-modbus-bridge: false in config.yaml"
    echo "    2. sudo systemctl disable --now s7honeypot-openplc"
    echo "    3. sudo systemctl restart s7honeypot-backend"
    echo ""
}

# ── Main ───────────────────────────────────────────────────────────
main() {
    echo ""
    echo "S7 Honeypot — OpenPLC v3 Docker Setup"
    echo "======================================"
    echo ""
    echo "OpenPLC runs in Docker. This script installs Docker Engine and the"
    echo "compose plugin if they are not already present — you do NOT need to"
    echo "install Docker separately. It then builds the OpenPLC v3 image,"
    echo "uploads the process program, and wires up the bridge."
    echo ""

    check_root
    check_files
    install_docker
    check_docker_compose
    build_openplc_image
    start_container
    wait_for_openplc
    openplc_login
    upload_program
    start_program
    set_run_mode_setting
    verify_modbus
    cleanup_cookies
    update_config
    install_docker_startup
    restart_honeypot
    print_summary
}

main "$@"
