#!/usr/bin/env bash
# ================================================================
# uninstall.sh — cleanly remove honeypot-s7
# ================================================================
#
# Stops and disables the services, reverts the fingerprint hardening,
# removes the systemd units and the install directory. Captured data in
# the state directory is preserved unless you pass --purge-data.
#
# Usage:
#   sudo bash uninstall.sh [--install-dir /opt/s7honeypot] [--purge-data] [--yes]
# ================================================================

set -euo pipefail

INSTALL_DIR="/opt/s7honeypot"
STATE_DIR="/var/lib/s7honeypot"
PURGE_DATA=0
ASSUME_YES=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --purge-data)  PURGE_DATA=1; shift ;;
        --yes|-y)      ASSUME_YES=1; shift ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"

echo ""
warn "This will remove honeypot-s7 from ${INSTALL_DIR}:"
echo "    - stop and disable all s7honeypot-* services"
echo "    - revert fingerprint hardening (iptables/sysctl)"
echo "    - remove the systemd unit files"
echo "    - delete ${INSTALL_DIR} (including the virtualenv)"
if [[ $PURGE_DATA -eq 1 ]]; then
    echo -e "    - ${RED}DELETE captured data in ${STATE_DIR}${NC} (--purge-data)"
else
    echo "    - PRESERVE captured data in ${STATE_DIR} (pass --purge-data to delete)"
fi
echo ""
if [[ $ASSUME_YES -ne 1 ]]; then
    read -r -p "Proceed? Type 'yes' to confirm: " ans
    [[ "$ans" == "yes" ]] || die "Aborted."
fi

SERVICES=(s7honeypot-harden s7honeypot-synack-spoof s7honeypot-web \
          s7honeypot-snmp s7honeypot-proxy s7honeypot-backend \
          s7honeypot-ip-writer s7honeypot-mac-spoof s7honeypot-openplc)

# ── 1. Stop + disable services ─────────────────────────────────────
info "Stopping and disabling services..."
for svc in "${SERVICES[@]}"; do
    systemctl stop    "${svc}.service" 2>/dev/null || true
    systemctl disable "${svc}.service" 2>/dev/null || true
done

# ── 2. Revert fingerprint hardening while the script still exists ───
if [[ -f "${INSTALL_DIR}/deploy/fingerprint_harden.sh" ]]; then
    info "Reverting fingerprint hardening (iptables/sysctl)..."
    bash "${INSTALL_DIR}/deploy/fingerprint_harden.sh" revert 2>/dev/null || \
        warn "fingerprint_harden.sh revert reported an issue — check iptables manually"
else
    warn "fingerprint_harden.sh not found — revert iptables/sysctl manually if needed"
fi

# ── 3. Stop the OpenPLC container if present ────────────────────────
if [[ -f "${INSTALL_DIR}/deploy/docker-compose.yml" ]] && command -v docker &>/dev/null; then
    info "Stopping OpenPLC container (if running)..."
    docker compose -f "${INSTALL_DIR}/deploy/docker-compose.yml" down 2>/dev/null || true
fi

# ── 4. Remove systemd unit files ───────────────────────────────────
info "Removing systemd unit files..."
for svc in "${SERVICES[@]}"; do
    rm -f "/etc/systemd/system/${svc}.service"
done
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

# ── 5. Remove the install directory ────────────────────────────────
if [[ -d "${INSTALL_DIR}" ]]; then
    info "Removing ${INSTALL_DIR}..."
    rm -rf "${INSTALL_DIR}"
fi

# ── 6. Captured data ───────────────────────────────────────────────
if [[ $PURGE_DATA -eq 1 ]]; then
    if [[ -d "${STATE_DIR}" ]]; then
        warn "Deleting captured data in ${STATE_DIR}..."
        rm -rf "${STATE_DIR}"
    fi
else
    info "Captured data left in place at ${STATE_DIR}"
    info "  (remove manually, or re-run with --purge-data)"
fi

# ── 7. Note on the spoofed MAC ─────────────────────────────────────
warn "The interface MAC may still be spoofed until the next reboot."
warn "  Reboot, or reset it with: sudo macchanger -p <interface>"

echo ""
info "honeypot-s7 removed."
