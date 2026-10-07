#!/usr/bin/env bash
# ================================================================
# install.sh — honeypot-s7 installation
# ================================================================
#
# Installs system + Python dependencies into an isolated virtualenv,
# deploys to /opt/s7honeypot, generates and enables the systemd units.
#
# Usage:
#   sudo bash deploy/install.sh [--install-dir /opt/s7honeypot] [--interface eth0]
#
# Before installation: cp config.yaml.example config.yaml and set
#   x-interface + a unique serial — the units and fingerprint_harden.sh
#   are generated from it.
# After installation (see INSTALL.md → The fast path):
#   1. Optional: sudo bash /opt/s7honeypot/deploy/install_openplc.sh
#   2. sudo reboot   (or start units in order — INSTALL.md Step 4)
#   3. Verify — INSTALL.md Step 5
# ================================================================

set -euo pipefail

INSTALL_DIR="/opt/s7honeypot"
IFACE="eth0"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # repo root (deploy/..)
MIN_PY_MINOR=9   # Python 3.9 floor (PEP 604 unions, PEP 585 generics)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$*"; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --interface)   IFACE="$2";       shift 2 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"

# ── 0. Platform + Python version gate ──────────────────────────────
command -v apt-get &>/dev/null || \
    die "This installer requires a Debian-family system (apt-get not found)."

info "Checking Python version..."
command -v python3 &>/dev/null || die "python3 not found."
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_FULL=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
if [[ "$PY_MAJOR" -ne 3 || "$PY_MINOR" -lt "$MIN_PY_MINOR" ]]; then
    error "Python 3.${MIN_PY_MINOR}+ required; found ${PY_FULL}."
    error "Options: upgrade the OS, build a newer python3 from source, or"
    error "use pyenv/uv to provide Python 3.${MIN_PY_MINOR}+, then re-run."
    die "Unsupported Python version."
fi
info "Python ${PY_FULL} — OK (>= 3.${MIN_PY_MINOR})"

# ── 1. System packages ─────────────────────────────────────────────
info "Installing system packages..."

# tshark's postinst asks an interactive debconf question ("Should
# non-superusers be able to capture packets?"). Under a scripted install
# `apt-get -y` does NOT answer it, so the install hangs waiting for input.
# Preseed the answer (no — services run as root) and force noninteractive.
export DEBIAN_FRONTEND=noninteractive
echo "wireshark-common wireshark-common/install-setuid boolean false" \
    | debconf-set-selections 2>/dev/null || true

# `apt-get update` warns (non-fatal) if an unrelated third-party repo on
# the box is unreachable; only a failure to fetch the main indexes matters,
# and that surfaces as "Unable to locate package" on the install below.
apt-get update -qq || warn "apt-get update reported errors — continuing"
apt-get install -y \
    python3 python3-pip python3-venv python3-dev python-is-python3 \
    python3-yaml build-essential \
    tshark macchanger iptables iproute2 net-tools procps curl git

# python3-netfilterqueue (the SYN-ACK spoofer's NFQUEUE binding) is packaged
# on Debian/Raspberry Pi OS but NOT on every Debian-family release (Ubuntu
# 24.04 lacks it). Try apt first; if absent, build the same module from pip
# inside the venv later (needs libnetfilter-queue-dev + python3-dev).
NFQ_FROM_PIP=0
if apt-get install -y python3-netfilterqueue 2>/dev/null; then
    info "python3-netfilterqueue installed from apt"
else
    warn "python3-netfilterqueue not in apt on this release — will build via pip"
    apt-get install -y libnetfilter-queue-dev
    NFQ_FROM_PIP=1
fi

if command -v python &>/dev/null; then
    info "python -> $(python --version 2>&1)"
else
    warn "python-is-python3 did not create the symlink — creating manually"
    update-alternatives --install /usr/bin/python python /usr/bin/python3 1
fi

if python3 -c 'import sqlite3' 2>/dev/null; then
    info "sqlite3 module present"
else
    die "Python sqlite3 module missing (needed for the diagnostic buffer)."
fi

# ── 2. Deploy application files ─────────────────────────────────────
info "Deploying to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
for d in src deploy tools openplc_program; do
    if [[ -d "${SRC_DIR}/${d}" ]]; then
        mkdir -p "${INSTALL_DIR}/${d}"
        cp -r "${SRC_DIR}/${d}/." "${INSTALL_DIR}/${d}/"
    fi
done
rm -f "${INSTALL_DIR}/deploy/systemd/"*.service 2>/dev/null || true

if [[ ! -f "${INSTALL_DIR}/config.yaml" ]]; then
    if [[ -f "${SRC_DIR}/config.yaml" ]]; then
        cp "${SRC_DIR}/config.yaml" "${INSTALL_DIR}/config.yaml"
    else
        cp "${SRC_DIR}/config.yaml.example" "${INSTALL_DIR}/config.yaml"
        warn "Seeded config.yaml from config.yaml.example — EDIT IT before starting"
    fi
fi
cp "${SRC_DIR}/requirements.txt" "${INSTALL_DIR}/" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/deploy/"*.sh 2>/dev/null || true

# ── 3. Virtualenv + Python packages ────────────────────────────────
# Isolated venv keeps pip packages out of the system Python (PEP 668).
# --system-site-packages lets it use the apt-built netfilterqueue without
# recompiling, while pip installs stay contained.
VENV="${INSTALL_DIR}/venv"
info "Creating virtualenv at ${VENV}..."
python3 -m venv --system-site-packages "${VENV}"

info "Installing Python packages into the virtualenv..."
"${VENV}/bin/pip" install --upgrade pip >/dev/null
"${VENV}/bin/pip" install "python-snap7>=3.0.0" "PyYAML>=6.0"
"${VENV}/bin/pip" install "pymodbus>=3.0.0" || \
    warn "pymodbus not installed — only needed for the OpenPLC bridge"

if [[ "${NFQ_FROM_PIP}" -eq 1 ]]; then
    info "Building NetfilterQueue in the virtualenv (pip)..."
    "${VENV}/bin/pip" install "NetfilterQueue>=1.1.0" || \
        warn "NetfilterQueue pip build failed — SYN-ACK spoofer will not run (see syn_ack_spoofer.py)"
fi
if "${VENV}/bin/python" -c 'import netfilterqueue' 2>/dev/null; then
    info "netfilterqueue imports cleanly in the venv"
else
    warn "netfilterqueue did not import in the venv — s7honeypot-synack-spoof will fail to start"
fi

if "${VENV}/bin/python" -c 'import snap7' 2>/dev/null; then
    info "python-snap7 imports cleanly in the venv"
else
    warn "python-snap7 did not import in the venv — check pip output above"
fi

# ── 4. Generate + install systemd units ────────────────────────────
info "Generating systemd units from config.yaml..."
"${VENV}/bin/python" "${INSTALL_DIR}/deploy/generate_services.py" \
    --config "${INSTALL_DIR}/config.yaml" \
    --install-dir "${INSTALL_DIR}"

info "Installing units to /etc/systemd/system/..."
cp "${INSTALL_DIR}/deploy/systemd/"*.service /etc/systemd/system/
systemctl daemon-reload
for svc in s7honeypot-mac-spoof s7honeypot-ip-writer s7honeypot-backend \
           s7honeypot-proxy s7honeypot-snmp s7honeypot-web \
           s7honeypot-synack-spoof s7honeypot-harden; do
    systemctl enable "${svc}.service" 2>/dev/null && info "enabled ${svc}" \
        || warn "could not enable ${svc}"
done

# ── 5. Runtime state directory ─────────────────────────────────────
mkdir -p /var/lib/s7honeypot
chmod 750 /var/lib/s7honeypot

# ── 6. Summary ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  honeypot-s7 installed to ${INSTALL_DIR}${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Python:  ${PY_FULL}  (venv: ${VENV})"
echo "  Services run under: ${VENV}/bin/python3"
echo ""
echo "  Next steps (full detail: INSTALL.md → The fast path):"
echo "  1. Confirm ${INSTALL_DIR}/config.yaml has the right x-interface and a"
echo "     UNIQUE serial. If you change interface/ports/paths now, see"
echo "     'Changed config after installing' in INSTALL.md before starting."
echo "  2. Optional OpenPLC — do this BEFORE the first start:"
echo "     sudo bash ${INSTALL_DIR}/deploy/install_openplc.sh"
echo "  3. Start everything:  sudo reboot"
echo "     (or start each unit in order — INSTALL.md, Step 4 Option B)"
echo "  4. Verify services, ports and firewall rules — INSTALL.md, Step 5"
echo ""
