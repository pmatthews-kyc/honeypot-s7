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
# After installation:
#   1. nano /opt/s7honeypot/config.yaml        (set interface, identity)
#   2. sudo bash /opt/s7honeypot/deploy/fingerprint_harden.sh apply
#   3. sudo systemctl start s7honeypot-proxy
#   Optional (OpenPLC process engine — installs Docker separately):
#   4. sudo bash /opt/s7honeypot/deploy/install_openplc.sh
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

apt-get update -qq
apt-get install -y \
    python3 python3-pip python3-venv python-is-python3 \
    python3-yaml python3-netfilterqueue build-essential \
    tshark macchanger iptables iproute2 net-tools procps curl git

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
echo "  Next steps:"
echo "  1. nano ${INSTALL_DIR}/config.yaml   (interface + UNIQUE serial/identity)"
echo "  2. sudo bash ${INSTALL_DIR}/deploy/fingerprint_harden.sh apply"
echo "     (also runs automatically at every boot via s7honeypot-harden.service)"
echo "  3. sudo systemctl start s7honeypot-proxy"
echo ""
echo "  If you change interface/paths in config, re-generate the units:"
echo "     sudo ${VENV}/bin/python ${INSTALL_DIR}/deploy/generate_services.py \\"
echo "         --install-dir ${INSTALL_DIR}"
echo "     sudo cp ${INSTALL_DIR}/deploy/systemd/*.service /etc/systemd/system/"
echo "     sudo systemctl daemon-reload"
echo ""
echo "  Optional OpenPLC engine (installs Docker itself when run):"
echo "     sudo bash ${INSTALL_DIR}/deploy/install_openplc.sh"
echo ""
