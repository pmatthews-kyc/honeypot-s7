#!/usr/bin/env bash
#
# fingerprint_harden.sh
# ----------------------
# Reduces the gap between "this is obviously an Ubuntu/Linux box" and "this
# looks like an embedded Siemens PLC stack" for passive/active OS
# fingerprinting (Nmap -O, p0f, and similar TTL/window/options-based
# guessing). This operates BELOW the S7comm application layer -- it doesn't
# touch anything in honeypot.py/backend_server.py, it just makes the raw
# TCP/IP behavior of the box less Linux-shaped.
#
# WHAT THIS DOES:
#   - Rewrites TTL on outbound packets from port 102 to a target value
#   - Tunes a handful of sysctl TCP parameters that factor into passive
#     fingerprinting (timestamps, SACK, window scaling)
#
# WHAT THIS DOES NOT DO:
#   - It does NOT reorder TCP options in the SYN-ACK, which is one of the
#     stronger signals p0f/Nmap use. Getting that exactly right requires
#     bypassing the kernel stack for this port and hand-crafting SYN-ACKs
#     (e.g. with scapy or a raw-socket responder) -- real additional work,
#     out of scope here. Treat this script as "closes the cheap, high-value
#     gaps," not "achieves a perfect stack fingerprint."
#   - It does NOT verify the target TTL/window values against a real
#     Siemens unit -- the defaults below are common embedded-stack values
#     referenced in public ICS fingerprinting research, not confirmed
#     against a specific device. CONFIRM AGAINST A REAL UNIT OR PUBLISHED
#     CAPTURE if device-class accuracy matters for your use case, and edit
#     the variables below accordingly.
#
# Usage:
#   sudo ./fingerprint_harden.sh apply     # apply rules + sysctl changes
#   sudo ./fingerprint_harden.sh revert    # remove rules, restore defaults
#   sudo ./fingerprint_harden.sh status    # show current state
#
# Persistence: iptables rules added here do NOT survive reboot on their
# own. Either call this script from a systemd unit / cron @reboot, or
# install `iptables-persistent` (Ubuntu/Debian) and run
# `netfilter-persistent save` after `apply`.

set -euo pipefail

# ---- Config: values read from config.yaml by generate_services.py ---------
S7_PORT=102
BACKEND_PORT=1102
TARGET_TTL=30   # IP TTL the honeypot presents. Real S7-300 = 30.
                        # (Linux default is 64, so leaving this at 64 would
                        # present a Linux TTL — a fingerprint.) Set via
                        # x-target-ttl in config.yaml.
IFACE="ens33"        # NIC serving the honeypot  (x-interface in config.yaml)

MANGLE_COMMENT="s7honeypot-fingerprint"
FILTER_COMMENT="s7honeypot-backend-isolation"
SYNACK_COMMENT="s7honeypot-synack-spoof"
SYNACK_QUEUE=42

apply() {
    echo "[*] Isolating backend port ${BACKEND_PORT} to loopback (REJECT, not DROP)..."
    # snap7.Server.start() takes no host/bind-address parameter at all
    # (confirmed against the real installed library on target hardware --
    # its signature is just start(self, tcp_port=102)), so there is NO
    # API-level way to force it to bind loopback-only. Whatever interface
    # it actually binds internally is outside this project's control.
    # This firewall rule is the actual guarantee: block any connection to
    # BACKEND_PORT that didn't originate on loopback.
    #
    # WHY REJECT WITH tcp-reset, NOT DROP:
    # DROP silently discards the probe, so nmap reports the port as
    # "filtered" -- which announces "a firewall is deliberately hiding
    # something here". A real S7-315 has no service on this port at all,
    # and a probe to a genuinely unused port gets a TCP RST from the
    # kernel, so nmap reports "closed". REJECT --reject-with tcp-reset
    # sends that same RST, making 1102 indistinguishable from any other
    # closed port on real hardware. "filtered" is a stronger fingerprint
    # than "closed", so DROP was the more revealing choice.
    iptables -A INPUT -p tcp --dport "${BACKEND_PORT}" ! -i lo \
        -j REJECT --reject-with tcp-reset \
        -m comment --comment "${FILTER_COMMENT}"

    echo "[*] Routing port-${S7_PORT} SYN-ACK through syn_ack_spoofer..."
    # Sends outgoing SYN-ACK packets from port 102 to nfqueue where
    # syn_ack_spoofer.py rewrites window=1024 and strips TCP options to
    # MSS-only -- the two fingerprint signals sysctl tuning cannot reach.
    # syn_ack_spoofer.py daemon must be running (see systemd unit).
    iptables -I OUTPUT -p tcp --sport "${S7_PORT}" \
        --tcp-flags SYN,ACK SYN,ACK \
        -j NFQUEUE --queue-num "${SYNACK_QUEUE}" --queue-bypass \
        -m comment --comment "${SYNACK_COMMENT}"
    # --queue-bypass: if the spoofer daemon is not running, SYN-ACK
    # packets pass through unmodified rather than being silently dropped
    # by the kernel. Without this, a crashed or not-yet-started daemon
    # breaks all S7comm connections with no error message.

    echo "[*] Tuning TCP sysctl parameters..."
    # Many embedded/RTOS TCP stacks (including older Siemens firmware)
    # don't support TCP timestamps or SACK, and use conservative/fixed
    # window scaling -- all of which show up distinctly in a passive
    # fingerprint (p0f, Nmap) versus a stock Linux stack that has all of
    # these enabled by default.
    sysctl -w net.ipv4.tcp_timestamps=0
    sysctl -w net.ipv4.tcp_sack=0
    sysctl -w net.ipv4.tcp_window_scaling=0

    # TTL: rewrite outbound TTL to the S7-300 value on the honeypot interface
    # via mangle, NOT via the global net.ipv4.ip_default_ttl sysctl. The
    # global sysctl would change the TTL of ALL host traffic — including this
    # box's own SSH/DNS/apt — which is undesirable and can surprise the
    # operator. The mangle rules below scope the TTL rewrite to traffic
    # leaving on the honeypot NIC, covering TCP (the S7/web/SNMP services)
    # AND ICMP (so `ping` shows TTL 30, not the Linux 64 — otherwise the
    # echo reply, which doesn't originate from port 102, would leak Linux).
    echo "[*] Rewriting outbound TTL to ${TARGET_TTL} on ${IFACE} (TCP + ICMP + UDP)..."
    iptables -t mangle -A POSTROUTING -o "${IFACE}" -p tcp \
        -j TTL --ttl-set "${TARGET_TTL}" \
        -m comment --comment "${MANGLE_COMMENT}-ttl-tcp"
    iptables -t mangle -A POSTROUTING -o "${IFACE}" -p icmp \
        -j TTL --ttl-set "${TARGET_TTL}" \
        -m comment --comment "${MANGLE_COMMENT}-ttl-icmp"
    # UDP too: SNMP replies otherwise leave with the Linux TTL (64) while
    # TCP and ICMP show 30 -- a mismatch no real device produces.
    iptables -t mangle -A POSTROUTING -o "${IFACE}" -p udp \
        -j TTL --ttl-set "${TARGET_TTL}" \
        -m comment --comment "${MANGLE_COMMENT}-ttl-udp"

    # ── Disable IPv6 ────────────────────────────────────────────────────
    # A real S7-300 (CPU 315-2 PN/DP and its generation) is IPv4-only — its
    # firmware predates IPv6 support in that CPU class. Modern Linux, by
    # contrast, auto-configures an IPv6 link-local address, answers Neighbor
    # Discovery, and responds to ping6 by default. A device that responds on
    # IPv6 AT ALL is therefore immediately inconsistent with claiming to be an
    # S7-300 — a binary tell. We disable IPv6 entirely (the realistic behavior
    # for this device is to be absent from IPv6), via sysctl plus an ip6tables
    # backstop. Reversed cleanly by `revert`.
    echo "[*] Disabling IPv6 (a real S7-300 is IPv4-only)..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=1      >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=1  >/dev/null 2>&1 || true
    sysctl -w "net.ipv6.conf.${IFACE}.disable_ipv6=1" >/dev/null 2>&1 || true
    # Backstop: drop all IPv6 in/out even if the stack comes back up somehow.
    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT   DROP 2>/dev/null || true
        ip6tables -P OUTPUT  DROP 2>/dev/null || true
        ip6tables -P FORWARD DROP 2>/dev/null || true
    fi

    # ── OpenPLC Docker isolation (belt-and-suspenders) ──────────────────
    # docker-compose.yml binds OpenPLC ports to 127.0.0.1 (loopback).
    # However, Docker inserts rules into its own DOCKER chain BEFORE the
    # INPUT chain, so a standard 'iptables -A INPUT ... -j DROP' does NOT
    # reliably block Docker-forwarded traffic on some kernel/Docker versions.
    # The DOCKER-USER chain IS processed before DOCKER and is the correct
    # place to block Docker-specific traffic from external interfaces.
    #
    # Additionally, Docker's MASQUERADE rule allows containers to make
    # outbound connections through the external NIC — the container could
    # scan other ICS hosts or reach the internet. The second rule below
    # blocks all outbound container traffic on the external interface.
    # This does NOT affect the modbus_bridge connection because that goes
    # host → 127.0.0.1 → docker0 → container (never through ens33).
    #
    # These rules are no-ops when OpenPLC is not installed (DOCKER-USER
    # chain won't exist), so they are safe to always include.
    if iptables -L DOCKER-USER -n &>/dev/null 2>&1; then
        echo "[*] Blocking OpenPLC Docker ports on external interface (DOCKER-USER)..."
        # Inbound ports use REJECT --reject-with tcp-reset (not DROP) for the
        # same reason as BACKEND_PORT above: DROP -> nmap "filtered" (a tell
        # that a firewall is hiding something); REJECT -> "closed", which is
        # how any unused port looks on real hardware.
        # Block inbound Modbus TCP (502) from external NIC
        iptables -I DOCKER-USER -i "${IFACE}" -p tcp --dport 502 \
            -j REJECT --reject-with tcp-reset \
            -m comment --comment "${MANGLE_COMMENT}-docker-modbus" 2>/dev/null || true
        # Block inbound OpenPLC v3 web IDE (8080) from external NIC
        iptables -I DOCKER-USER -i "${IFACE}" -p tcp --dport 8080 \
            -j REJECT --reject-with tcp-reset \
            -m comment --comment "${MANGLE_COMMENT}-docker-ide" 2>/dev/null || true
        # Outbound container traffic uses DROP, not REJECT: this blocks a
        # (potentially compromised) container from reaching the ICS network,
        # and we deliberately give it NO feedback -- silent black-hole is
        # correct for egress containment, unlike the inbound case.
        iptables -I DOCKER-USER -i docker0 -o "${IFACE}" -j DROP \
            -m comment --comment "${MANGLE_COMMENT}-docker-egress" 2>/dev/null || true
        echo "[*] DOCKER-USER rules applied (inbound 502/8080 REJECT, egress DROP)."
    else
        echo "[!] DOCKER-USER chain not found — Docker not installed or not running."
        echo "    OpenPLC ports will be protected by docker-compose.yml loopback"
        echo "    binding alone. Run 'apply' again after installing Docker."
    fi

    echo "[*] Applied. Current mangle rules:"
    iptables -t mangle -L POSTROUTING -n -v | grep -A1 "${MANGLE_COMMENT}" || true
    echo "[*] Current backend-isolation filter rule:"
    iptables -L INPUT -n -v | grep -A1 "${FILTER_COMMENT}" || true

    cat <<EOF

[*] Persistence: s7honeypot-harden.service (enabled by install.sh) re-runs
    this apply at every boot. If you manage the rules yourself, disable
    that unit and persist them with netfilter-persistent plus a
    /etc/sysctl.d drop-in instead.

[!] VERIFY the backend isolation actually matters on your setup:
    sudo ss -tlnp | grep ${BACKEND_PORT}
    If it shows 127.0.0.1:${BACKEND_PORT}, the library already binds
    loopback-only and this rule is pure defense-in-depth. If it shows
    0.0.0.0:${BACKEND_PORT} or your real IP, this rule is load-bearing --
    confirm it's actually applied before considering this safe.
EOF
}

revert() {
    echo "[*] Removing backend-isolation filter rule..."
    while iptables -C INPUT -p tcp --dport "${BACKEND_PORT}" ! -i lo \
        -j REJECT --reject-with tcp-reset \
        -m comment --comment "${FILTER_COMMENT}" 2>/dev/null; do
        iptables -D INPUT -p tcp --dport "${BACKEND_PORT}" ! -i lo \
            -j REJECT --reject-with tcp-reset \
            -m comment --comment "${FILTER_COMMENT}"
    done
    # Also remove the old DROP form if a previous version installed it
    while iptables -C INPUT -p tcp --dport "${BACKEND_PORT}" ! -i lo -j DROP \
        -m comment --comment "${FILTER_COMMENT}" 2>/dev/null; do
        iptables -D INPUT -p tcp --dport "${BACKEND_PORT}" ! -i lo -j DROP \
            -m comment --comment "${FILTER_COMMENT}"
    done

    echo "[*] Removing SYN-ACK NFQUEUE rule..."
    while iptables -C OUTPUT -p tcp --sport "${S7_PORT}" \
        --tcp-flags SYN,ACK SYN,ACK \
        -j NFQUEUE --queue-num "${SYNACK_QUEUE}" --queue-bypass \
        -m comment --comment "${SYNACK_COMMENT}" 2>/dev/null; do
        iptables -D OUTPUT -p tcp --sport "${S7_PORT}" \
            --tcp-flags SYN,ACK SYN,ACK \
            -j NFQUEUE --queue-num "${SYNACK_QUEUE}" --queue-bypass \
            -m comment --comment "${SYNACK_COMMENT}"
    done

    # Remove Docker DOCKER-USER isolation rules if present
    if iptables -L DOCKER-USER -n &>/dev/null 2>&1; then
        echo "[*] Removing OpenPLC Docker isolation rules from DOCKER-USER..."
        # Remove REJECT forms (current) and DROP forms (from older versions)
        for verb in "REJECT --reject-with tcp-reset" "DROP"; do
            iptables -D DOCKER-USER -i "${IFACE}" -p tcp --dport 502 -j ${verb} \
                -m comment --comment "${MANGLE_COMMENT}-docker-modbus" 2>/dev/null || true
            iptables -D DOCKER-USER -i "${IFACE}" -p tcp --dport 8080 -j ${verb} \
                -m comment --comment "${MANGLE_COMMENT}-docker-ide" 2>/dev/null || true
        done
        iptables -D DOCKER-USER -i docker0 -o "${IFACE}" -j DROP \
            -m comment --comment "${MANGLE_COMMENT}-docker-egress" 2>/dev/null || true
    fi

    # Remove the scoped TTL mangle rules (TCP + ICMP)
    echo "[*] Removing TTL rewrite rules..."
    for proto in tcp icmp udp; do
        while iptables -t mangle -C POSTROUTING -o "${IFACE}" -p "${proto}" \
            -j TTL --ttl-set "${TARGET_TTL}" \
            -m comment --comment "${MANGLE_COMMENT}-ttl-${proto}" 2>/dev/null; do
            iptables -t mangle -D POSTROUTING -o "${IFACE}" -p "${proto}" \
                -j TTL --ttl-set "${TARGET_TTL}" \
                -m comment --comment "${MANGLE_COMMENT}-ttl-${proto}"
        done
    done

    echo "[*] Restoring default sysctl values..."
    sysctl -w net.ipv4.tcp_timestamps=1
    sysctl -w net.ipv4.tcp_sack=1
    sysctl -w net.ipv4.tcp_window_scaling=1
    # Note: we no longer touch net.ipv4.ip_default_ttl (the TTL rewrite is
    # done via the scoped mangle rules above, not the global sysctl).

    echo "[*] Re-enabling IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=0      >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=0  >/dev/null 2>&1 || true
    sysctl -w "net.ipv6.conf.${IFACE}.disable_ipv6=0" >/dev/null 2>&1 || true
    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT   ACCEPT 2>/dev/null || true
        ip6tables -P OUTPUT  ACCEPT 2>/dev/null || true
        ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    fi

    echo "[*] Reverted."
}

status() {
    echo "--- mangle rules ---"
    iptables -t mangle -L POSTROUTING -n -v | grep -B1 -A1 "${MANGLE_COMMENT}" || echo "(none applied)"
    echo
    echo "--- backend-isolation filter rule ---"
    iptables -L INPUT -n -v | grep -B1 -A1 "${FILTER_COMMENT}" || echo "(none applied)"
    echo
    echo "--- SYN-ACK NFQUEUE rule ---"
    iptables -L OUTPUT -n -v | grep -B1 -A1 "${SYNACK_COMMENT}" || echo "(none applied)"
    echo
    echo "--- what the backend actually bound to (verify against the rule above) ---"
    ss -tlnp 2>/dev/null | grep ":${BACKEND_PORT} " || echo "(nothing listening on ${BACKEND_PORT} right now)"
    echo
    echo "--- relevant sysctl values ---"
    sysctl net.ipv4.tcp_timestamps net.ipv4.tcp_sack net.ipv4.tcp_window_scaling
    echo
    echo "--- IPv6 (should be disabled: 1) ---"
    sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "(IPv6 sysctl unavailable)"
    echo
    echo "--- TTL rewrite (should show ttl-set ${TARGET_TTL} for tcp + icmp + udp) ---"
    iptables -t mangle -L POSTROUTING -n -v | grep "TTL set" || echo "(no TTL rules applied)"
}

case "${1:-}" in
    apply)  apply ;;
    revert) revert ;;
    status) status ;;
    *)
        echo "Usage: $0 {apply|revert|status}"
        exit 1
        ;;
esac
