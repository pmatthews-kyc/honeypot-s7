"""
s7_precheck.py
---------------
Cheap, protocol-level filter to separate "something that actually speaks
S7comm" from generic internet background noise (mass TCP scanners sending
junk, non-S7 clients probing port 102, single SYN-then-close probes).

This does NOT and cannot distinguish a real attacker from an automated
S7comm-aware fuzzer -- both complete a valid TPKT/COTP handshake and only
diverge in what they send *after* that, inside the S7 payload itself. That
distinction belongs in post-hoc analysis of the JSONL command log / pcap
(e.g. sessions that sweep every function code systematically, sessions with
high-entropy payloads, single source hitting many SZL IDs in rapid
succession are fuzzer-shaped; a session that reads specific DBs, writes
specific values, or issues a STOP is attacker-shaped). See README.

What this DOES filter: TCP connections that never send a valid TPKT header
(0x03 0x00 <len_hi> <len_lo>) followed by a COTP Connection Request PDU
(opcode 0xE0) with plausible TSAP values. That covers the overwhelming
majority of opportunistic port-102 noise.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass


TPKT_VERSION = 0x03
COTP_CONNECTION_REQUEST = 0xE0

# How many bytes we need to see to make a decision. TPKT header (4) +
# COTP CR minimum header (7) + enough variable part to reach dst-TSAP (C2).
# A full COTP CR with all three params (TPDU-size, src-TSAP, dst-TSAP) is
# typically 22 bytes; 32 gives comfortable headroom.
PRECHECK_BYTES = 32
PRECHECK_TIMEOUT = 3.0


@dataclass
class PrecheckResult:
    is_real_s7: bool
    reason: str
    peeked: bytes
    cotp_src_ref: int = 0      # client's SRC-REF from CR -- echoed back in CC DST-REF
    cotp_dst_tsap: bytes = b"" # C2 param (dst-TSAP) from CR -- rack/slot encoded here


def peek_validate_cotp_cr(sock: socket.socket) -> PrecheckResult:
    """
    Non-destructively peek at the first bytes of a new connection (using
    MSG_PEEK so the real protocol handler still sees the full stream) and
    check for a valid TPKT + COTP Connection Request.

    Also extracts the client's COTP SRC-REF so the relay can echo it
    back correctly in the backend's CC response. RFC 905 (ISO 8073)
    requires the CC's DST-REF to match the CR's SRC-REF. snap7.Server
    returns DST-REF=0x0000, which strict clients (not nmap, but real S7
    tools) reject with "TCP connected, ISO didn't". The relay patches
    the CC's DST-REF using cotp_src_ref before forwarding to the client.

    COTP CR layout (TPKT-framed):
        byte 0-3: TPKT header
        byte 4:   COTP LI (length indicator)
        byte 5:   COTP type (0xE0 = CR)
        byte 6-7: DST-REF (usually 0x0000 from client)
        byte 8-9: SRC-REF  ← this is what we extract

    Call this immediately after accept(), before handing the socket off to
    the S7 protocol handler / capture manager.
    """
    sock.settimeout(PRECHECK_TIMEOUT)
    try:
        data = sock.recv(PRECHECK_BYTES, socket.MSG_PEEK)
    except socket.timeout:
        return PrecheckResult(False, "no data received before timeout", b"")
    except OSError as e:
        return PrecheckResult(False, f"socket error during peek: {e}", b"")
    finally:
        sock.settimeout(None)

    if len(data) < 7:
        return PrecheckResult(False, "too few bytes for TPKT+COTP header", data)

    if data[0] != TPKT_VERSION:
        return PrecheckResult(False, f"not TPKT (version byte={data[0]:#x})", data)

    # TPKT: version(1) reserved(1) length_hi(1) length_lo(1)
    tpkt_length = (data[2] << 8) | data[3]
    if tpkt_length < 7 or tpkt_length > 65535:
        return PrecheckResult(False, f"implausible TPKT length {tpkt_length}", data)

    # COTP header starts at byte 4: length_indicator(1) pdu_type(1) ...\
    cotp_pdu_type = data[5]
    if cotp_pdu_type != COTP_CONNECTION_REQUEST:
        return PrecheckResult(
            False, f"not a COTP Connection Request (pdu_type={cotp_pdu_type:#x})", data
        )

    # Extract SRC-REF from bytes 8-9 (present if we have >= 10 bytes)
    cotp_src_ref = 0
    if len(data) >= 10:
        cotp_src_ref = (data[8] << 8) | data[9]

    # Extract dst-TSAP (C2 param) from the CR variable part.
    # Variable params start at byte 11 (after TPKT[4] + LI[1] + type[1] +
    # DST-REF[2] + SRC-REF[2] + CLASS[1] = 11). Each param is:
    # code(1) + length(1) + value(length).
    # dst-TSAP (C2) encodes the target rack/slot: byte0=conn_type,
    # byte1=(rack<<5)|slot. Used by the proxy to send COTP DR if the
    # rack/slot doesn't match our configured identity, matching what a
    # real S7-300 would do for an unrecognised TSAP.
    cotp_dst_tsap = b""
    j = 11
    while j + 2 <= len(data):
        code = data[j]
        ln   = data[j + 1]
        val  = data[j + 2:j + 2 + ln]
        if code == 0xC2:
            cotp_dst_tsap = val
            break
        j += 2 + ln

    return PrecheckResult(True, "valid TPKT+COTP Connection Request", data,
                          cotp_src_ref=cotp_src_ref,
                          cotp_dst_tsap=cotp_dst_tsap)
