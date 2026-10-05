"""
szl_status_handler.py
------------------------
Intercepts S7 "Read SZL" requests (Userdata PDU, CPU-functions group,
Read SZL subfunction) specifically for SZL ID 0x0424 -- the diagnostic-
buffer/CPU-status area -- and answers with the CURRENT shared cpu_state
(see cpu_state.py), so an attacker who sends PLC STOP and then checks
run/stop state via a real SZL read (rather than just trusting their own
STOP command succeeded) sees it actually reflected, instead of a device
that silently ignores its own reported state.

This targets exactly the gap flagged in STATUS.md: block_transfer_handler
tracked STOP locally with nothing else in the stack aware of it.

CONFIDENCE NOTE, same posture as ladder_block_store.py and the block-name
parsing in block_transfer_handler.py: SZL ID 0x0424 being the relevant
area for CPU status, and the general Userdata/Read-SZL request shape
(parameter head 0x00 0x01 0x12 0x04, function group 4 = CPU functions,
subfunction 0x01 = Read SZL, followed by the actual SZL-ID/index in the
data block), reflects general public S7comm community documentation
(the same shape Snap7's own open-source client and Wireshark's s7comm
dissector use) -- solid at the "this is the right general area" level,
NOT independently verified byte-exact against a live capture. Detection
here uses a permissive byte-pattern match for the SZL-ID (0x04 0x24)
rather than a fully rigorous structural parse, same reasoning as the
block-reference scan: lower engineering risk, and if the pattern doesn't
match, the request just falls through to the backend unmodified rather
than breaking anything.

The response this builds is a minimal, self-consistent SZL data block
(round-trips through this project's own parser in tests) with a single
byte varied to reflect RUN vs STOP. It is NOT guaranteed to match a real
Siemens SZL 0x0424 response byte-for-byte -- validate against a real
capture before assuming a strict client parses it exactly as expected.
"""

from __future__ import annotations

import logging
from pathlib import Path

import s7_header as sh
import cpu_state

log = logging.getLogger("szl_status")

SZL_ID_CPU_STATUS = bytes([0x04, 0x24])  # SZL 0x0424, byte order as it appears on the wire

# Userdata parameter head Siemens uses for CPU-function requests --
# permissive match target, not a strict full parse.
USERDATA_PARAM_HEAD_PREFIX = bytes([0x00, 0x01, 0x12])


def is_read_szl_cpu_status_request(parsed: sh.ParsedFrame) -> bool:
    if not parsed.is_s7_data or parsed.pdu_type != sh.PDU_TYPE_USERDATA:
        return False
    payload = parsed.params + parsed.data
    return (USERDATA_PARAM_HEAD_PREFIX in payload) and (SZL_ID_CPU_STATUS in payload)


def build_status_response(pdu_reference: int, state_path: Path = cpu_state.STATE_PATH) -> bytes:
    """
    Build a minimal SZL 0x0424-shaped response reflecting the current
    shared cpu_state. Structure: a short data block with a return code,
    the SZL-ID being answered, and a single status byte -- 0x08 for RUN,
    0x04 for STOP (values chosen to be clearly distinguishable in a hex
    dump for testing/manual inspection; NOT independently verified as
    matching real Siemens status byte values at this exact offset).
    """
    state = cpu_state.read_cpu_state(state_path)
    status_byte = 0x08 if state == cpu_state.STATE_RUN else 0x04

    data = bytes([0xFF]) + SZL_ID_CPU_STATUS + bytes([status_byte])
    # Minimal Userdata response parameter block echoing a "read SZL,
    # response" shape -- again, plausible general shape, not verified
    # byte-exact.
    params = bytes([0x00, 0x01, 0x12, 0x04, 0x12, 0x44, 0x01, 0x00])

    return sh.build_ack_data_response(pdu_reference, params=params, data=data)


class SZLStatusHandler:
    def __init__(self, cmd_logger, cpu_state_path: Path | None = None):
        self.cmd_logger = cmd_logger
        self._cpu_state_path = cpu_state_path or cpu_state.STATE_PATH

    def handles(self, parsed: sh.ParsedFrame) -> bool:
        return is_read_szl_cpu_status_request(parsed)

    def handle(self, session_id: str, peer_ip: str, peer_port: int,
               parsed: sh.ParsedFrame) -> bytes:
        state = cpu_state.read_cpu_state(self._cpu_state_path)
        log.info("SZL CPU-status read from %s:%d -- reporting %s", peer_ip, peer_port, state)

        self.cmd_logger.log_event(
            session_id, peer_ip, peer_port, "szl_status_read",
            parsed.params + parsed.data,
            {"function": "read_szl_cpu_status", "reported_state": state},
        )

        return build_status_response(parsed.pdu_reference, self._cpu_state_path)
