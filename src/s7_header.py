"""
s7_header.py
------------
TPKT + COTP (Data PDU) + S7 header parse/build. This is the framing layer
that sits between s7_precheck.py (which only validates the initial COTP
Connection Request) and the actual S7 job requests carrying function
codes like block download/upload and PLC STOP.

Structure implemented here is the well-documented public S7comm framing
(the same structure Wireshark's s7comm dissector and the open-source
Snap7 library use):

    TPKT header (4 bytes):
        version(1)=0x03, reserved(1)=0x00, length_hi(1), length_lo(1)
        `length` is the TOTAL frame length including these 4 bytes.

    COTP Data PDU header (3 bytes, for an already-connected session):
        length_indicator(1)=0x02, pdu_type(1)=0xF0 (DT), tpdu_number(1)
        (0x80 = end-of-tsdu bit set, sequence 0 -- S7 doesn't fragment at
        the COTP layer in normal operation, so this is effectively fixed)

    S7 header:
        Job Request   (pdu_type 0x01): 10 bytes, no error fields
        Ack / Ack-Data (pdu_type 0x02/0x03): 12 bytes, adds error_class +
                                              error_code
        protocol_id(1)=0x32, pdu_type(1), reserved(2), pdu_reference(2),
        param_length(2), data_length(2), [error_class(1), error_code(1)]

    followed by `param_length` bytes of parameters, then `data_length`
    bytes of data. For a Job Request, parameters[0] is the function code.

CONFIDENCE NOTE: the framing above (TPKT/COTP/S7 header) is solid, widely
publicly documented structure. The finer sub-parameter layout WITHIN
specific function codes' parameter/data blocks (e.g. the exact block-name
encoding inside a Request Download 0x1A) is not something I have
byte-exact verified certainty on without testing against a real capture
-- block_transfer_handler.py treats the raw parameter/data bytes as the
thing worth capturing rather than depending on parsing them precisely.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

TPKT_HEADER_LEN = 4
COTP_DT_HEADER_LEN = 3
S7_HEADER_JOB_LEN = 10
S7_HEADER_ACKDATA_LEN = 12

PDU_TYPE_JOB_REQUEST = 0x01
PDU_TYPE_ACK = 0x02
PDU_TYPE_ACK_DATA = 0x03
PDU_TYPE_USERDATA = 0x07  # Confirmed from S7PacketAnalyzer.cs MessageTypeDescription

COTP_TYPE_DT = 0xF0

# Function codes -- confirmed from S7PacketAnalyzer.cs lines 218-229
# (independent C# implementation, cross-checked against our own captures)
FUNC_SETUP_COMM    = 0xF0
FUNC_CPU_SERVICES  = 0x00  # SZL reads come through here
FUNC_READ_VAR      = 0x04
FUNC_WRITE_VAR     = 0x05
FUNC_REQ_DOWNLOAD  = 0x1A
FUNC_DOWNLOAD_BLK  = 0x1B
FUNC_DOWNLOAD_END  = 0x1C
FUNC_START_UPLOAD  = 0x1D
FUNC_UPLOAD        = 0x1E
FUNC_END_UPLOAD    = 0x1F
FUNC_PLC_CONTROL   = 0x28  # PI Service in S7PacketAnalyzer.cs
FUNC_PLC_STOP      = 0x29

FUNCTION_CODE_NAMES = {
    FUNC_SETUP_COMM:    "setup_communication",
    FUNC_CPU_SERVICES:  "cpu_services",
    FUNC_READ_VAR:      "read_var",
    FUNC_WRITE_VAR:     "write_var",
    FUNC_REQ_DOWNLOAD:  "request_download",
    FUNC_DOWNLOAD_BLK:  "download_block",
    FUNC_DOWNLOAD_END:  "download_ended",
    FUNC_START_UPLOAD:  "start_upload",
    FUNC_UPLOAD:        "upload",
    FUNC_END_UPLOAD:    "end_upload",
    FUNC_PLC_CONTROL:   "plc_control",
    FUNC_PLC_STOP:      "plc_stop",
}


def read_tpkt_frame(sock: socket.socket) -> bytes | None:
    """
    Block until one complete TPKT frame is read (TPKT header + however
    many bytes its length field declares), or return None on a closed/
    reset connection. This is the message-framing equivalent of
    s7_precheck's byte-level peek, but consumes the socket for real
    (no MSG_PEEK) since it's used after a session is already accepted.
    """
    header = _recv_exact(sock, TPKT_HEADER_LEN)
    if header is None:
        return None
    if header[0] != 0x03:
        # Not a TPKT frame at all -- caller should treat the connection
        # as misbehaving; hand back what we have so it can still be
        # logged rather than silently discarded.
        return header

    total_len = (header[2] << 8) | header[3]
    remaining = total_len - TPKT_HEADER_LEN
    if remaining < 0:
        return header

    rest = _recv_exact(sock, remaining)
    if rest is None:
        return header
    return header + rest


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    if n == 0:
        return b""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@dataclass
class ParsedFrame:
    is_s7_data: bool
    pdu_type: int | None = None
    pdu_reference: int | None = None
    function_code: int | None = None
    params: bytes = b""
    data: bytes = b""


def parse_frame(frame: bytes) -> ParsedFrame | None:
    """
    Parse a full TPKT frame down to the S7 job-request level. Returns
    None if the frame is too short or malformed to be worth logging as
    structured; returns a ParsedFrame with is_s7_data=False for
    non-Data COTP PDUs (connection request/confirm, etc. -- those are
    handled by s7_precheck.py, not here).
    """
    if len(frame) < TPKT_HEADER_LEN + 3:
        return None
    if frame[0] != 0x03:
        return None

    cotp_li = frame[4]
    cotp_type = frame[5]

    if cotp_type != COTP_TYPE_DT:
        return ParsedFrame(is_s7_data=False)

    cotp_header_len = 1 + cotp_li  # li byte itself + li-declared following bytes
    s7_start = TPKT_HEADER_LEN + cotp_header_len

    if len(frame) < s7_start + S7_HEADER_JOB_LEN:
        return ParsedFrame(is_s7_data=False)

    s7 = frame[s7_start:]
    if s7[0] != 0x32:
        return ParsedFrame(is_s7_data=False)

    pdu_type = s7[1]
    pdu_reference = (s7[4] << 8) | s7[5]
    param_length = (s7[6] << 8) | s7[7]
    data_length = (s7[8] << 8) | s7[9]

    # Header length by PDU type: Job Request (0x01) and Userdata (0x07)
    # both use the 10-byte header (no error_class/error_code fields);
    # only Ack (0x02) and Ack-Data (0x03) use the 12-byte header. An
    # earlier version of this function incorrectly grouped Userdata with
    # Ack-Data's 12-byte header -- caught while building SZL-read
    # interception (szl_status_handler.py), which is the first code path
    # to actually exercise Userdata frames; existing tests only ever
    # covered Job Request and Ack-Data.
    if pdu_type in (PDU_TYPE_JOB_REQUEST, PDU_TYPE_USERDATA):
        header_len = S7_HEADER_JOB_LEN
    else:
        header_len = S7_HEADER_ACKDATA_LEN
    if len(s7) < header_len + param_length + data_length:
        # Declared lengths exceed what we actually received -- malformed
        # or truncated. Still worth surfacing minimally for logging.
        return ParsedFrame(is_s7_data=True, pdu_type=pdu_type, pdu_reference=pdu_reference)

    params = s7[header_len:header_len + param_length]
    data = s7[header_len + param_length:header_len + param_length + data_length]
    function_code = params[0] if len(params) >= 1 else None

    return ParsedFrame(
        is_s7_data=True,
        pdu_type=pdu_type,
        pdu_reference=pdu_reference,
        function_code=function_code,
        params=params,
        data=data,
    )


def build_ack_data_response(pdu_reference: int, params: bytes = b"", data: bytes = b"",
                             error_class: int = 0, error_code: int = 0) -> bytes:
    """
    Build a complete TPKT+COTP+S7 Ack-Data response frame. Used to reply
    directly to block-transfer/control requests the proxy intercepts
    itself, without involving the backend s7.Server.
    """
    s7_header = bytes([
        0x32, PDU_TYPE_ACK_DATA,
        0x00, 0x00,
        (pdu_reference >> 8) & 0xFF, pdu_reference & 0xFF,
        (len(params) >> 8) & 0xFF, len(params) & 0xFF,
        (len(data) >> 8) & 0xFF, len(data) & 0xFF,
        error_class & 0xFF, error_code & 0xFF,
    ])
    cotp = bytes([0x02, COTP_TYPE_DT, 0x80])
    body = cotp + s7_header + params + data
    total_len = TPKT_HEADER_LEN + len(body)
    tpkt = bytes([0x03, 0x00, (total_len >> 8) & 0xFF, total_len & 0xFF])
    return tpkt + body
