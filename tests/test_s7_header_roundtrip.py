"""
test_s7_header_roundtrip.py
-----------------------------
No real S7 client/PLC available in this build environment. Builds a
synthetic job-request frame the way a real S7comm client would (TPKT +
COTP DT + S7 job header + a function code param), parses it back, then
builds an ack-data response and re-parses that too.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import s7_header as sh


def build_synthetic_job_request(pdu_reference: int, function_code: int,
                                 extra_params: bytes = b"", data: bytes = b"") -> bytes:
    params = bytes([function_code]) + extra_params
    s7 = bytes([
        0x32, sh.PDU_TYPE_JOB_REQUEST,
        0x00, 0x00,
        (pdu_reference >> 8) & 0xFF, pdu_reference & 0xFF,
        (len(params) >> 8) & 0xFF, len(params) & 0xFF,
        (len(data) >> 8) & 0xFF, len(data) & 0xFF,
    ])
    cotp = bytes([0x02, sh.COTP_TYPE_DT, 0x80])
    body = cotp + s7 + params + data
    total_len = sh.TPKT_HEADER_LEN + len(body)
    tpkt = bytes([0x03, 0x00, (total_len >> 8) & 0xFF, total_len & 0xFF])
    return tpkt + body


def test_job_request_roundtrip():
    frame = build_synthetic_job_request(
        pdu_reference=0x1234,
        function_code=0x1A,  # Request Download
        extra_params=b"\x01\x02BLOCKNAME",
        data=b"",
    )
    parsed = sh.parse_frame(frame)
    assert parsed is not None
    assert parsed.is_s7_data is True
    assert parsed.pdu_type == sh.PDU_TYPE_JOB_REQUEST
    assert parsed.pdu_reference == 0x1234
    assert parsed.function_code == 0x1A
    assert parsed.params == b"\x1a\x01\x02BLOCKNAME"
    print("Job request round-trip: OK")


def test_ack_data_roundtrip():
    response = sh.build_ack_data_response(
        pdu_reference=0x1234,
        params=b"\x00",
        data=b"HELLO",
        error_class=0,
        error_code=0,
    )
    parsed = sh.parse_frame(response)
    assert parsed is not None
    assert parsed.is_s7_data is True
    assert parsed.pdu_type == sh.PDU_TYPE_ACK_DATA
    assert parsed.pdu_reference == 0x1234
    # For ack-data frames function_code isn't meaningful the same way,
    # but params/data should still come through intact.
    assert parsed.data == b"HELLO"
    print("Ack-data round-trip: OK")


def test_read_tpkt_frame_via_socket():
    """Exercise read_tpkt_frame against a real socket pair (not just bytes
    in memory) to catch partial-recv bugs a pure in-memory test would
    miss -- e.g. large frames arriving in multiple TCP segments."""
    import socket
    import threading

    frame = build_synthetic_job_request(
        pdu_reference=0x0001,
        function_code=0x1B,  # Download Block
        data=b"X" * 5000,  # forces multiple recv() calls on most systems
    )

    server_sock, client_sock = socket.socketpair()

    def sender():
        # dribble it out in small pieces to simulate a slow/fragmented sender
        for i in range(0, len(frame), 137):
            client_sock.sendall(frame[i:i + 137])

    t = threading.Thread(target=sender)
    t.start()
    received = sh.read_tpkt_frame(server_sock)
    t.join()

    assert received == frame, f"length mismatch: got {len(received) if received else None}, want {len(frame)}"
    parsed = sh.parse_frame(received)
    assert parsed.function_code == 0x1B
    assert parsed.data == b"X" * 5000
    print("Fragmented socket read (read_tpkt_frame): OK")

    server_sock.close()
    client_sock.close()


def test_userdata_header_length():
    """
    Regression test for a real bug: Userdata (0x07) frames were being
    parsed with the 12-byte Ack-Data header length instead of the
    correct 10-byte header (Userdata has no error_class/error_code
    fields, same shape as Job Request). Existing tests never exercised
    pdu_type=0x07 at all before this, so the bug went uncaught until
    building SZL-read interception.
    """
    pdu_reference = 0x0005
    params = b"\x00\x01\x12\x04\x11\x44\x01\x00"  # plausible-shaped Read SZL parameter head
    data = b"\xAB\xCD"

    s7 = bytes([
        0x32, sh.PDU_TYPE_USERDATA,
        0x00, 0x00,
        (pdu_reference >> 8) & 0xFF, pdu_reference & 0xFF,
        (len(params) >> 8) & 0xFF, len(params) & 0xFF,
        (len(data) >> 8) & 0xFF, len(data) & 0xFF,
    ])
    cotp = bytes([0x02, sh.COTP_TYPE_DT, 0x80])
    body = cotp + s7 + params + data
    total_len = sh.TPKT_HEADER_LEN + len(body)
    frame = bytes([0x03, 0x00, (total_len >> 8) & 0xFF, total_len & 0xFF]) + body

    parsed = sh.parse_frame(frame)
    assert parsed is not None
    assert parsed.is_s7_data is True
    assert parsed.pdu_type == sh.PDU_TYPE_USERDATA
    assert parsed.params == params, f"expected exact params, got {parsed.params!r}"
    assert parsed.data == data, f"expected exact data, got {parsed.data!r}"
    print("Userdata (0x07) header length correctly treated as 10 bytes: OK")


if __name__ == "__main__":
    test_job_request_roundtrip()
    test_ack_data_roundtrip()
    test_read_tpkt_frame_via_socket()
    test_userdata_header_length()
    print("\nAll S7 header self-tests passed.")
