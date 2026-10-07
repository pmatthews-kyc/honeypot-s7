"""
test_honeypot_relay_integration.py
-------------------------------------
Exercises S7Proxy._relay directly over real socket pairs (client<->proxy,
proxy<->backend), bypassing accept()/precheck, to confirm the actual
wiring in honeypot.py: block-transfer/control frames get answered by the
proxy itself and never reach the backend socket, while an ordinary frame
(read_var) still passes through to the backend and the backend's
response makes it back to the client.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import os
import socket
import tempfile
import threading

import yaml

import s7_header as sh
from test_s7_header_roundtrip import build_synthetic_job_request


def _make_proxy(szl_status_intercept_enabled: bool = False):
    import honeypot

    with open(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "config.yaml.example")) as f:
        cfg = yaml.safe_load(f)

    tmpdir = tempfile.mkdtemp()
    cfg["storage"]["data_dir"] = tmpdir
    cfg["storage"]["require_mount"] = False
    cfg["capture"]["enabled"] = False
    # Keep runtime state (cpu_state.json, honeypot.db) in the temp dir —
    # otherwise the PLC STOP exercised below is written to the REAL
    # /var/lib/s7honeypot and a later fresh install boots into STOP.
    cfg["x-state-dir"] = tmpdir
    cfg.setdefault("logging", {})["state_dir"] = tmpdir
    cfg["logging"]["honeypot_db"] = os.path.join(tmpdir, "honeypot.db")
    cfg["ladder_program"]["szl_status_intercept_enabled"] = szl_status_intercept_enabled

    tmp_config = os.path.join(tmpdir, "test_config.yaml")
    with open(tmp_config, "w") as f:
        yaml.safe_dump(cfg, f)

    return honeypot.S7Proxy(tmp_config)


def test_block_transfer_intercepted_not_forwarded():
    proxy = _make_proxy()

    client_local, client_remote = socket.socketpair()
    backend_local, backend_remote = socket.socketpair()

    # backend_remote plays the role of the (never actually reached, for
    # this frame) backend s7.Server -- if anything shows up here, the
    # interception failed to prevent forwarding.
    backend_received = []

    def fake_backend():
        backend_remote.settimeout(2)
        try:
            data = backend_remote.recv(4096)
            if data:
                backend_received.append(data)
        except socket.timeout:
            pass

    backend_thread = threading.Thread(target=fake_backend, daemon=True)
    backend_thread.start()

    relay_thread = threading.Thread(
        target=proxy._relay,
        args=(client_remote, backend_local, "test-session", "10.0.0.1", 54321),
        daemon=True,
    )
    relay_thread.start()

    # Attacker sends a PLC STOP request (function code 0x29) -- should be
    # intercepted and answered directly, never touching the backend.
    stop_frame = build_synthetic_job_request(pdu_reference=1, function_code=0x29)
    client_local.sendall(stop_frame)

    client_local.settimeout(3)
    response = client_local.recv(4096)
    parsed_response = sh.parse_frame(response)

    assert parsed_response is not None
    assert parsed_response.pdu_type == sh.PDU_TYPE_ACK_DATA, "should get an ack-data response directly from the proxy"
    print("PLC STOP frame answered directly by proxy -- OK")

    backend_thread.join(timeout=3)
    assert backend_received == [], f"backend should NEVER see the intercepted frame, but received: {backend_received}"
    print("Intercepted frame never reached backend -- OK")

    client_local.close()
    client_remote.close()
    backend_local.close()
    backend_remote.close()


def test_ordinary_frame_still_forwarded_to_backend():
    proxy = _make_proxy()

    client_local, client_remote = socket.socketpair()
    backend_local, backend_remote = socket.socketpair()

    relay_thread = threading.Thread(
        target=proxy._relay,
        args=(client_remote, backend_local, "test-session-2", "10.0.0.2", 54322),
        daemon=True,
    )
    relay_thread.start()

    # read_var (0x04) is NOT one of the intercepted function codes -- it
    # should pass through to the backend unchanged.
    read_frame = build_synthetic_job_request(pdu_reference=42, function_code=0x04)
    client_local.sendall(read_frame)

    backend_remote.settimeout(3)
    forwarded = backend_remote.recv(4096)
    assert forwarded == read_frame, "ordinary frame must reach the backend byte-for-byte unchanged"
    print("Ordinary (non-intercepted) frame correctly forwarded to backend -- OK")

    # Simulate the backend replying -- should reach the client.
    fake_backend_response = sh.build_ack_data_response(pdu_reference=42, data=b"fakevalue")
    backend_remote.sendall(fake_backend_response)

    client_local.settimeout(3)
    reply = client_local.recv(4096)
    assert reply == fake_backend_response, "backend's response must reach the client unchanged"
    print("Backend response correctly relayed back to client -- OK")

    client_local.close()
    client_remote.close()
    backend_local.close()
    backend_remote.close()


def test_szl_status_intercepted_not_forwarded():
    """
    Tests the interception MECHANISM works correctly when explicitly
    enabled -- it's disabled by default in shipped config.yaml (see that
    file's comment) after a real compatibility bug: nmap's s7-info.nse
    queries this same SZL ID as part of its own normal identification
    sequence and crashed parsing this project's fabricated, never-
    independently-verified response structure for it. This test still
    validates the plumbing (interception happens, backend never sees
    it) for whenever that response structure gets properly verified and
    this feature is safe to re-enable.
    """
    proxy = _make_proxy(szl_status_intercept_enabled=True)

    client_local, client_remote = socket.socketpair()
    backend_local, backend_remote = socket.socketpair()
    backend_received = []

    def fake_backend():
        backend_remote.settimeout(2)
        try:
            data = backend_remote.recv(4096)
            if data:
                backend_received.append(data)
        except socket.timeout:
            pass

    backend_thread = threading.Thread(target=fake_backend, daemon=True)
    backend_thread.start()

    relay_thread = threading.Thread(
        target=proxy._relay,
        args=(client_remote, backend_local, "test-session-3", "10.0.0.3", 54323),
        daemon=True,
    )
    relay_thread.start()

    # Build a synthetic Read-SZL CPU-status Userdata frame the same way
    # test_szl_status_integration.py does, at the raw-frame level this
    # time (through the real TPKT/COTP framing, not a pre-built ParsedFrame).
    params = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
    data = bytes([0x00, 0x00, 0x04, 0x02, 0x04, 0x24, 0x00, 0x00])
    s7 = bytes([
        0x32, sh.PDU_TYPE_USERDATA, 0x00, 0x00, 0x00, 0x01,
        (len(params) >> 8) & 0xFF, len(params) & 0xFF,
        (len(data) >> 8) & 0xFF, len(data) & 0xFF,
    ])
    cotp = bytes([0x02, sh.COTP_TYPE_DT, 0x80])
    body = cotp + s7 + params + data
    total_len = sh.TPKT_HEADER_LEN + len(body)
    frame = bytes([0x03, 0x00, (total_len >> 8) & 0xFF, total_len & 0xFF]) + body

    client_local.sendall(frame)
    client_local.settimeout(3)
    response = client_local.recv(4096)
    parsed_response = sh.parse_frame(response)

    assert parsed_response is not None
    assert parsed_response.pdu_type == sh.PDU_TYPE_ACK_DATA
    print("SZL status frame answered directly by proxy -- OK")

    backend_thread.join(timeout=3)
    assert backend_received == [], f"backend should never see the intercepted SZL frame, got: {backend_received}"
    print("Intercepted SZL status frame never reached backend -- OK")

    client_local.close()
    client_remote.close()
    backend_local.close()
    backend_remote.close()


def test_szl_status_disabled_by_default_forwards_to_backend():
    """
    The actual regression fix: with szl_status_intercept_enabled left at
    its default (False), a Read-SZL 0x0424 request must fall through to
    the backend like any other unrecognized SZL request -- NOT get
    intercepted and answered with the fabricated structure that broke
    nmap's s7-info.nse. This is the property that fixes the real bug.
    """
    proxy = _make_proxy(szl_status_intercept_enabled=False)

    client_local, client_remote = socket.socketpair()
    backend_local, backend_remote = socket.socketpair()
    backend_received = []

    def fake_backend():
        backend_remote.settimeout(2)
        try:
            data = backend_remote.recv(4096)
            if data:
                backend_received.append(data)
        except socket.timeout:
            pass

    backend_thread = threading.Thread(target=fake_backend, daemon=True)
    backend_thread.start()

    relay_thread = threading.Thread(
        target=proxy._relay,
        args=(client_remote, backend_local, "test-session-4", "10.0.0.4", 54324),
        daemon=True,
    )
    relay_thread.start()

    params = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
    data = bytes([0x00, 0x00, 0x04, 0x02, 0x04, 0x24, 0x00, 0x00])
    s7 = bytes([
        0x32, sh.PDU_TYPE_USERDATA, 0x00, 0x00, 0x00, 0x01,
        (len(params) >> 8) & 0xFF, len(params) & 0xFF,
        (len(data) >> 8) & 0xFF, len(data) & 0xFF,
    ])
    cotp = bytes([0x02, sh.COTP_TYPE_DT, 0x80])
    body = cotp + s7 + params + data
    total_len = sh.TPKT_HEADER_LEN + len(body)
    frame = bytes([0x03, 0x00, (total_len >> 8) & 0xFF, total_len & 0xFF]) + body

    client_local.sendall(frame)

    backend_thread.join(timeout=3)
    assert backend_received == [frame], (
        f"with the feature disabled (the shipped default), this frame must "
        f"reach the backend UNCHANGED like any other request -- got: {backend_received}"
    )
    print("SZL 0x0424 request correctly forwarded to backend when feature "
          "disabled (shipped default) -- OK, this is the actual bug fix")

    client_local.close()
    client_remote.close()
    backend_local.close()
    backend_remote.close()


if __name__ == "__main__":
    test_block_transfer_intercepted_not_forwarded()
    test_ordinary_frame_still_forwarded_to_backend()
    test_szl_status_intercepted_not_forwarded()
    test_szl_status_disabled_by_default_forwards_to_backend()
    print("\nAll honeypot relay integration tests passed.")
