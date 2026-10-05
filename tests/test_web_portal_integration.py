"""
test_web_portal_integration.py
---------------------------------
Real end-to-end test: starts an actual WebPortalServer on loopback, makes
real HTTP requests against it, and confirms rendering, logging, and the
Server-header suppression behavior. No mocking of http.server internals --
this exercises the real stdlib server exactly as deployed.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import json
import os
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

from command_logger import CommandLogger
import web_portal
import cpu_state


def _start_test_server(port: int, require_login: bool = False, server_header: str = ""):
    with open(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "config.yaml.example")) as f:
        cfg = yaml.safe_load(f)

    tmpdir = tempfile.mkdtemp()
    cfg["storage"]["data_dir"] = tmpdir
    cfg["storage"]["require_mount"] = False
    cfg["web_portal"]["require_login"] = require_login
    cfg["web_portal"]["server_header"] = server_header

    data_dir = web_portal.resolve_and_verify(cfg)
    jsonl_path = web_portal.substitute_data_dir(cfg["logging"]["jsonl_path"], data_dir)
    identity = web_portal.S7Identity.from_config(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "config.yaml.example"))
    cmd_logger = CommandLogger(jsonl_path)

    server = web_portal.WebPortalServer("127.0.0.1", port, identity, cfg["web_portal"], cmd_logger)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    return server, jsonl_path, identity


def test_main_page_shows_correct_identity():
    server, jsonl_path, identity = _start_test_server(8199)
    try:
        resp = urllib.request.urlopen("http://127.0.0.1:8199/")
        body = resp.read().decode()
        assert identity.order_code in body
        assert identity.module_name in body
        assert identity.serial_number in body
        print("Main page identity fields: OK")
    finally:
        server.shutdown()


def test_server_header_absent_by_default():
    server, _, _ = _start_test_server(8198, server_header="")
    try:
        resp = urllib.request.urlopen("http://127.0.0.1:8198/")
        assert "Server" not in resp.headers, "Server header must be fully absent, not empty"
        print("Server header suppression: OK")
    finally:
        server.shutdown()


def test_server_header_present_when_configured():
    server, _, _ = _start_test_server(8197, server_header="FakeSiemensHTTP/1.0")
    try:
        resp = urllib.request.urlopen("http://127.0.0.1:8197/")
        assert resp.headers.get("Server") == "FakeSiemensHTTP/1.0"
        print("Server header custom value: OK")
    finally:
        server.shutdown()


def test_login_always_rejected_and_credentials_captured():
    server, jsonl_path, _ = _start_test_server(8196, require_login=True)
    try:
        data = urllib.parse.urlencode({"username": "admin", "password": "hunter2"}).encode()
        resp = urllib.request.urlopen("http://127.0.0.1:8196/login", data=data)
        body = resp.read().decode()
        assert "Invalid" in body
        print("Login always rejected: OK")
    finally:
        server.shutdown()
        time.sleep(0.2)

    with open(jsonl_path) as f:
        events = [json.loads(l) for l in f if l.strip()]
    login_events = [e for e in events if e["event_type"] == "http_login_attempt"]
    assert len(login_events) == 1
    assert login_events[0]["parsed"]["username"] == "admin"
    assert login_events[0]["parsed"]["password"] == "hunter2"
    print("Credential capture logged correctly: OK")


def test_unknown_path_404_and_logged():
    server, jsonl_path, _ = _start_test_server(8195)
    try:
        try:
            urllib.request.urlopen("http://127.0.0.1:8195/../../etc/passwd")
            assert False, "should have raised HTTPError"
        except urllib.error.HTTPError as e:
            assert e.code == 404
        print("Unknown/traversal path returns 404: OK")
    finally:
        server.shutdown()
        time.sleep(0.2)

    with open(jsonl_path) as f:
        events = [json.loads(l) for l in f if l.strip()]
    req_events = [e for e in events if e["event_type"] == "http_request"]
    assert any("passwd" in e["parsed"].get("path", "") for e in req_events)
    print("Suspicious path attempt logged: OK")


def test_cpu_status_reflects_shared_state():
    """The web portal must show whatever cpu_state.py's shared state file
    says, since block_transfer_handler.py (a completely separate process
    in real deployment) is what actually writes it -- this is the fix for
    the gap flagged in STATUS.md."""
    tmp_state_path = Path(tempfile.mkdtemp()) / "cpu_state.json"
    original_path = cpu_state.STATE_PATH
    cpu_state.STATE_PATH = tmp_state_path  # patch module-level default for this test
    try:
        server, _, identity = _start_test_server(8190)
        try:
            resp = urllib.request.urlopen("http://127.0.0.1:8190/")
            body = resp.read().decode()
            assert ">RUN<" in body, "should default to RUN with no state file written yet"
            print("CPU status defaults to RUN before any STOP: OK")
        finally:
            server.shutdown()

        cpu_state.write_cpu_state(cpu_state.STATE_STOP, tmp_state_path)

        server2, _, _ = _start_test_server(8189)
        try:
            resp2 = urllib.request.urlopen("http://127.0.0.1:8189/")
            body2 = resp2.read().decode()
            assert ">STOP<" in body2, "should reflect STOP written externally by another process"
            print("CPU status correctly reflects externally-written STOP state: OK")
        finally:
            server2.shutdown()
    finally:
        cpu_state.STATE_PATH = original_path


def test_require_login_false_hides_form():
    server, _, _ = _start_test_server(8194, require_login=False)
    try:
        resp = urllib.request.urlopen("http://127.0.0.1:8194/")
        body = resp.read().decode()
        assert "<form" not in body, "login form should not render when require_login is false"
        print("require_login=false correctly hides the form: OK")
    finally:
        server.shutdown()


def test_page_is_plain_not_styled():
    """Confirm the page renders the authentic Siemens portal structure:
    Siemens branding, navigation panel, and module identification table.
    (This test was updated when web_portal.py was upgraded from a
    plain-HTML stub to the faithful Siemens S7-300 portal replica.)"""
    server, _, _ = _start_test_server(8193)
    try:
        resp = urllib.request.urlopen("http://127.0.0.1:8193/")
        body = resp.read().decode()
        assert "SIEMENS" in body,       "Siemens branding must be present"
        assert "nav-link" in body,       "navigation panel must be present"
        assert "Portal0000.htm" in body, "real portal URL must appear in nav links"
        assert "Diagnostic Buffer" in body, "diagnostic buffer section required"
        assert "Deutsch" in body,        "language selector must be present"
        print("Page renders authentic Siemens S7-300 portal structure: OK")
    finally:
        server.shutdown()


def test_generic_scanner_path_flagged_but_still_logged():
    server, jsonl_path, _ = _start_test_server(8192)
    try:
        req = urllib.request.Request("http://127.0.0.1:8192/wp-login.php")
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError:
            pass  # expect 404, that's fine
        print("Generic scanner path request completed (expect 404): OK")
    finally:
        server.shutdown()
        time.sleep(0.2)

    with open(jsonl_path) as f:
        events = [json.loads(l) for l in f if l.strip()]
    matching = [e for e in events if "wp-login" in e["parsed"].get("path", "")]
    assert len(matching) == 1
    assert matching[0]["parsed"]["generic_scanner_signal"] is True
    assert "wp-login" in matching[0]["parsed"]["matched_path_substrings"]
    print("Generic scanner path correctly flagged AND fully logged (not dropped): OK")


def test_targeted_request_not_flagged_as_generic():
    server, jsonl_path, _ = _start_test_server(8191)
    try:
        urllib.request.urlopen("http://127.0.0.1:8191/")
        print("Targeted (root path) request completed: OK")
    finally:
        server.shutdown()
        time.sleep(0.2)

    with open(jsonl_path) as f:
        events = [json.loads(l) for l in f if l.strip()]
    root_events = [e for e in events if e["parsed"].get("path") == "/"]
    assert len(root_events) == 1
    assert root_events[0]["parsed"]["generic_scanner_signal"] is False
    print("Targeted request correctly NOT flagged as generic scanner noise: OK")


if __name__ == "__main__":
    test_main_page_shows_correct_identity()
    test_server_header_absent_by_default()
    test_server_header_present_when_configured()
    test_login_always_rejected_and_credentials_captured()
    test_unknown_path_404_and_logged()
    test_cpu_status_reflects_shared_state()
    test_require_login_false_hides_form()
    test_page_is_plain_not_styled()
    test_generic_scanner_path_flagged_but_still_logged()
    test_targeted_request_not_flagged_as_generic()
    print("\nAll web portal integration tests passed.")
