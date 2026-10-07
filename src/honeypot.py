"""
honeypot.py
-----------
Architecture:

    attacker --> [precheck proxy, public port 102] --> [s7.Server, loopback]
                        |
                        +--> tshark session capture (capture_manager.py)
                        +--> JSONL command log (command_logger.py)

Why a proxy in front of s7.Server instead of hooking its internals directly:
python-snap7's pure-Python s7.Server is a fast-moving, recently-rewritten
API (3.0 was a ground-up rewrite; a 4.0 with further changes is in
progress). Rather than depend on internal accept-loop hooks that may change
between versions, we do the two things that actually matter for your goals
-- (1) filtering out non-S7 noise, (2) capturing raw payloads for later
reverse engineering -- at the TCP level in front of the library, where the
interface is just "bytes in, bytes out" and won't break under us.

s7.Server itself does NOT run bound to loopback only, despite this
module's original design intent -- see backend_server.py's docstring:
its start() method has no host/bind-address parameter at all, and it
was confirmed on real target hardware to bind 0.0.0.0. Isolation is
enforced at the firewall level instead (fingerprint_harden.sh's `apply`
command adds the iptables rule for this) -- not by the library binding
loopback-only, which it can't be made to do. Its SZL identity response
is patched via identity.py; see backend_server.py for exactly where
that hook goes for the confirmed-working library version.

Run as root (or with CAP_NET_BIND_SERVICE + CAP_NET_RAW) since this binds
port 102 and shells out to tshark.
"""

from __future__ import annotations

import sys
import logging
import socket
import threading
import time
import yaml

from block_transfer_handler import BlockTransferHandler, FUNCTION_NAMES
from szl_status_handler import SZLStatusHandler
from clock_handler import ClockHandler
from block_list_handler import BlockListHandler
from szl_identity_handler import SZLIdentityHandler
from capture_manager import CaptureManager
from command_logger import CommandLogger
from ladder_block_store import BlockStore
from s7_precheck import peek_validate_cotp_cr
import s7_header as sh
from read_write_parser import parse_from_frame, FUNCTION_CODE as FUNCTION_CODE_NAMES
from storage import resolve_and_verify, substitute_data_dir, StorageError
import cpu_state
import diag_log


def _build_cotp_dr(dst_ref: int, reason: int = 0x03) -> bytes:
    """
    Build a COTP DR (Disconnect Request) TPKT frame.

    Sent when a client's COTP CR targets the wrong rack/slot TSAP --
    matching what a real S7-300 does for an unrecognised destination.

    DR format (RFC 905 / ISO 8073):
        TPKT header (4 bytes)
        LI = 6 (6 bytes follow)
        Type = 0x80 (DR)
        DST-REF (2 bytes) -- echo client's SRC-REF so it can match
        SRC-REF = 0x0000  -- we're ending the connection
        Reason (1 byte)
            0x01 = not specified
            0x02 = congestion at TSAP
            0x03 = session entity not attached to TSAP  ← use this for wrong slot
            0x04 = address unknown
    """
    cotp = bytes([
        0x06,                          # LI = 6
        0x80,                          # DR type
        (dst_ref >> 8) & 0xFF,         # DST-REF high
        dst_ref & 0xFF,                # DST-REF low
        0x00, 0x00,                    # SRC-REF = 0
        reason & 0xFF,                 # reason
    ])
    total = 4 + len(cotp)
    return bytes([0x03, 0x00, (total >> 8) & 0xFF, total & 0xFF]) + cotp


def _decode_tsap_rack_slot(tsap: bytes):
    """
    Decode rack and slot from a COTP TSAP value.
    S7 TSAP encoding (both src and dst):
        byte 0: connection type (0x01=PG, 0x02=OP, 0x03=S7Basic)
        byte 1: (rack << 5) | slot
    Returns (rack, slot) or (None, None) if tsap is too short.
    """
    if len(tsap) < 2:
        return None, None
    return tsap[1] >> 5, tsap[1] & 0x1F

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("honeypot")

# Fallback max PDU if config.yaml doesn't set identity.max_pdu. The actual
# value used is read from config (240/480/960 are the real S7 values); this
# constant is only the default. snap7 advertises 960, a value no real S7-300
# returns, so the relay patches the negotiate ACK to the configured value.
REAL_S7_315_MAX_PDU = 480


class S7Proxy:
    def __init__(self, config_path: str = "config.yaml"):
        import diag_log as _dl
        _dl.configure(config_path)

        with open(config_path) as f:
            self.cfg = yaml.safe_load(f)

        net = self.cfg["network"]
        cap = self.cfg["capture"]
        logcfg = self.cfg["logging"]

        # Resolve + verify the removable-drive-backed data directory
        # before anything tries to write to it. This raises loudly and
        # refuses to start rather than silently falling back to writing
        # on the SD card if the drive isn't mounted -- see storage.py.
        try:
            data_dir = resolve_and_verify(self.cfg)
        except StorageError as e:
            log.error("Storage check failed: %s", e)
            raise

        log.info("Capture data directory: %s (verified mounted)", data_dir)

        pcap_dir = substitute_data_dir(cap["pcap_dir"], data_dir)
        jsonl_path = substitute_data_dir(logcfg["jsonl_path"], data_dir)

        self.public_host = net["host"]
        self.public_port = net["port"]
        self.backend_host = "127.0.0.1"
        self.backend_port = 1102  # NOT actually loopback-restricted by the library --
                                   # see backend_server.py's docstring. Isolation is
                                   # enforced by fingerprint_harden.sh's firewall rule.

        self.capture_enabled = cap.get("enabled", True)
        self.capture_mgr = CaptureManager(
            interface=cap["interface"],
            pcap_dir=pcap_dir,
            max_session_seconds=cap.get("max_session_seconds", 900),
            max_session_bytes=cap.get("max_session_bytes", 50 * 1024 * 1024),
        )
        self.cmd_logger = CommandLogger(jsonl_path)
        self.require_valid_cotp = cap.get("require_valid_cotp", True)

        # Rack and slot from identity config -- used to validate COTP TSAPs.
        # A real S7-300 sends COTP DR for connections targeting the wrong
        # rack/slot. snap7 accepts anything; we enforce this here.
        ident = self.cfg.get("identity", {})
        self.expected_rack = int(ident.get("rack", 0))
        self.expected_slot = int(ident.get("slot", 2))
        # Negotiated max PDU (240/480/960). Patched into the setup-comm ACK
        # below, since snap7 advertises 960. Must match SZL 0x0131 — both read
        # from the same config value, so they can't drift apart.
        self._max_pdu = int(ident.get("max_pdu", REAL_S7_315_MAX_PDU))

        # Fake ladder-program block store + handler for block download/
        # upload and PLC control/STOP -- see block_transfer_handler.py.
        # These function codes are intercepted and answered directly by
        # the proxy (not forwarded to the backend s7.Server), since
        # there's no guarantee the backend implements program transfer
        # at all -- see that module's docstring for why.
        ladder_cfg = self.cfg.get("ladder_program", {})
        self.ladder_enabled = ladder_cfg.get("enabled", True)
        # Resolve the runtime-state paths (cpu_state.json, honeypot.db) from
        # THIS config, not from whatever config.yaml happens to be in the
        # CWD. The proxy writes STOP/RUN transitions, so without this a
        # proxy started with an explicit config path would record them in
        # the wrong state dir.
        cpu_state.configure(config_path)
        diag_log.configure(config_path)
        self.block_store = BlockStore()
        self.block_handler = BlockTransferHandler(
            self.block_store, self.cmd_logger,
            cpu_state_path=cpu_state.STATE_PATH)
        self.szl_status_handler = SZLStatusHandler(self.cmd_logger)
        self.clock_handler = ClockHandler(self.cmd_logger)
        self.block_list_handler = BlockListHandler(self.block_store)
        self.szl_identity_handler = SZLIdentityHandler(config_path)
        # DEFAULT FALSE -- see config.yaml comment. A real compatibility
        # bug: nmap's s7-info.nse queries SZL 0x0424 as part of its own
        # normal identification sequence and crashes parsing this
        # project's never-independently-verified fabricated response for
        # it. Disabled by default until that structure is verified
        # against a real capture.
        self.szl_status_intercept_enabled = ladder_cfg.get("szl_status_intercept_enabled", False)

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.public_host, self.public_port))
        listener.listen(128)
        log.info("Listening on %s:%d (public)", self.public_host, self.public_port)

        try:
            while True:
                client_sock, addr = listener.accept()
                threading.Thread(
                    target=self._handle_connection,
                    args=(client_sock, addr),
                    daemon=True,
                ).start()
        finally:
            listener.close()
            self.capture_mgr.stop_all()

    def _handle_connection(self, client_sock: socket.socket, addr) -> None:
        peer_ip, peer_port = addr

        if self.require_valid_cotp:
            result = peek_validate_cotp_cr(client_sock)
            if not result.is_real_s7:
                log.debug("Dropping non-S7 connection from %s:%d (%s)",
                          peer_ip, peer_port, result.reason)
                client_sock.close()
                return

            # Validate dst_TSAP rack/slot -- a real S7-300 sends COTP DR
            # for connections targeting a slot that doesn't exist.
            cotp_src_ref = result.cotp_src_ref
            if result.cotp_dst_tsap:
                rack, slot = _decode_tsap_rack_slot(result.cotp_dst_tsap)
                if rack is not None and (rack != self.expected_rack or
                                          slot != self.expected_slot):
                    dr = _build_cotp_dr(cotp_src_ref, reason=0x03)
                    try:
                        client_sock.sendall(dr)
                    except OSError:
                        pass
                    log.info(
                        "Rejected COTP CR from %s:%d: wrong rack/slot "
                        "(got rack=%d slot=%d, expected rack=%d slot=%d) "
                        "-- sent COTP DR reason=0x03 (session not attached to TSAP)",
                        peer_ip, peer_port, rack, slot,
                        self.expected_rack, self.expected_slot,
                    )
                    client_sock.close()
                    return

            log.info("Validated S7 session from %s:%d (COTP SRC-REF=0x%04x)",
                     peer_ip, peer_port, result.cotp_src_ref)
        else:
            cotp_src_ref = 0

        session = None
        if self.capture_enabled:
            try:
                session = self.capture_mgr.start_session(peer_ip, peer_port, self.public_port)
            except Exception as e:
                log.warning("Failed to start tshark capture for %s:%d: %s", peer_ip, peer_port, e)

        session_id = session.session_id if session else f"nocap-{peer_ip}-{peer_port}-{int(time.time())}"
        self.cmd_logger.log_event(session_id, peer_ip, peer_port, "connect", b"")

        try:
            backend_sock = socket.create_connection((self.backend_host, self.backend_port), timeout=5)
        except OSError as e:
            log.error("Backend s7.Server unreachable at %s:%d: %s",
                      self.backend_host, self.backend_port, e)
            client_sock.close()
            if session:
                self.capture_mgr.stop_session(session.session_id)
            return

        self._relay(client_sock, backend_sock, session_id, peer_ip, peer_port,
                    cotp_src_ref=cotp_src_ref)

        if session:
            self.capture_mgr.stop_session(session.session_id)
        self.cmd_logger.log_event(session_id, peer_ip, peer_port, "disconnect", b"")

    def _relay(self, client_sock, backend_sock, session_id, peer_ip, peer_port,
               cotp_src_ref: int = 0) -> None:
        """
        Two directions, handled differently on purpose:

        client -> backend: read whole TPKT frames (not arbitrary byte
        chunks), so we can make a per-message decision -- block-transfer
        and PLC-control function codes (see block_transfer_handler.py)
        get answered directly by the proxy and are NOT forwarded to the
        backend s7.Server. Everything else (read/write var, SZL, Setup
        Communication, the COTP connection-confirm handshake) is
        forwarded through unchanged, exactly as before.

        backend -> client: intercept the first COTP CC (Connect Confirm)
        to patch DST-REF. snap7.Server returns DST-REF=0x0000, but RFC 905
        requires it to echo the client's SRC-REF from the CR. nmap is
        permissive and ignores this; real S7 tools are strict and reject
        the ISO connection with "TCP connected, ISO didn't". Patching
        takes 2 bytes and no checksum (COTP class-0 has none).
        Everything else is raw-chunk forwarding.
        """
        stop_event = threading.Event()
        cc_patched = threading.Event()   # set once the CC patch is done

        def client_to_backend():
            try:
                while not stop_event.is_set():
                    frame = sh.read_tpkt_frame(client_sock)
                    if frame is None:
                        break

                    parsed = sh.parse_frame(frame)

                    if (self.ladder_enabled and parsed is not None
                            and parsed.is_s7_data
                            and self.block_handler.handles(parsed.function_code)):
                        self.cmd_logger.log_event(
                            session_id, peer_ip, peer_port, "s7_request", frame,
                            {"function_code": parsed.function_code,
                             "function_name": FUNCTION_NAMES.get(parsed.function_code),
                             "intercepted": True},
                        )
                        response = self.block_handler.handle(session_id, peer_ip, peer_port, parsed)
                        client_sock.sendall(response)
                        continue

                    if (self.szl_status_intercept_enabled and parsed is not None
                            and parsed.is_s7_data
                            and self.szl_status_handler.handles(parsed)):
                        self.cmd_logger.log_event(
                            session_id, peer_ip, peer_port, "s7_request", frame,
                            {"pdu_type": parsed.pdu_type, "intercepted": True,
                             "function_name": "read_szl_cpu_status"},
                        )
                        response = self.szl_status_handler.handle(session_id, peer_ip, peer_port, parsed)
                        client_sock.sendall(response)
                        continue

                    if (parsed is not None and
                            self.szl_identity_handler.handles(parsed)):
                        # SZL identity reads (group=4, sf=0x01) for the
                        # SZL IDs we own: 0x0000, 0x0011, 0x001C, 0x0037,
                        # 0x0232, 0x0424, 0x0D91.
                        #
                        # Intercepted here rather than in backend_server.py
                        # because the snap7 internal hook (_get_szl_data)
                        # is absent from many installed versions.  Handling
                        # at the proxy layer is version-independent.
                        response = self.szl_identity_handler.handle(
                            session_id, peer_ip, peer_port, parsed)
                        if response:
                            client_sock.sendall(response)
                        continue

                    if (parsed is not None and self.clock_handler.handles(parsed)):
                        # Clock functions (READ_CLOCK, SET_CLOCK) intercepted
                        # here -- snap7.Server does not implement these.
                        # READ_CLOCK returns real Pi system time in S7 BCD.
                        # SET_CLOCK accepts and logs the write; does NOT
                        # change the Pi system clock.
                        response = self.clock_handler.handle(
                            session_id, peer_ip, peer_port, parsed)
                        if response:
                            client_sock.sendall(response)
                        continue

                    if (parsed is not None and self.block_list_handler.handles(parsed)):
                        # Block service (group=3): LIST/COUNT/INFO for online view.
                        # snap7.Server doesn't implement these; we serve from
                        # the block store so STEP 7/TIA Portal online view shows
                        # the correct block inventory after a download.
                        response = self.block_list_handler.handle(
                            session_id, peer_ip, peer_port, parsed)
                        if response:
                            client_sock.sendall(response)
                        continue

                    # Not intercepted -- log what we can parse and forward
                    # the raw frame to the backend unchanged.
                    parsed_fields = {}
                    if parsed is not None and parsed.is_s7_data:
                        # Try rich read/write var parsing first -- gives
                        # per-item DB/address/type/value detail in the log
                        rw = parse_from_frame(parsed)
                        if rw:
                            parsed_fields = rw
                        else:
                            fc = parsed.function_code
                            parsed_fields = {
                                "pdu_type":      parsed.pdu_type,
                                "function_code": fc,
                                "function_name": FUNCTION_CODE_NAMES.get(fc, f"0x{fc:02x}" if fc is not None else None),
                            }
                    self.cmd_logger.log_event(
                        session_id, peer_ip, peer_port, "s7_request", frame, parsed_fields
                    )
                    backend_sock.sendall(frame)
            except OSError:
                pass
            finally:
                stop_event.set()

        def backend_to_client():
            try:
                backend_sock.settimeout(60)
                first_chunk = True
                while not stop_event.is_set():
                    try:
                        chunk = backend_sock.recv(4096)
                    except socket.timeout:
                        continue
                    if not chunk:
                        break

                    # First chunk from the backend is the COTP CC (Connect
                    # Confirm). snap7.Server sets DST-REF=0x0000 instead of
                    # echoing the client's SRC-REF from the CR. Strict S7
                    # clients (not nmap, but real tools) reject this and
                    # report "TCP connected, ISO didn't". Patch it here.
                    #
                    # COTP CC layout inside TPKT frame:
                    #   [0:4]  TPKT header
                    #   [4]    COTP LI
                    #   [5]    COTP type (0xD0 = CC)
                    #   [6:8]  DST-REF  ← patch: echo client's SRC-REF
                    #   [8:10] SRC-REF  (backend's own reference)
                    #   [10]   class/options ← patch: force 0x00 for class-0
                    #
                    # snap7 sets class/options = 0x01 (explicit-flow-control
                    # bit set). STEP 7, TIA Portal, and python-snap7 all
                    # check this byte and reject with "TCP connected, ISO
                    # didn't" when it is non-zero.  S7 class-0 connections
                    # always use 0x00 here.
                    #
                    # COTP class-0 has no checksum -- direct byte patch only.
                    if (first_chunk and cotp_src_ref != 0
                            and len(chunk) >= 11
                            and chunk[5] == 0xD0):   # COTP CC
                        chunk = bytearray(chunk)
                        # 1. DST-REF: echo client's SRC-REF
                        cc_dst_ref = (chunk[6] << 8) | chunk[7]
                        if cc_dst_ref == 0x0000:
                            chunk[6] = (cotp_src_ref >> 8) & 0xFF
                            chunk[7] =  cotp_src_ref        & 0xFF
                            log.debug(
                                "Patched COTP CC DST-REF: 0x0000 → 0x%04x",
                                cotp_src_ref,
                            )
                        # 2. class/options: force 0x00 (class-0, no options)
                        if chunk[10] != 0x00:
                            log.debug(
                                "Patched COTP CC class/options: 0x%02x → 0x00 "
                                "(snap7 sets explicit-flow-control bit; "
                                "S7 clients reject non-zero value here)",
                                chunk[10],
                            )
                            chunk[10] = 0x00
                        chunk = bytes(chunk)
                    first_chunk = False
                    cc_patched.set()

                    # ── PDU negotiate ACK: correct max PDU to 480 ─────────
                    # A real CPU 315-2 PN/DP negotiates max PDU = 480 bytes
                    # (confirmed: SIMATIC S7-300 CPU 31xC/31x Technical Data,
                    # 6ES7 315-2AG10-0AB0). Both the C libsnap7 server and the
                    # pure-Python snap7 server advertise 960, which no real
                    # S7-300 ever returns — a direct fingerprint of the
                    # emulator rather than the device it claims to be.
                    #
                    # Setup-Communication ACK layout inside the TPKT frame:
                    #   [0:4]   TPKT header
                    #   [4:7]   COTP DT (LI=02, PDU type 0xF0, EOT)
                    #   [7]     S7 protocol ID (0x32)
                    #   [8]     ROSCTR (0x03 = Ack_Data)
                    #   [9:11]  redundancy id
                    #   [11:13] PDU reference
                    #   [13:15] parameter length (0x0008)
                    #   [15:17] data length
                    #   [17]    error class / error code (Ack_Data only)
                    #   [19]    function code (0xF0 = Setup communication)
                    #   [20]    reserved
                    #   [21:23] max AmQ calling
                    #   [23:25] max AmQ called
                    #   [25:27] PDU length  ← patch 0x03C0 (960) → 0x01E0 (480)
                    #
                    # Patching this rather than reconfiguring the backend keeps
                    # the fix independent of which snap7 build is installed —
                    # the same reasoning behind the COTP CC patches above.
                    if (len(chunk) >= 27
                            and chunk[7] == 0x32          # S7 protocol ID
                            and chunk[8] == 0x03          # ROSCTR Ack_Data
                            and chunk[19] == 0xF0):       # fc Setup communication
                        advertised = (chunk[25] << 8) | chunk[26]
                        if advertised != self._max_pdu:
                            chunk = bytearray(chunk)
                            chunk[25] = (self._max_pdu >> 8) & 0xFF
                            chunk[26] =  self._max_pdu        & 0xFF
                            chunk = bytes(chunk)
                            log.debug(
                                "Patched PDU negotiate: %d → %d bytes "
                                "(configured max_pdu)",
                                advertised, self._max_pdu,
                            )

                    self.cmd_logger.log_event(
                        session_id, peer_ip, peer_port, "s7_response", chunk, {}
                    )
                    client_sock.sendall(chunk)
            except OSError:
                pass
            finally:
                stop_event.set()

        t1 = threading.Thread(target=client_to_backend, daemon=True)
        t2 = threading.Thread(target=backend_to_client, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        client_sock.close()
        backend_sock.close()


if __name__ == "__main__":
    proxy = S7Proxy(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")
    proxy.start()
