"""
identity.py
-----------
Builds the SZL 0x001C (Component Identification) response payload from
config.yaml, using the field offsets Siemens firmware actually uses. These
offsets are the same ones Conpot's S7 template targets and that Nmap's
s7-info / plcscan / Shodan's S7comm parser read from.

Keeping this as a pure "config -> bytes" builder means the identity can be
swapped (different CPU family, different firmware string) without touching
any protocol handling code.
"""

from __future__ import annotations

import logging
import os
import struct
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("identity")

# ── hot-reload cache ──────────────────────────────────────────────────────────
# read_identity() checks the config file's mtime on every call and rebuilds
# the S7Identity object only when the file has changed on disk.  This is the
# same pattern cpu_state.read_cpu_state() uses: zero-restart config updates.
#
# Tests override _IDENTITY_CONFIG_PATH to point at a temp file.

_IDENTITY_CONFIG_PATH: Path = Path("config.yaml")
_identity_cache: Optional["S7Identity"] = None
_identity_mtime: float = 0.0


import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import Paths as _Paths
_NETWORK_STATE_PATH = _Paths.load().network_state


def _network_state_path() -> Path:
    """Resolve network_state.json via Paths; falls back to the default."""
    try:
        from paths import Paths
        return Paths.load().network_state
    except Exception:
        return _NETWORK_STATE_PATH


def read_identity(config_path: "Path | str | None" = None) -> "S7Identity":
    """
    Return the current S7Identity, rebuilding it if config.yaml has been
    modified since the last call.

    This makes serial number, order code, firmware version, and all other
    identity fields live-updatable: edit config.yaml and the next S7comm
    SZL query (0x0011, 0x001C, 0x0037 …) and the next SNMP walk will
    both reflect the new values without restarting any service.

    Thread-safe enough for the honeypot's single-threaded SZL path:
    worst case two threads rebuild simultaneously and one result is
    discarded, which is harmless.
    """
    global _identity_cache, _identity_mtime, _IDENTITY_CONFIG_PATH

    path = Path(config_path) if config_path else _IDENTITY_CONFIG_PATH

    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = 0.0

    if _identity_cache is None or mtime > _identity_mtime:
        try:
            cfg  = yaml.safe_load(path.read_text())
            ic   = cfg.get("identity", {})
            _identity_cache = S7Identity(
                plc_name             = ic.get("plc_name", ""),
                module_name          = ic.get("module_name", ""),
                order_code           = ic.get("order_code", ""),
                firmware_version     = ic.get("firmware_version", ""),
                firmware_version_parts = ic.get("firmware_version_parts"),
                serial_number        = ic.get("serial_number", ""),
                module_type_name     = ic.get("module_type_name", ""),
                copyright            = ic.get("copyright", ""),
                plant_id             = ic.get("plant_id", ""),
                max_pdu              = ic.get("max_pdu", 480),
            )
            _identity_mtime = mtime
            log.debug("Identity reloaded from %s (mtime=%.3f)", path, mtime)
        except Exception as exc:
            log.warning("Failed to reload identity from %s: %s", path, exc)
            if _identity_cache is None:
                raise

    return _identity_cache


def _pack_field(data: bytearray, offset: int, value: str, length: int) -> None:
    """Write a null-padded/truncated ASCII field into data at offset."""
    encoded = value.encode("ascii", errors="replace")[:length]
    data[offset:offset + length] = encoded.ljust(length, b"\x00")


@dataclass
class S7Identity:
    order_code: str
    firmware_version: str
    serial_number: str
    plc_name: str
    module_name: str
    copyright: str
    plant_id: str
    module_type_name: str
    firmware_version_parts: list = None  # set properly in __post_init__
    max_pdu: int = 480                   # negotiated PDU; 240/480/960 only

    def __post_init__(self):
        if self.firmware_version_parts is None:
            self.firmware_version_parts = [0, 0, 0]
        # Guard against a non-standard PDU, which would itself be a tell.
        if self.max_pdu not in (240, 480, 960):
            log.warning("identity.max_pdu=%s is not a standard S7 value "
                        "(240/480/960); using it anyway, but this is a "
                        "fingerprint risk", self.max_pdu)

    @classmethod
    def from_config(cls, path: str = "config.yaml") -> "S7Identity":
        with open(path, "r") as f:
            cfg = yaml.safe_load(f)
        ident = cfg["identity"]
        return cls(
            order_code=ident["order_code"],
            firmware_version=ident["firmware_version"],
            serial_number=ident["serial_number"],
            plc_name=ident["plc_name"],
            module_name=ident["module_name"],
            copyright=ident["copyright"],
            plant_id=ident.get("plant_id", ""),
            module_type_name=ident["module_type_name"],
            firmware_version_parts=ident.get("firmware_version_parts", [0, 0, 0]),
            max_pdu=ident.get("max_pdu", 480),
        )

    def build_szl_001c(self) -> bytes:
        """
        Build the SZL 0x001C payload (component identification).

        Field offsets confirmed against python-snap7 3.1.2's own parser
        (snap7/szl.py parse_cpu_info_szl) on 2026-08-26:
            ASName(24)@6, ModuleName(24)@40, Copyright(26)@108,
            SerialNumber(24)@142, ModuleTypeName(32)@176.

        Those offsets ARE the standard record layout: length-per-record 34
        (2-byte index + 32 bytes of data) after the 4-byte header, so
            4 + 34*0 + 2 = 6     record 1
            4 + 34*1 + 2 = 40    record 2
            4 + 34*3 + 2 = 108   record 4
            4 + 34*4 + 2 = 142   record 5
            4 + 34*5 + 2 = 176   record 6
        The header and per-record index fields were previously left as
        zeros, which is invisible to snap7 (it reads fixed offsets) but
        breaks any client that parses the header properly — plcscan does
        `unpack('!HHHH', data[:8])` and then splits by element size, so a
        zero length-per-record raises ValueError and the scan reports
        nothing for this SZL. Filling them in satisfies both.
        """
        LPR = 34            # 2-byte index + 32 data bytes per record
        NREC = 6
        data = bytearray(4 + LPR * NREC)         # 208 bytes
        struct.pack_into(">HH", data, 0, LPR, NREC)

        # Record indexes per the S7 spec for SZL 0x001C:
        #   1 PLC name, 2 module name, 3 plant id, 4 copyright,
        #   5 serial number, 7 module type name
        for slot, index in enumerate((1, 2, 3, 4, 5, 7)):
            struct.pack_into(">H", data, 4 + slot * LPR, index)

        _pack_field(data, 6,   self.plc_name,        24)
        _pack_field(data, 40,  self.module_name,      24)
        _pack_field(data, 74,  self.plant_id,         32)
        _pack_field(data, 108, self.copyright,        26)
        _pack_field(data, 142, self.serial_number,    24)
        _pack_field(data, 176, self.module_type_name, 32)
        return bytes(data)

    def build_order_code_szl(self) -> bytes:
        """
        SZL 0x0011, python-snap7's OWN minimal structure: order_code (20
        bytes) + firmware_version (4 bytes), 24 bytes total. Confirmed
        correct against the real library's own default implementation --
        BUT this does NOT satisfy nmap's s7-info.nse / real-PLC-derived
        expectations for this SZL ID (see build_module_identification_szl
        below). Kept for compatibility with tools that use python-snap7's
        own client (whose get_order_code() presumably expects this exact
        minimal shape), but NOT used by default in backend_server.py's
        patch -- see that file.
        """
        if len(self.order_code) > 20:
            log.warning("identity.order_code (%r) is longer than 20 bytes "
                        "and will be truncated to %r", self.order_code,
                        self.order_code[:20])
        if len(self.firmware_version) > 4:
            log.warning("identity.firmware_version (%r) is longer than 4 "
                        "bytes and will be truncated to %r", self.firmware_version,
                        self.firmware_version[:4])

        order_code = self.order_code.encode("ascii", errors="replace").ljust(20, b"\x00")[:20]
        version = self.firmware_version.encode("ascii", errors="replace").ljust(4, b"\x00")[:4]
        return order_code + version

    def build_module_identification_szl(self, total_length: int = 100) -> bytes:
        """
        SZL 0x0011 -- proper indexed-record structure, confirmed against
        two independent sources on 2026-08-26:

        1. test_plcserver.py (S7-400 reference implementation): confirmed
           length_per_record=28, 4 records, each record = index(2) +
           order_code(20) + extra_flags(6). Fields confirmed at
           szl_data-relative offsets: Module at 6, Basic Hardware at 34.

        2. Real tcpdump capture of nmap scanning our own running honeypot:
           programmatic parse confirmed szl_data content-start offset 37
           from TPKT start, strings at szl_data-relative 10 (old wrong
           placement) vs nmap-reads-from 6 and 34 (correct). Offset
           correction was applied and confirmed via programmatic byte
           counting rather than manual hex-column reading (which caused
           two counting errors before that approach was abandoned).

        Structure built:
            [0:2]   length_per_record = 28 (0x001c)
            [2:4]   num_records = 3
            -- Record 1 (Module / CPU order code) --
            [4:6]   index = 0x0001
            [6:26]  order_code, 20 bytes, null-padded    ← Module (nmap pos 44)
            [26:32] extra: 0x00 0x82 0x00 0x00 0x00 0x00
            -- Record 2 (Basic Hardware) --
            [32:34] index = 0x0006
            [34:54] order_code, 20 bytes, null-padded    ← Basic Hardware (nmap pos 72)
            [54:60] extra: 0x00 0x82 0x00 0x00 0x00 0x00
            -- Record 3 (Firmware version area) --
            [60:62] index = 0x0007
            [62:82] 20 spaces
            [82:88] extra: 0x00 0x00 0x00 ver[0] ver[1] ver[2]
                                           ↑           ← nmap reads ver[0] at pos 123 (szl_data[85])

        Total: 4 + 3×28 = 88 bytes EXACTLY.

        The default was previously padded to 100 bytes, so the declared
        header (28 × 3 = 84 body bytes) disagreed with the 96 actually
        present. snap7 reads fixed offsets and never noticed, but a client
        that splits the body by length-per-record — plcscan does exactly
        that — gets a fourth, truncated record. Real hardware returns
        precisely length_per_record × num_records bytes.
        """
        data = bytearray(4 + 28 * 3)
        order_code_bytes = self.order_code.encode("ascii", errors="replace")[:20].ljust(20, b"\x00")

        # SZL header
        struct.pack_into(">HH", data, 0, 28, 3)   # length_per_record=28, num_records=3

        # Record 1 — Module (order code)
        struct.pack_into(">H", data, 4, 0x0001)
        data[6:26] = order_code_bytes
        data[26:32] = b"\x00\x82\x00\x00\x00\x00"

        # Record 2 — Basic Hardware (same order code, different index)
        struct.pack_into(">H", data, 32, 0x0006)
        data[34:54] = order_code_bytes
        data[54:60] = b"\x00\x82\x00\x00\x00\x00"

        # Record 3 — Firmware version
        struct.pack_into(">H", data, 60, 0x0007)
        data[62:82] = b" " * 20   # 20 spaces, matching reference implementation
        parts = (self.firmware_version_parts + [0, 0, 0])[:3]
        # version bytes land at szl_data[85:88] = record3_extra[3:6]
        data[82:88] = bytes([0x00, 0x00, 0x00, parts[0] & 0xFF, parts[1] & 0xFF, parts[2] & 0xFF])

        return bytes(data)

    def build_cpu_status_szl(self, cpu_state_str: str = "RUN") -> bytes:
        """
        SZL 0x0424 -- CPU scan cycle / operating mode status.

        CONFIRMED 2026-08-28 from real pcap (s7comm_reading_plc_status.pcap).
        Real status tools query this SZL repeatedly (not just nmap). Our
        earlier szl_status_handler.py fabricated an incorrect structure
        and was disabled. Now implemented with the confirmed real format.

        Confirmed szl_data layout (24 bytes total):
            [0:2]   length_per_record = 20  (0x0014)
            [2:4]   num_records = 1         (0x0001)
            --- Record (20 bytes) ---
            [4:6]   identifier = 0x5144     (confirmed from capture)
            [6:8]   mode word: high byte=0xFF (fixed), low byte=mode
                    0xFF08 = STOP  (low byte 0x08 = STOP)
                    0xFF28 = RUN   (low byte 0x28 = RUN)
            [8:16]  zeros (8 bytes)
            [16:24] 8-byte BCD-format timestamp (current time)

        The mode low byte 0x08/0x28 matches the standard Siemens
        CPU operating mode encoding used across multiple SZL types.
        """
        import datetime
        now = datetime.datetime.now()

        mode_low = 0x08 if cpu_state_str == "STOP" else 0x28
        mode_word = (0xFF << 8) | mode_low

        # 8-byte timestamp in format observed in capture:
        # day(1) month(1) year_lo(1) year_lo2(1) hour(1) min(1) sec(1) subsec(1)
        # From capture: 14 08 20 12 05 28 34 94 = 2012-08-14 05:28 approx
        def bcd(n): return ((n // 10) << 4) | (n % 10)
        yr = now.year % 100
        ts_bytes = bytes([
            bcd(now.day), bcd(now.month), bcd(yr // 10), bcd(yr % 10),
            bcd(now.hour), bcd(now.minute), bcd(now.second),
            (now.microsecond // 100000) & 0xFF,
        ])

        record = struct.pack(">HH", 0x5144, mode_word) + b"\x00" * 8 + ts_bytes
        szl_data = struct.pack(">HH", 20, 1) + record   # 4 header + 20 record

        return bytes(szl_data)

    def build_module_status_szl(self) -> bytes:
        """
        SZL 0x0D91 -- Module run state.

        CONFIRMED 2026-08-28 from real pcap. This SZL is polled in a
        tight loop by status tools -- it's the primary 'is the device
        alive?' check. Returning the observed 20-byte pattern signals
        that the module is present and operating normally.

        Confirmed raw szl_data (20 bytes, always the same in the capture,
        does not change with CPU state):
            00 10 00 01  -- lpr=16, nrec=1
            00 00 02 00  -- record[0:4]
            7F FF        -- record[4:6] (0x7FFF = max/unlimited?)
            00 C0 00 C0  -- record[6:10] (capability flags?)
            00 00 B4 02 00 11  -- record[10:16]
        """
        return bytes.fromhex("00100001000002007fff00c000c00000b4020011")

    def build_network_info_szl(self, network_state: dict | None = None) -> bytes:
        """
        SZL 0x0037 -- Ethernet/IP interface configuration.

        Sources IP, subnet mask, and MAC from the network_state dict
        (populated by boot_ip_writer.py at startup from the live
        interface).  Falls back to zeros if not available.

        Confirmed byte layout (4-byte header + 48-byte record = 52 bytes):
            header: lpr=48, nrec=1
            record[0:2]   = index 0xFFFF
            record[2:6]   = IP address (4 bytes, big-endian octets)
            record[6:10]  = subnet mask (4 bytes)
            record[10:14] = zeros (4 bytes reserved)
            record[14:20] = MAC address (6 bytes)
            record[20:48] = zeros (28 bytes padding)
        """
        def parse_ip(s):
            try:
                return bytes(int(o) for o in s.split("."))
            except Exception:
                return b"\x00" * 4

        def parse_mac(s):
            try:
                return bytes(int(b, 16) for b in s.split(":"))
            except Exception:
                return b"\x00" * 6

        state = network_state or {}
        if not state:
            from pathlib import Path
            import json as _json
            p = _network_state_path()
            if p.exists():
                try:
                    state = _json.loads(p.read_text())
                except Exception:
                    pass

        ip_bytes   = parse_ip(state.get("ip_address", "0.0.0.0"))
        mask_bytes = parse_ip(state.get("netmask",    "255.255.255.0"))
        mac_bytes  = parse_mac(state.get("mac_address","00:00:00:00:00:00"))

        record  = struct.pack(">H", 0xFFFF)   # index
        record += ip_bytes                     # [2:6]  IP
        record += mask_bytes                   # [6:10] mask
        record += b"\x00" * 4                 # [10:14] reserved
        record += mac_bytes                    # [14:20] MAC
        record += b"\x00" * 28                # [20:48] padding
        assert len(record) == 48

        return struct.pack(">HH", 48, 1) + record   # header + record

    def build_szl_list(self) -> bytes:
        """
        SZL 0x0000 — list of all SZL IDs supported by this module.

        s7scan.py calls read_szl_list() first and uses the returned list
        to gate whether it queries each subsequent SZL (line 371 of s7scan):
            if (len(szl_list) == 0) or (szl in szl_list): query it

        If 0x0000 falls through to snap7, snap7 returns its own internal
        list which may not include 0x0037, 0x0232, 0x0424, 0x0D91 that we
        added to the _get_szl_data patch.  That causes s7scan to skip our
        ethernet details page and log "Error reading SZL list".

        This list matches what a real S7-315-2 PN/DP firmware V2.6 exposes.
        Confirmed IDs cross-referenced against the s7comm_reading_plc_status
        capture (which showed 35 distinct SZL reads from a real device).
        """
        szl_ids = [
            0x0000,  # SZL list itself
            0x0011,  # Module identification (order code, firmware)
            0x0012,  # Module characteristics
            0x0013,  # Memory areas
            0x0014,  # Block types supported
            0x0015,  # No restart after error
            0x0017,  # Block types (detail)
            0x001A,  # System areas
            0x001B,  # Block areas
            0x001C,  # Component identification (PLC name, serial)
            0x001D,  # Interrupt status
            0x0021,  # Interrupt list
            0x0022,  # Module status info
            0x0023,  # I/O status
            0x0024,  # Module rack config
            0x0025,  # User-defined diagnostic events
            0x0031,  # Communication status data
            0x0032,  # Protection-related
            0x0036,  # Block information
            0x0037,  # Ethernet details (IP/MAC)
            0x0038,  # Blocks (alternate)
            0x0039,  # Module diagnostic info
            0x003A,  # Module status
            0x0074,  # PLC hardware config
            0x0091,  # Diagnostic buffer overview
            0x0092,  # Diagnostic buffer detail
            0x0094,  # Communication connections
            0x0095,  # IEC diagnostics
            0x0096,  # OB priorities
            0x009A,  # Telegram information
            0x00A0,  # Diagnostic buffer (full)
            0x00B1,  # S7 message buffer
            0x00B2,  # S7 message (send)
            0x0112,  # Hardware configuration
            0x0131,  # Communication parameters
            0x0132,  # Communication partners
            0x0174,  # DP diagnostics
            0x0222,  # DP cyclic
            0x0232,  # Protection level
            0x0424,  # CPU scan / operating mode
            0x0474,  # DP redundancy
            0x0D91,  # Module run state (polled)
            0x00A0,  # Diagnostic buffer (CPU event history)
        ]
        lpr  = 2   # 2 bytes per record (each record = 1 SZL ID)
        nrec = len(szl_ids)
        body = b"".join(struct.pack(">H", sid) for sid in szl_ids)
        return struct.pack(">HH", lpr, nrec) + body

    def build_diagnostic_buffer_szl(self) -> bytes:
        """
        SZL 0x00A0 -- Diagnostic Buffer (S7-300).

        S7 clients (python-snap7, STEP 7, TIA Portal) query this SZL to
        display the CPU's event history.  Without a response, python-snap7
        raises 'CPU error' and tools show a blank diagnostic page.

        Format (20 bytes per record, newest entry first):
            szl_data[0:2]  = lpr = 20
            szl_data[2:4]  = nrec = N (number of entries)
            per record:
              [0:2]  event_id: class(1) + number(1)
              [2:4]  additional info
              [4:12] timestamp — 8-byte S7 BCD, same as READ_CLOCK:
                       year%100, month, day, hour, min, sec, ms_hi,
                       (ms_lo<<4) | DOW (1=Sun..7=Sat)
              [12:20] event-specific params (zeros for most entries)

        Common S7-315 event IDs (Siemens System Manual + Wireshark dissector):
            0x8552 — CPU startup / power on complete
            0x4803 — Cold restart complete (STOP phase done)
            0x4800 — Mode transition: STOP → RUN
            0x5481 — OB1 first scan begins (RUN confirmed)
            0x5500 — PROFIBUS DP cyclic exchange active
            0x4001 — Scan cycle monitoring OK (periodic heartbeat)

        The timestamps are derived from the fake_boot_epoch stored in
        network_state.json, so the event history is consistent with the
        uptime shown by the web portal and SNMP sysUpTime.
        """
        import json as _json
        import time as _time
        import datetime as _dt

        # Read boot epoch from shared state
        try:
            ns = _json.loads(
                _network_state_path().read_text()
            )
            boot_epoch = ns.get("fake_boot_epoch", _time.time() - 7200)
        except Exception:
            boot_epoch = _time.time() - 7200

        now_epoch = _time.time()
        uptime_s  = now_epoch - boot_epoch

        def bcd(n: int) -> int:
            return ((n // 10) << 4) | (n % 10)

        def s7_ts(epoch: float) -> bytes:
            """8-byte S7 BCD timestamp from a Unix epoch."""
            dt  = _dt.datetime.fromtimestamp(epoch)
            dow = (dt.weekday() + 1) % 7 + 1   # 1=Sun..7=Sat
            ms  = dt.microsecond // 1000
            return bytes([
                bcd(dt.year % 100), bcd(dt.month), bcd(dt.day),
                bcd(dt.hour), bcd(dt.minute), bcd(dt.second),
                bcd(ms // 10),
                ((ms % 10) << 4) | dow,
            ])

        def entry(event_class: int, event_num: int,
                  epoch: float, info: int = 0) -> bytes:
            """
            One 20-byte diagnostic buffer record, S7-300 layout.

            CONFIRMED layout (Siemens S7-300 diagnostic buffer entry, and
            matching the Wireshark s7comm dissector):
                [0:2]   event ID (class << 8 | number)
                [2]     priority class
                [3]     OB number
                [4:6]   reserved / datdid
                [6:12]  additional info 1-3
                [12:20] timestamp, DATE_AND_TIME, 8-byte BCD

            The timestamp previously sat at [4:12], so clients read zeros
            from [12:20] and displayed "[unknown time]" for every entry.
            """
            rec = bytearray(20)
            struct.pack_into(">H", rec, 0, (event_class << 8) | event_num)
            rec[2] = 0x01                    # priority class 1 (normal)
            rec[3] = 0x01                    # OB 1
            struct.pack_into(">H", rec, 6, info)
            rec[12:20] = s7_ts(epoch)        # DATE_AND_TIME goes here
            return bytes(rec)

        # ── boot sequence (always present) ───────────────────────────
        # Records are collected as (epoch, bytes) so synthetic and stored
        # events can be merged and sorted; stripped to bytes before packing.
        def tentry(cls, num, epoch, info=0):
            return (epoch, entry(cls, num, epoch, info))

        records = [
            # class  num    offset_s  description
            tentry(0x85, 0x52, boot_epoch + 0),    # Power on / startup complete
            tentry(0x48, 0x03, boot_epoch + 1),    # Cold restart (STOP phase)
            tentry(0x48, 0x00, boot_epoch + 5),    # STOP → RUN transition
            tentry(0x54, 0x81, boot_epoch + 6),    # OB1 first scan / RUN confirmed
            tentry(0x55, 0x00, boot_epoch + 10),   # PROFIBUS DP active
        ]

        # ── periodic scan-cycle OK events (every 30 min) ─────────────
        # Bounded: only generate enough to fill one PDU. Previously this
        # looped across the whole uptime (1440 records at 30 days) and then
        # threw nearly all of them away.
        t = max(boot_epoch + 1800, now_epoch - 40 * 1800)
        while t < now_epoch - 60:
            records.append(tentry(0x40, 0x01, t))  # Scan cycle monitoring OK
            t += 1800

        # ── real process events from the shared SQLite buffer ─────────
        # The web portal and this SZL must show the SAME history: an
        # attacker who reads SZL 0x00A0 over S7comm and then opens the web
        # portal would otherwise see two different event logs from one
        # device. Both now read diag_log; only the record count differs,
        # which is correct — S7comm is PDU-limited, the web server is not.
        try:
            import diag_log as _dl
            for fake_ts, desc in _dl.load_events(limit=40):
                cls, num = 0x48, 0x10          # generic user/process event
                low = desc.lower()
                if "alarm" in low:
                    cls, num = 0x39, 0x01      # process alarm
                elif "stop" in low and "mode" in low:
                    cls, num = 0x48, 0x01      # RUN -> STOP
                elif "run" in low and "mode" in low:
                    cls, num = 0x48, 0x00      # STOP -> RUN
                records.append(tentry(cls, num, fake_ts))
        except Exception:
            pass    # SZL must still build if the DB is unavailable

        # Chronological, then reversed to newest-first below
        records.sort(key=lambda r: r[0])

        # Newest first. Cap by PDU SIZE, not just record count.
        #
        # A real S7-315 holds 100 diagnostic entries, but it cannot return
        # them all in one response: at 20 bytes per record, 100 records is
        # 2004 bytes with the header, and the negotiated max PDU is 480.
        # Returning an oversized response makes the client fail with an
        # opaque protocol error (observed: "Read SZL failed: Unknown error
        # (0x81)") once uptime grew enough to generate many scan-cycle
        # entries. Real hardware returns the newest records that fit and
        # sets the more-follows flag; clients page with szl_index.
        #
        # Budget: max_pdu - ~60 bytes of S7 header/params/data-header, divided
        # by 20 bytes per record. At 480 that's ~21 records; at 240 it's ~9.
        # This MUST track the negotiated PDU: an oversized response exceeds the
        # PDU and the client throws "Read SZL failed: Unknown error (0x81)".
        # Real hardware returns only what fits and pages the rest via szl_index.
        _RECORD_BYTES = 20
        _PDU_OVERHEAD = 72   # TPKT+COTP+S7 header+params+SZL data-header, with
                             # headroom so the framed response stays under the PDU
        _max_records = max(1, (self.max_pdu - _PDU_OVERHEAD) // _RECORD_BYTES)
        records = [rec for _ts, rec in reversed(records)][:_max_records]

        lpr  = _RECORD_BYTES
        nrec = len(records)
        return struct.pack(">HH", lpr, nrec) + b"".join(records)

    def build_protection_szl(self) -> bytes:
        """
        SZL 0x0232 — Module protection data.

        s7scan.py calls read_protection() specifically and parses the result
        into a ProtectionRecord.  Without this, s7scan logs:
            'Error occurred while reading module protection info'
        which is a clear signal the device is not a real PLC.

        Format confirmed from Siemens documentation for S7-300 CPUs:
            length_per_record = 10 bytes
            num_records = 1
            Record layout (10 bytes):
              [0:2]  index = 0x0001
              [2:4]  sch_schutz: key-switch protection
                     0 = no protection (full access, default for unprotected PLC)
              [4:6]  cpu_schutz: CPU protection level
                     0 = no restriction
              [6:8]  anl_schutz: startup protection
                     0 = no restriction
              [8:10] mode_sel: mode selector position
                     3 = RUN position (normal operating state)

        An unprotected S7-315 in RUN with key switch at RUN returns exactly
        these values.  Returning "no protection" is realistic for an exposed
        PLC on an unsegmented network -- which is precisely the scenario our
        honeypot is simulating.
        """
        record = struct.pack(">HHHHH",
            0x0001,   # index
            0x0000,   # sch_schutz: no key-switch protection
            0x0000,   # cpu_schutz: no CPU protection
            0x0000,   # anl_schutz: no startup protection
            0x0003,   # mode_sel:   key switch in RUN position
        )
        lpr  = 10
        nrec = 1
        return struct.pack(">HH", lpr, nrec) + record
        """
        SZL 0x0037 — network configuration. Confirmed field layout from
        test_plcserver.py reference implementation:
            Record (48 bytes, index included):
            [0:2]   index 0xffff
            [2:6]   IP address (4 bytes)
            [6:10]  subnet mask (4 bytes)
            [10:14] default gateway (same as IP for simple setups)
            [14:20] MAC address (6 bytes)
            [20:22] 0x01 0x00
            [22:30] 8 zero bytes
            [30:48] mostly zeros (0x8f 0x88 at [30:32] in reference -- TBD)

        Sources network state from /var/lib/s7honeypot/network_state.json
        written by boot_ip_writer.py at boot -- same file SNMP already
        uses, ensuring consistency across all four identity surfaces
        (S7comm SZL 0x0037, S7comm SZL 0x001C, SNMP ifPhysAddress,
        web portal CPU status row).
        """
        import json
        from pathlib import Path

        state = network_state or {}
        if not state:
            state_path = _network_state_path()
            if state_path.exists():
                try:
                    state = json.loads(state_path.read_text())
                except (json.JSONDecodeError, OSError):
                    pass

        def parse_ip(ip_str: str) -> bytes:
            try:
                return bytes(int(o) for o in ip_str.split("."))
            except Exception:
                return b"\x00\x00\x00\x00"

        def parse_mac(mac_str: str) -> bytes:
            try:
                return bytes(int(b, 16) for b in mac_str.split(":"))
            except Exception:
                return b"\x00\x00\x00\x00\x00\x00"

        ip_bytes   = parse_ip(state.get("ip_address", "0.0.0.0"))
        mask_bytes = parse_ip(state.get("netmask", "255.255.255.0"))
        gw_bytes   = ip_bytes  # use device IP as gateway -- realistic for many S7-300 setups
        mac_bytes  = parse_mac(state.get("mac_address", "00:00:00:00:00:00"))

        szl_data = bytearray(52)   # 4 header + 1×48 record
        struct.pack_into(">HH", szl_data, 0, 48, 1)  # length_per_record=48, num_records=1

        # Record at szl_data[4:52]
        struct.pack_into(">H", szl_data, 4, 0xFFFF)  # index
        szl_data[6:10]  = ip_bytes
        szl_data[10:14] = mask_bytes
        szl_data[14:18] = gw_bytes
        szl_data[18:24] = mac_bytes
        szl_data[24:26] = b"\x01\x00"
        # [26:52] zeros (including the 0x8f88 field seen in reference --
        # left zero here since its meaning isn't clear and a real S7-300
        # may use a different value than the S7-400 reference shows)

        return bytes(szl_data)

    # ── Tier 2 SZLs from Wireshark dissector + CPU Technical Data ─────────────
    # Sources:
    #   Wireshark packet-s7comm_szl_ids.c (Thomas Wiens, verified against HW)
    #   Siemens SIMATIC S7-300 CPU 31xC/31x Technical Data, A5E00105475-08
    #   CPU 315-2 DP (6ES7315-2AG10-0AB0) firmware V2.6 specifications
    #
    # Field sequences derived from dissector hf_* field declarations.
    # Values derived from confirmed CPU Technical Data PDF specs.
    # These return data rather than errors for STEP 7 Module Information
    # queries — a meaningful fidelity improvement over falling through to snap7.

    def build_memory_areas_szl(self) -> bytes:
        """
        SZL 0x0013 — User memory areas.

        Dissector: szl_0113_index_names, hf_s7comm_szl_0013_0000_*
        lpr=22 bytes per record:
          [0:2]   index   UINT16
          [2:3]   code    UINT8  (1=volatile RAM, 2=FEPROM, 3=mixed)
          [3:4]   pad     UINT8
          [4:8]   size    UINT32 total bytes
          [8:9]   mode    UINT8  flags
          [9:10]  granu   UINT8  granularity
          [10:12] ber1    UINT16 range1 total (KB units)
          [12:14] belegt1 UINT16 range1 used  (KB units)
          [14:16] block1  UINT16 block size 1
          [16:18] ber2    UINT16 range2 total
          [18:20] belegt2 UINT16 range2 used
          [20:22] block2  UINT16 block size 2

        CPU 315-2 DP (6ES7315-2AG10-0AB0) confirmed specs:
          Work memory: 128 KB volatile RAM
          Load memory integrated: 64 KB FEPROM
          Load memory (MMC plugged): 0 / max 8 MB
        """
        WORK_MEM   = 128 * 1024        # 131072 bytes
        WORK_USED  = 22  * 1024        # ~22 KB used (typical small OB1+DBs)
        LOAD_INT   = 64  * 1024        # 65536 bytes integrated FEPROM
        LOAD_MMC   = 0                 # no MMC inserted (0 = empty)
        LOAD_MAX   = 8 * 1024 * 1024   # 8 MB maximum pluggable MMC

        def rec(index, code, size, used):
            ber1    = size // 1024 if size else 0
            belegt1 = used // 1024 if used else 0
            return struct.pack(">HBBI BBHHHHHH",
                index, code, 0, size,
                0x05, 1,                 # mode=5, granu=1
                ber1, belegt1, 1,        # ber1, belegt1, block1
                0, 0, 0)                 # ber2, belegt2, block2

        records = [
            rec(0x0001, 0x01, WORK_MEM,  WORK_USED),  # work memory volatile
            rec(0x0002, 0x02, LOAD_INT,  LOAD_INT),   # load memory integrated FEPROM
            rec(0x0003, 0x03, LOAD_MMC,  0),           # load memory plugged (MMC)
            rec(0x0004, 0x02, LOAD_MAX,  0),           # max pluggable load memory
            rec(0x0005, 0x01, 0,          0),           # backup memory (none)
            rec(0x0006, 0x01, 0,          0),           # memory reserved for CFBs
        ]
        lpr, nrec = 22, len(records)
        return struct.pack(">HH", lpr, nrec) + b"".join(records)

    def build_system_areas_szl(self) -> bytes:
        """
        SZL 0x0014 — System areas (PII, PIQ, markers, timers, counters).

        Dissector: szl_0114_index_names, hf_s7comm_szl_xy14_000x_*
        lpr=8 bytes per record:
          [0:2] index    UINT16  area type
          [2:4] code     UINT16  same as index
          [4:6] quantity UINT16  size or count
          [6:8] reman    UINT16  retentive quantity

        CPU 315-2 DP (6ES7315-2AG10-0AB0) confirmed Technical Data:
          PII: 128 bytes | PIQ: 128 bytes
          Marker bytes: 256 (MB0-MB255)
          S7 Timers: 256  |  S7 Counters: 256
        """
        def rec(idx, qty, rem=0):
            return struct.pack(">HHHH", idx, idx, qty, rem)

        records = [
            rec(0x0001, 128,   0),    # PII: 128 bytes process image inputs
            rec(0x0002, 128,   0),    # PIQ: 128 bytes process image outputs
            rec(0x0003, 256,  16),    # Marker bytes: 256, 16 retentive (MB0-MB15)
            rec(0x0004, 256,   0),    # S7 timers: 256
            rec(0x0005, 256,   0),    # S7 counters: 256
            rec(0x0006, 8192,  0),    # Logical address bytes: 8192
            rec(0x0007, 32768, 0),    # Local data area: 32768 bytes total
            rec(0x0008, 256,   0),    # Marker bytes (count variant)
            rec(0x0009, 32,    0),    # Local data in KB: 32
        ]
        lpr, nrec = 8, len(records)
        return struct.pack(">HH", lpr, nrec) + b"".join(records)

    def build_comm_capability_szl(self, szl_index: int = 0x0001) -> bytes:
        """
        SZL 0x0131 — Communication capability parameters, index 0x0001.

        Dissector: hf_s7comm_szl_0131_0001_*
        lpr=20 bytes:
          [0:2]   index   UINT16 = 0x0001
          [2:4]   pdu     UINT16 max PDU size = 480 (S7-315 spec)
          [4:6]   anz     UINT16 max connections = 16
          [6:10]  mpi_bps UINT32 MPI baud = 12,000,000
          [10:14] kbus_bps UINT32 K-bus baud = 0 (no K-bus)
          [14:20] res     6 bytes reserved

        The max PDU of 480 is the confirmed spec for the S7-315-2 DP.
        snap7 advertises 960 in its negotiate PDU — this SZL contains
        the authoritative value that STEP 7 uses for capability display.
        """
        MAX_PDU  = self.max_pdu       # from config (240/480/960)
        MAX_CONNS = 16
        MPI_BPS  = 12_000_000

        if szl_index in (0x0000, 0x0001):
            rec = (struct.pack(">HHHI", 0x0001, MAX_PDU, MAX_CONNS, MPI_BPS)
                   + struct.pack(">I", 0)       # kbus_bps
                   + b"\x00" * 6)               # reserved
            lpr, nrec = 20, 1
        else:
            lpr, nrec, rec = 20, 0, b""
        return struct.pack(">HH", lpr, nrec) + rec

    def build_comm_status_szl(self, szl_index: int = 0x0004,
                              cpu_state_str: str = "RUN") -> bytes:
        """
        SZL 0x0132 — Communication status data.

        Index 0x0001 — general connection data (lpr=20):
          [0:2]  index    UINT16
          [2:4]  res_pg   UINT16  reserved PG connections = 1
          [4:6]  res_os   UINT16  reserved OS connections = 1
          [6:8]  u_pg     UINT16  used PG = 0
          [8:10] u_os     UINT16  used OS = 0
          [10:12]proj     UINT16  configured = 4
          [12:14]auf      UINT16  established = 0
          [14:16]free     UINT16  free = 12
          [16:18]used     UINT16  in use = 0
          [18:20]last     UINT16

        Index 0x0004 — key switch / mode (lpr=26):
          Dissector: hf_s7comm_szl_0132_0004_*, szl_bart_sch_names
          [0:2]  index      UINT16
          [2:4]  key        UINT16  1=RUN, 3=STOP (physical key position)
          [4:6]  param      UINT16  1=CRST (parameter memory restart type)
          [6:8]  real       UINT16  actual operating mode
          [8:10] bart_sch   UINT16  key switch setting (1=RUN, 3=STOP)
          [10:12]crst_wrst  UINT16  1=CRST
          [12]   ken_f      UINT8   module features = 0
          [13]   ken_rel    UINT8   firmware release = 6 (V2.6)
          [14]   ken_ver1_hw UINT8  HW version major = 1
          [15]   ken_ver2_hw UINT8  HW version minor = 0
          [16]   ken_ver1_awp UINT8 AW prog major = 2
          [17]   ken_ver2_awp UINT8 AW prog minor = 6
          [18:26]res        8 bytes reserved
        """
        run = (cpu_state_str == "RUN")
        mode_val = 1 if run else 3   # szl_bart_sch_names: 1=RUN, 3=STOP

        if szl_index in (0x0000, 0x0001):
            rec = struct.pack(">HHHHHHHHHH",
                0x0001, 1, 1, 0, 0, 4, 0, 12, 0, 0)
            lpr, nrec = 20, 1
            return struct.pack(">HH", lpr, nrec) + rec

        elif szl_index == 0x0004:
            rec = struct.pack(">HHHHHH",
                0x0004, mode_val, 1, mode_val, mode_val, 1)
            rec += struct.pack(">BBBBBB",
                0,    # ken_f
                6,    # ken_rel: firmware release 6 → V2.6
                1,    # ken_ver1_hw
                0,    # ken_ver2_hw
                2,    # ken_ver1_awp
                6)    # ken_ver2_awp
            rec += b"\x00" * 8   # reserved
            lpr, nrec = 26, 1
            return struct.pack(">HH", lpr, nrec) + rec

        else:
            return struct.pack(">HH", 20, 0)   # empty — unknown index


if __name__ == "__main__":
    ident = S7Identity.from_config("config.yaml")
    payload = ident.build_szl_001c()
    print(f"SZL 0x001C payload ({len(payload)} bytes):")
    print(payload.hex())
