#!/usr/bin/env python3
"""
Interactive S7 client (built on python-snap7).

Connects once, then drops into a menu-driven REPL where you can repeatedly
issue "commands" against the target and see a human-readable (ASCII) dump
of the response:

  - Module identification   (SZL 0x0011)
  - Component identification (SZL 0x001C)
  - Protection info          (SZL 0x0232 / index 0x0004)
  - Ethernet details         (SZL 0x0037)
  - Diagnostic buffer        (SZL 0x00A0 -- event log)
  - CPU state / info / order code
  - CPU control: STOP / HOT START / COLD START

Intended for testing against an S7 honeypot (e.g. Conpot's s7comm
template) or a real S7-300/400 CPU you're authorized to test.

Usage:
    python3 s7_repl.py <host> [--port 102] [--rack 0] [--slot 2]
"""

import argparse
import struct
import sys
import time

import snap7
from snap7.client import Client
from snap7.error import S7Error
from snap7.type import Parameter


# --------------------------------------------------------------------------
# SZL record parsers
#
# python-snap7's read_szl() returns an S7SZL ctypes struct: Header
# (LengthDR = bytes per record, NDR = number of records) followed by a
# Data byte array that already has the SZL-ID/index stripped off by the
# underlying snap7 library -- so Data is just NDR records, each LengthDR
# bytes, back to back.
# --------------------------------------------------------------------------

def szl_records(szl) -> list:
    """Split an S7SZL struct's Data into a list of raw per-record bytes."""
    length_dr = szl.Header.LengthDR
    ndr = szl.Header.NDR
    total = length_dr * ndr
    raw = bytes(bytearray(szl.Data[:total]))
    return [raw[i:i + length_dr] for i in range(0, total, length_dr)]


def parse_module_id_blob(data: bytes) -> list:
    """
    Parse the full SZL 0x0011 (Module Identification) data blob.

    Ground-truthed against a real target: the blob starts with a 4-byte
    mini-header -- 2 bytes record length, 2 bytes record count -- that
    duplicates what's already in S7SZL.Header, followed by that many
    fixed-length records: index(2) + order number(20, ASCII/NUL-padded)
    + BGType(2) + version-major(2) + version-minor/patch(2).
    """
    if len(data) < 4:
        return []
    record_len, count = struct.unpack("!HH", data[0:4])
    records = []
    offset = 4
    for _ in range(count):
        rec = data[offset:offset + record_len]
        if len(rec) < record_len:
            break
        records.append(rec)
        offset += record_len
    return records


def fmt_module_id(record: bytes) -> str:
    # 28-byte record: index(2), order number(20, space/NUL padded),
    # BGType(2), version-major(2), version-minor/patch(2)
    index = struct.unpack("!H", record[0:2])[0]
    order_number = record[2:22].strip(b" ").strip(b"\x00").decode("ascii", errors="replace")
    ausbg = struct.unpack("!H", record[24:26])[0]
    ausbe = struct.unpack("!H", record[26:28])[0]
    version = f"{ausbg & 0xFF}.{(ausbe >> 8) & 0xFF}.{ausbe & 0xFF}"
    label = {1: "Module", 6: "Basic hardware", 7: "Basic firmware"}.get(index, f"Unknown index {index}")
    lines = [label]
    if order_number:
        lines.append(f"    Order number: {order_number}")
    lines.append(f"    Version: {version}")
    return "\n".join(lines)


def fmt_component_id(record: bytes) -> str:
    index = struct.unpack("!H", record[0:2])[0]
    labels = {
        1: "PLC name", 2: "Module name", 3: "Plant identification",
        4: "Stamp", 5: "Serial number", 7: "Module type name",
        8: "Memory card serial number", 9: "Manufacturer/profile info",
        10: "OEM copyright info", 11: "Location designation",
    }
    if index == 9:
        manufacturer_id, profile_id, profile_type = struct.unpack("!HHH", record[2:8])
        return f"Manufacturer/profile info\n    Manufacturer ID: {manufacturer_id}; Profile ID: {profile_id}; Profile type: {profile_type}"
    name_end = {1: 26, 2: 26, 5: 26, 3: 34, 7: 34, 8: 34, 11: 34, 4: 28, 10: 28}.get(index, len(record))
    name = record[2:name_end].strip(b"\x00").decode("ascii", errors="replace")
    label = labels.get(index, f"Unknown index {index}")
    if not name:
        return None
    return f"{label}: {name}"


def parse_protection_blob(data: bytes) -> bytes:
    """
    SZL 0x0232 also has the 4-byte mini-header (record length, record
    count) in front of the actual data, same as SZL 0x0011 -- confirmed
    against a real target: length=10, count=1, followed by one 10-byte
    record of five uint16 fields.
    """
    record = strip_szl_mini_header(data)
    return record if len(record) >= 10 else None


def fmt_protection(record: bytes) -> str:
    sch_schal, sch_par, sch_rel, bart_sch, anl_sch = struct.unpack("!HHHHH", record[0:10])
    mode_names = {1: "RUN", 2: "RUN-P", 3: "STOP", 4: "MRES"}
    startup_names = {1: "CRST", 2: "WRST"}
    lines = [
        f"Mode selector (parameterized): {sch_schal} ({mode_names.get(sch_schal, 'undefined')})",
        f"    Protection level (parameterized): {sch_par}",
        f"    Protection level (in load memory): {sch_rel}",
        f"    Mode-selector switch, actual position: {bart_sch} ({mode_names.get(bart_sch, 'no physical switch / undefined')})",
        f"    Startup switch position: {anl_sch} ({startup_names.get(anl_sch, 'no physical switch / undefined')})",
    ]
    return "\n".join(lines)


def strip_szl_mini_header(data: bytes) -> bytes:
    """
    Several SZL responses on this target (0x0011, 0x0232, 0x0037 confirmed
    so far) embed a redundant 4-byte {record length, record count} header
    at the front of the data blob, duplicating what's already in the outer
    S7SZL.Header. This strips it and returns just the first record's bytes.
    """
    if len(data) < 4:
        return data
    record_len, count = struct.unpack("!HH", data[0:4])
    if count < 1 or len(data) < 4 + record_len:
        return data
    return data[4:4 + record_len]


def fmt_eth_details(record: bytes) -> str:
    # 48-byte record (SZL 0x0037)
    from socket import inet_ntoa
    logaddr = struct.unpack("!H", record[0:2])[0]
    ip_addr = inet_ntoa(record[2:6])
    subnet = inet_ntoa(record[6:10])
    gateway = inet_ntoa(record[10:14])
    mac = ":".join("{:02x}".format(b) for b in record[14:20])
    source = record[20]
    source_str = {
        0: "IP address not initialized",
        1: "IP address was configured in STEP 7",
        2: "IP address was set via DCP",
        3: "IP address was obtained from a DHCP server",
    }.get(source, "")
    lines = [f"Logical base address: 0x{logaddr:X}"]
    # Some targets (seen on honeypots) leave `source` at 0 ("not
    # initialized") even when a real IP is populated -- only trust that
    # label when it isn't contradicted by an actual non-zero IP.
    if ip_addr != "0.0.0.0":
        lines.append(f"    IP address: {ip_addr}/{subnet}")
        lines.append(f"    Default gateway: {gateway}")
    elif source_str:
        lines.append(f"    {source_str}")
    lines.append(f"    MAC address: {mac}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Command implementations
# --------------------------------------------------------------------------

def cmd_module_id(client: Client):
    szl = client.read_szl(0x0011, 0x0000)
    total = szl.Header.LengthDR * szl.Header.NDR
    blob = bytes(bytearray(szl.Data[:total]))
    records = parse_module_id_blob(blob)
    if not records:
        print("  (no records returned)")
        return
    for r in records:
        print("  " + fmt_module_id(r).replace("\n", "\n  "))


def cmd_component_id(client: Client):
    # SZL 0x001C, when read with index=0, returns ONE flat fixed-layout
    # structure (AS name, module name, copyright, serial number, module
    # type name at fixed offsets) rather than a list of separately-indexed
    # records. python-snap7's own get_cpu_info() already parses this
    # correctly (confirmed against this target), so reuse it instead of
    # re-implementing (and getting wrong) the same offsets here.
    info = client.get_cpu_info()
    fields = [
        ("AS name", info.ASName),
        ("Module name", info.ModuleName),
        ("Copyright", info.Copyright),
        ("Serial number", info.SerialNumber),
        ("Module type name", info.ModuleTypeName),
    ]
    for label, value in fields:
        text = value.decode(errors="replace").strip()
        if text:
            print(f"  {label}: {text}")


def cmd_protection(client: Client):
    szl = client.read_szl(0x0232, 0x0004)
    total = szl.Header.LengthDR * szl.Header.NDR
    blob = bytes(bytearray(szl.Data[:total]))
    record = parse_protection_blob(blob)
    if record is None:
        print("  (no protection record returned)")
        return
    print("  " + fmt_protection(record).replace("\n", "\n  "))


def cmd_eth_details(client: Client):
    szl = client.read_szl(0x0037, 0x0000)
    total = szl.Header.LengthDR * szl.Header.NDR
    blob = bytes(bytearray(szl.Data[:total]))
    record = strip_szl_mini_header(blob)
    if not record:
        print("  (no records returned)")
        return
    print("  " + fmt_eth_details(record).replace("\n", "\n  "))


def _bcd(b: int) -> int:
    """One packed-BCD byte -> its decimal value (0x26 -> 26)."""
    return (b >> 4) * 10 + (b & 0x0F)


def _decode_s7_datetime(ts: bytes) -> str:
    """
    Decode an 8-byte S7 DATE_AND_TIME (BCD) field.

    Layout: [year, month, day, hour, minute, second, ms_hi, ms_lo/weekday].
    Year < 90 -> 2000+year, else 1900+year. Returns "unknown time" if the
    field is all zero or clearly invalid.
    """
    if len(ts) < 6 or ts[:6] == b"\x00" * 6:
        return "unknown time"
    yr = _bcd(ts[0]); yr += 2000 if yr < 90 else 1900
    mo, dy, hh, mm, ss = (_bcd(ts[1]), _bcd(ts[2]),
                          _bcd(ts[3]), _bcd(ts[4]), _bcd(ts[5]))
    if not (1 <= mo <= 12 and 1 <= dy <= 31 and hh < 24 and mm < 60 and ss < 60):
        return "unknown time"
    return f"{yr:04d}-{mo:02d}-{dy:02d} {hh:02d}:{mm:02d}:{ss:02d}"


def cmd_diag_buffer(client: Client):
    """
    SZL 0x00A0 -- diagnostic buffer.

    Previously this called client.read_diagnostic_buffer(), whose parser in
    this python-snap7 build does not decode the S7-300 record layout: it
    yielded event_id=0x0000 / empty timestamps ("[unknown time]") and, on
    real responses, read fields 4 bytes out of phase because it treated the
    SZL mini-header as the first record.

    We now read the SZL directly and parse it with the SAME mini-header
    convention the rest of this script already uses for 0x0011/0x0232/0x0037:

        data[0:2]  length-per-record (lpr)
        data[2:4]  record count (nrec)
        then nrec records of lpr bytes each, where each record is:
            [0:2]   event ID = (event_class << 8) | event_number
            [2]     priority class
            [3]     OB number
            [4:6]   reserved / data ID
            [6:12]  additional info
            [12:20] timestamp, DATE_AND_TIME, 8-byte BCD   <-- the fix
    """
    szl = client.read_szl(0x00A0, 0x0000)
    total = szl.Header.LengthDR * szl.Header.NDR
    blob = bytes(bytearray(szl.Data[:total]))

    if len(blob) < 4:
        print("  (no diagnostic buffer entries returned)")
        return

    lpr, nrec = struct.unpack("!HH", blob[0:4])
    if lpr == 0 or nrec == 0:
        print("  (no diagnostic buffer entries returned)")
        return

    body = blob[4:]
    printed = 0
    for i in range(nrec):
        rec = body[i * lpr:(i + 1) * lpr]
        if len(rec) < lpr:
            break
        event_id = struct.unpack("!H", rec[0:2])[0]
        ts_str = _decode_s7_datetime(rec[12:20]) if lpr >= 20 else "unknown time"
        print(f"  [{ts_str}] event_id=0x{event_id:04X}")
        printed += 1

    if not printed:
        print("  (no diagnostic buffer entries returned)")


def cmd_cpu_state(client: Client):
    print(f"  CPU state: {client.get_cpu_state()}")


def cmd_cpu_info(client: Client):
    info = client.get_cpu_info()
    print(f"  Module type : {info.ModuleTypeName.decode(errors='replace')}")
    print(f"  Serial no.  : {info.SerialNumber.decode(errors='replace')}")
    print(f"  AS name     : {info.ASName.decode(errors='replace')}")
    print(f"  Copyright   : {info.Copyright.decode(errors='replace')}")
    print(f"  Module name : {info.ModuleName.decode(errors='replace')}")


def cmd_order_code(client: Client):
    # python-snap7's own get_order_code() assumes SZL 0x0011 is a single
    # flat record, but this target returns 3 sub-records (index 1/6/7) --
    # so pull the order number from the "Module" record and the version
    # from the "Basic firmware" record ourselves instead.
    szl = client.read_szl(0x0011, 0x0000)
    total = szl.Header.LengthDR * szl.Header.NDR
    blob = bytes(bytearray(szl.Data[:total]))
    records = parse_module_id_blob(blob)
    order_number = ""
    version = ""
    for rec in records:
        index = struct.unpack("!H", rec[0:2])[0]
        if index == 1:
            order_number = rec[2:22].strip(b" ").strip(b"\x00").decode("ascii", errors="replace")
        elif index == 7:
            ausbg = struct.unpack("!H", rec[24:26])[0]
            ausbe = struct.unpack("!H", rec[26:28])[0]
            version = f"{ausbg & 0xFF}.{(ausbe >> 8) & 0xFF}.{ausbe & 0xFF}"
    print(f"  Order code : {order_number}")
    print(f"  Version    : {version}")


def _confirm(prompt: str) -> bool:
    answer = input(f"{prompt} Type 'yes' to confirm: ").strip().lower()
    return answer == "yes"


def cmd_raw_szl(client: Client):
    id_str = input("  SZL-ID (hex, e.g. 0011): ").strip()
    index_str = input("  SZL-Index (hex, default 0000): ").strip() or "0000"
    try:
        szl_id = int(id_str, 16)
        szl_index = int(index_str, 16)
    except ValueError:
        print("  Invalid hex value.")
        return
    szl = client.read_szl(szl_id, szl_index)
    total = szl.Header.LengthDR * szl.Header.NDR
    raw = bytes(bytearray(szl.Data[:total]))
    print(f"  Header: LengthDR={szl.Header.LengthDR}, NDR={szl.Header.NDR}, total data bytes={total}")
    print(f"  Raw hex: {raw.hex()}")
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
    print(f"  ASCII  : {printable}")


def scan_rack_slot(host: str, port: int = 102, rack_range=range(0, 8),
                    slot_range=range(0, 32), timeout_ms: int = 500,
                    stop_at_first: bool = True, quiet: bool = False) -> list:
    """
    Try every (rack, slot) combination in the given ranges and return the
    ones that produce a live, successfully-negotiated S7 connection.

    Rack (3 bits) and slot (5 bits) are encoded directly into the COTP
    remote TSAP during connection setup (TSAP = 0x0100 | rack<<5 | slot),
    so "scanning" for them is just brute-forcing that handshake with a
    short per-attempt timeout via snap7's PingTimeout parameter.
    """
    found = []
    rack_list = list(rack_range)
    slot_list = list(slot_range)
    total = len(rack_list) * len(slot_list)
    tried = 0
    for rack in rack_list:
        for slot in slot_list:
            tried += 1
            if not quiet:
                print(f"\r  Trying rack={rack} slot={slot} ({tried}/{total})...", end="", flush=True)
            client = Client()
            try:
                client.set_param(Parameter.PingTimeout, timeout_ms)
            except Exception:
                pass
            try:
                client.connect(host, rack, slot, port)
                if client.get_connected():
                    found.append((rack, slot))
                    if not quiet:
                        print(f"\r  [+] Found working rack={rack} slot={slot}" + " " * 20)
                    if stop_at_first:
                        client.disconnect()
                        return found
            except (S7Error, RuntimeError, OSError):
                pass
            finally:
                try:
                    if client.get_connected():
                        client.disconnect()
                except Exception:
                    pass
    if not quiet:
        print("\r" + " " * 60 + "\r", end="")
    return found


def cmd_scan_rack_slot(client: Client):
    # NOTE: this scans using new, separate connections -- it does not
    # touch or interrupt the REPL's existing connected `client`.
    host = getattr(client, "host", None) or input("  Host/IP to scan: ").strip()
    port_str = input(f"  Port [{getattr(client, 'port', 102)}]: ").strip()
    port = int(port_str) if port_str else getattr(client, "port", 102)
    stop_str = input("  Stop at first match? [Y/n]: ").strip().lower()
    stop_at_first = stop_str != "n"
    print(f"[*] Scanning {host}:{port} for valid rack/slot combinations (this may take a while)...")
    found = scan_rack_slot(host, port, stop_at_first=stop_at_first)
    if not found:
        print("  No working rack/slot combination found.")
    else:
        print(f"  Found {len(found)} combination(s): " + ", ".join(f"rack={r} slot={s}" for r, s in found))


def cmd_read_db(client: Client):
    try:
        db_number = int(input("  DB number: ").strip())
        start = int((input("  Byte offset [0]: ").strip() or "0"))
        size = int((input("  Number of bytes to read [64]: ").strip() or "64"))
    except ValueError as e:
        print(f"  Invalid input: {e}")
        return
    data = bytes(client.db_read(db_number, start, size))
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
    print(f"  DB{db_number}.{start} ({size} bytes):")
    print(f"    hex  : {data.hex()}")
    print(f"    ascii: {printable}")


def cmd_scan_dbs(client: Client):
    """
    Scan a range of DB numbers, reading a few bytes from each and reporting
    which respond. There is no S7 command to enumerate DBs, so this probes
    each number in turn — the same thing an attacker enumerating data blocks
    would do. Each DB is classified as:
        DATA   — responded with non-zero content
        zeros  — responded but all bytes were zero (pre-allocated/empty)
        ERROR  — the read failed (DB does not exist on the device)
    """
    print("  ⚠  Each DB number is a separate S7 read. A large range means")
    print("     hundreds of round-trips: it is slow, floods the target's logs,")
    print("     and against a REAL PLC can stress or momentarily hang the CPU's")
    print("     communication. Keep the range small — 1–50 is a good default.")
    try:
        lo = int((input("  First DB number [1]: ").strip() or "1"))
        hi = int((input("  Last DB number [50]: ").strip() or "50"))
        probe = int((input("  Bytes to read from each [16]: ").strip() or "16"))
    except ValueError as e:
        print(f"  Invalid input: {e}")
        return
    if lo < 1 or hi < lo:
        print("  Invalid range.")
        return
    # Keep each probe well under the PDU payload limit (~222 bytes at PDU
    # 240). An oversized read fails on EVERY DB and would be misreported
    # as "absent" — this is a peek at the first few bytes, not a dump.
    if not 1 <= probe <= 200:
        print("  Bytes to read must be between 1 and 200.")
        return

    span = hi - lo + 1
    if span > 2000:
        print("  Range too large (max 2000 DBs per scan).")
        return
    if span > 200:
        print(f"  ⚠  {span} DBs is a large scan — this may take a while and is")
        print("     noisy against the target.")
        if input("     Continue? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("  Cancelled.")
            return

    print(f"\n  Scanning DB{lo}..DB{hi}, {probe} bytes each "
          f"({span} probes)...\n")
    data_count = zero_count = err_count = 0
    aborted_at = None
    for db in range(lo, hi + 1):
        if db > lo:
            time.sleep(0.05)   # pace probes so a real CPU isn't hammered
        try:
            raw = bytes(client.db_read(db, 0, probe))
        except Exception as e:
            # A dead socket makes every remaining read fail; without this
            # check the rest of the range would be misreported as "absent".
            try:
                still_up = client.get_connected()
            except Exception:
                still_up = False
            if not still_up:
                aborted_at = db
                print(f"  DB{db:<4}  connection lost — aborting scan")
                break
            err_count += 1
            # keep error lines terse; most of a big range will be errors
            # on a real device, so only show them for small ranges
            if span <= 50:
                print(f"  DB{db:<4}  ERROR  ({type(e).__name__})")
            continue
        if any(raw):
            data_count += 1
            hexs = raw.hex()
            # first 8 bytes shown, space-grouped for readability
            shown = " ".join(hexs[i:i+2] for i in range(0, min(16, len(hexs)), 2))
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:8])
            print(f"  DB{db:<4}  DATA   {shown:<24}  {printable}")
        else:
            zero_count += 1
            print(f"  DB{db:<4}  zeros")

    probed = data_count + zero_count + err_count
    print(f"\n  Summary: {data_count} with data, {zero_count} all-zeros, "
          f"{err_count} errors (absent), of {probed} probed.")
    if aborted_at is not None:
        print(f"  ⚠  Scan stopped at DB{aborted_at}: connection lost. "
              f"Reconnect and rescan DB{aborted_at}..DB{hi}.")


def _parse_hex_bytes(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("0x", "").replace(",", "")
    if len(s) % 2 != 0:
        raise ValueError("Hex string must have an even number of digits")
    return bytes.fromhex(s)


def cmd_write_db(client: Client):
    try:
        db_number = int(input("  DB number: ").strip())
        start = int(input("  Byte offset: ").strip())
        data = _parse_hex_bytes(input("  Bytes to write (hex, e.g. 'DEADBEEF' or 'DE AD BE EF'): "))
    except ValueError as e:
        print(f"  Invalid input: {e}")
        return
    before = bytes(client.db_read(db_number, start, len(data)))
    print(f"  Current value at DB{db_number}.{start}: {before.hex()}")
    if not _confirm(f"This will write {data.hex()} to DB{db_number} at offset {start}."):
        print("  Cancelled.")
        return
    client.db_write(db_number, start, bytearray(data))
    after = bytes(client.db_read(db_number, start, len(data)))
    print(f"  Wrote. Value is now: {after.hex()}")


def cmd_write_merker(client: Client):
    try:
        start = int(input("  Merker byte offset (M): ").strip())
        data = _parse_hex_bytes(input("  Bytes to write (hex): "))
    except ValueError as e:
        print(f"  Invalid input: {e}")
        return
    before = bytes(client.mb_read(start, len(data)))
    print(f"  Current value at M{start}: {before.hex()}")
    if not _confirm(f"This will write {data.hex()} to M{start}."):
        print("  Cancelled.")
        return
    client.mb_write(start, len(data), bytearray(data))
    after = bytes(client.mb_read(start, len(data)))
    print(f"  Wrote. Value is now: {after.hex()}")


def cmd_write_output(client: Client):
    try:
        start = int(input("  Output byte offset (Q): ").strip())
        data = _parse_hex_bytes(input("  Bytes to write (hex): "))
    except ValueError as e:
        print(f"  Invalid input: {e}")
        return
    before = bytes(client.ab_read(start, len(data)))
    print(f"  Current value at Q{start}: {before.hex()}")
    if not _confirm(f"This will write {data.hex()} to Q{start} (physical outputs on a real PLC)."):
        print("  Cancelled.")
        return
    client.ab_write(start, bytearray(data))
    after = bytes(client.ab_read(start, len(data)))
    print(f"  Wrote. Value is now: {after.hex()}")


def cmd_write_input(client: Client):
    try:
        start = int(input("  Input byte offset (I): ").strip())
        data = _parse_hex_bytes(input("  Bytes to write (hex): "))
    except ValueError as e:
        print(f"  Invalid input: {e}")
        return
    before = bytes(client.eb_read(start, len(data)))
    print(f"  Current value at I{start}: {before.hex()}")
    if not _confirm(f"This will force-write {data.hex()} to the input process image at I{start}."):
        print("  Cancelled.")
        return
    client.eb_write(start, len(data), bytearray(data))
    after = bytes(client.eb_read(start, len(data)))
    print(f"  Wrote. Value is now: {after.hex()}")


def cmd_plc_stop(client: Client):
    if not _confirm("This will STOP the CPU."):
        print("  Cancelled.")
        return
    client.plc_stop()
    print("  STOP command sent.")


def cmd_plc_hot_start(client: Client):
    if not _confirm("This will HOT START the CPU."):
        print("  Cancelled.")
        return
    client.plc_hot_start()
    print("  HOT START command sent.")


def cmd_plc_cold_start(client: Client):
    if not _confirm("This will COLD START the CPU (resets to initial values)."):
        print("  Cancelled.")
        return
    client.plc_cold_start()
    print("  COLD START command sent.")


MENU = [
    ("1", "Module identification", cmd_module_id),
    ("2", "Component identification", cmd_component_id),
    ("3", "Protection info", cmd_protection),
    ("4", "Ethernet details", cmd_eth_details),
    ("5", "Diagnostic buffer", cmd_diag_buffer),
    ("6", "CPU state", cmd_cpu_state),
    ("7", "CPU info", cmd_cpu_info),
    ("8", "Order code", cmd_order_code),
    ("9", "PLC STOP", cmd_plc_stop),
    ("10", "PLC HOT START", cmd_plc_hot_start),
    ("11", "PLC COLD START", cmd_plc_cold_start),
    ("12", "Raw SZL dump (diagnostic)", cmd_raw_szl),
    ("13", "Write to Data Block (DB)", cmd_write_db),
    ("14", "Write to Merker (M)", cmd_write_merker),
    ("15", "Write to Output (Q)", cmd_write_output),
    ("16", "Write to Input (I) -- force process image", cmd_write_input),
    ("17", "Scan for rack/slot", cmd_scan_rack_slot),
    ("18", "Read from Data Block (DB)", cmd_read_db),
    ("19", "Scan DB range (enumerate DBs)", cmd_scan_dbs),
]


def print_menu():
    print("\n--- S7 client menu ---")
    for key, label, _ in MENU:
        print(f"  [{key}] {label}")
    print("  [q] Quit")


def repl(client: Client):
    commands = {key: fn for key, _, fn in MENU}
    while True:
        print_menu()
        choice = input("Select> ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return
        fn = commands.get(choice)
        if fn is None:
            print("Unknown option.")
            continue
        try:
            fn(client)
        except S7Error as e:
            print(f"  [!] S7 error: {e}")
        except RuntimeError as e:
            # python-snap7 raises plain RuntimeError (not S7Error) for some
            # failures, e.g. read_szl()/read_diagnostic_buffer() when the
            # target doesn't implement the requested SZL-ID at all -- which
            # is common with honeypots that only emulate a handful of SZLs.
            print(f"  [!] Request failed: {e}")
        except (OSError, struct.error) as e:
            print(f"  [!] Error: {e}")


def main():
    ap = argparse.ArgumentParser(description="Interactive S7 client (python-snap7)")
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=102)
    ap.add_argument("--rack", type=int, default=0)
    ap.add_argument("--slot", type=int, default=2)
    ap.add_argument("--scan", action="store_true",
                     help="Scan for a working rack/slot combination before connecting "
                          "(overrides --rack/--slot)")
    ap.add_argument("--scan-all", action="store_true",
                     help="With --scan, keep scanning after the first match and report all of them")
    args = ap.parse_args()

    if args.scan:
        print(f"[*] Scanning {args.host}:{args.port} for a working rack/slot combination...")
        found = scan_rack_slot(args.host, args.port, stop_at_first=not args.scan_all)
        if not found:
            print("[!] No working rack/slot combination found in the scanned range "
                  "(rack 0-7, slot 0-31). The target may be unreachable, or use a "
                  "non-standard TSAP.", file=sys.stderr)
            sys.exit(1)
        if len(found) > 1:
            print(f"[+] Found {len(found)} combinations: " +
                  ", ".join(f"rack={r} slot={s}" for r, s in found))
        args.rack, args.slot = found[0]
        print(f"[+] Using rack={args.rack}, slot={args.slot}")

    client = Client()
    try:
        print(f"[*] Connecting to {args.host}:{args.port} (rack={args.rack}, slot={args.slot})")
        client.connect(args.host, args.rack, args.slot, args.port)
        if not client.get_connected():
            print("[!] Connect call returned but client reports not connected", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Connected. Negotiated PDU length: {client.get_pdu_length()}")
        repl(client)
    except S7Error as e:
        print(f"[!] S7 error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[!] Connection error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
    finally:
        if client.get_connected():
            client.disconnect()


if __name__ == "__main__":
    main()
