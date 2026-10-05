"""
clock_handler.py
-----------------
Handles S7 Userdata time function requests: READ_CLOCK (subfunction 0x01)
and SET_CLOCK (subfunction 0x02).

Intercepted in the proxy relay so the backend snap7.Server doesn't need
to implement them, and so we get proper logging and realistic responses.

WIRE FORMAT CONFIRMED from a real pcap capture
(s7comm_reading_setting_plc_time.pcap, decoded 2026-08-28):

Userdata params field [5] encodes method (hi nibble) + function group
(lo nibble):
    0x47 = type=4(request), group=7(time)  ← what we look for
    0x87 = type=8(response), group=7(time)

Params[6] = subfunction: 0x01=READ_CLOCK, 0x02=SET_CLOCK

READ_CLOCK request  params: 00 01 12 04 11 47 01 00
READ_CLOCK request  data:   0a 00 00 00  (empty -- just asking)

READ_CLOCK response params: 00 01 12 08 12 87 01 01 00 00 00 00
READ_CLOCK response data:   ff 09 00 0a  [8-byte BCD time]  00 00
  (inner_len=10 = 8 time bytes + 2 trailing zeros confirmed from capture)

SET_CLOCK request   params: 00 01 12 04 11 47 02 00
SET_CLOCK request   data:   ff 09 00 0a  [8-byte BCD time]  00 00

SET_CLOCK response  params: 00 01 12 08 12 87 02 01 00 00 00 00
SET_CLOCK response  data:   0a 00 00 00  (empty ack)

S7 DATE_AND_TIME BCD encoding (8 bytes, all BCD except byte[7] split):
    byte[0] = year   (BCD 00-99; 00-89=2000-2089, 90-99=1990-1999)
    byte[1] = month  (BCD 01-12)
    byte[2] = day    (BCD 01-31)
    byte[3] = hour   (BCD 00-23)
    byte[4] = minute (BCD 00-59)
    byte[5] = second (BCD 00-59)
    byte[6] = ms top 2 digits (BCD 00-99; 594ms → 0x59)
    byte[7] = hi nibble: ms last digit (0-9)
              lo nibble: day-of-week (1=Sun, 2=Mon, 3=Tue, 4=Wed,
                                      5=Thu, 6=Fri, 7=Sat)
"""

from __future__ import annotations

import datetime
import logging
import struct

log = logging.getLogger("clock_handler")

# Confirmed from capture: params[5] encodes method+group
_TIME_GROUP_REQUEST  = 0x47  # hi nibble=4(request),  lo nibble=7(time group)
_TIME_GROUP_RESPONSE = 0x87  # hi nibble=8(response), lo nibble=7(time group)
_SUBFUNC_READ = 0x01
_SUBFUNC_SET  = 0x02


def _bcd(n: int) -> int:
    """Encode integer 0-99 to BCD byte."""
    return ((n // 10) << 4) | (n % 10)


def _unbcd(b: int) -> int:
    """Decode BCD byte to integer."""
    return (b >> 4) * 10 + (b & 0xF)


def encode_s7_time(dt: datetime.datetime | None = None) -> bytes:
    """
    Encode a datetime to the 8-byte S7 DATE_AND_TIME BCD format.
    Uses current time if dt is None.

    DOW mapping (confirmed from capture: byte[7] lo nibble=3 = Tue):
        Python weekday(): 0=Mon, 1=Tue, 2=Wed, 3=Thu, 4=Fri, 5=Sat, 6=Sun
        S7 DOW:           2=Mon, 3=Tue, 4=Wed, 5=Thu, 6=Fri, 7=Sat, 1=Sun
        Formula: s7_dow = ((python_dow + 1) % 7) + 1
    """
    if dt is None:
        dt = datetime.datetime.now()

    yr = dt.year % 100  # last 2 digits: 2026 → 26
    ms = dt.microsecond // 1000  # μs → ms
    ms_hi = ms // 10             # top 2 decimal digits of ms
    ms_lo = ms % 10              # last decimal digit

    # DOW conversion
    s7_dow = ((dt.weekday() + 1) % 7) + 1

    return bytes([
        _bcd(yr),
        _bcd(dt.month),
        _bcd(dt.day),
        _bcd(dt.hour),
        _bcd(dt.minute),
        _bcd(dt.second),
        _bcd(ms_hi),
        (ms_lo << 4) | s7_dow,
    ])


def decode_s7_time(time_bytes: bytes) -> dict:
    """Decode 8-byte S7 BCD time to a dict."""
    if len(time_bytes) < 8:
        return {}
    yr = _unbcd(time_bytes[0])
    year = 2000 + yr if yr < 90 else 1900 + yr
    DOW_NAMES = {1:"Sun", 2:"Mon", 3:"Tue", 4:"Wed", 5:"Thu", 6:"Fri", 7:"Sat"}
    dow_raw = time_bytes[7] & 0xF
    return {
        "year":   year,
        "month":  _unbcd(time_bytes[1]),
        "day":    _unbcd(time_bytes[2]),
        "hour":   _unbcd(time_bytes[3]),
        "minute": _unbcd(time_bytes[4]),
        "second": _unbcd(time_bytes[5]),
        "ms":     _unbcd(time_bytes[6]) * 10 + (time_bytes[7] >> 4),
        "dow":    DOW_NAMES.get(dow_raw, f"?({dow_raw})"),
    }


def time_dict_to_str(t: dict) -> str:
    return (f"{t.get('year','?')}-{t.get('month','?'):02d}-{t.get('day','?'):02d} "
            f"{t.get('hour','?'):02d}:{t.get('minute','?'):02d}:"
            f"{t.get('second','?'):02d}.{t.get('ms','?'):03d} {t.get('dow','?')}")


def _build_userdata_response(pdu_reference: int, resp_params: bytes,
                             resp_data: bytes) -> bytes:
    """Build a complete TPKT + COTP DT + S7 Userdata response frame."""
    param_len = len(resp_params)
    data_len  = len(resp_data)

    # S7 header: 10 bytes for Userdata (pdu_type=0x07)
    s7_hdr = bytes([0x32, 0x07, 0x00, 0x00]) + \
             struct.pack(">H", pdu_reference) + \
             struct.pack(">HH", param_len, data_len)

    body = s7_hdr + resp_params + resp_data

    # COTP DT: LI=2, type=0xF0, nr_eot=0x80
    cotp = bytes([0x02, 0xF0, 0x80])

    total = 4 + len(cotp) + len(body)
    tpkt  = bytes([0x03, 0x00]) + struct.pack(">H", total)
    return tpkt + cotp + body


class ClockHandler:
    """
    Handles S7 READ_CLOCK and SET_CLOCK Userdata requests.

    Intercept check: params[5] == 0x47 (time group request) and
    params[6] in (0x01=READ, 0x02=SET). Confirmed field positions
    from the real pcap.

    READ_CLOCK: returns current Pi system time encoded in S7 BCD format.

    SET_CLOCK: accepts the write, logs the requested time, responds
    with ack. Does NOT change the Pi's system clock -- that would be
    an unintended side-effect of running the honeypot. The attacker's
    time write is logged so it can be seen in the JSONL, but the actual
    Pi time is unchanged.
    """

    def __init__(self, cmd_logger):
        self._logger = cmd_logger

    def handles(self, parsed) -> bool:
        if not getattr(parsed, "is_s7_data", False):
            return False
        if parsed.pdu_type != 0x07:           # must be Userdata
            return False
        params = parsed.params
        if len(params) < 7:
            return False
        return (params[5] == _TIME_GROUP_REQUEST and
                params[6] in (_SUBFUNC_READ, _SUBFUNC_SET))

    def handle(self, session_id: str, peer_ip: str, peer_port: int,
               parsed) -> bytes:
        subfunc = parsed.params[6]
        if subfunc == _SUBFUNC_READ:
            return self._read_clock(session_id, peer_ip, peer_port, parsed)
        elif subfunc == _SUBFUNC_SET:
            return self._set_clock(session_id, peer_ip, peer_port, parsed)
        return b""

    # ── Response params templates (confirmed from capture) ──────────────

    def _resp_params(self, subfunc: int) -> bytes:
        """
        Build the 12-byte response params block.
        Confirmed pattern: 00 01 12 08 12 87 [subfunc] 01 00 00 00 00
        """
        return bytes([
            0x00, 0x01, 0x12, 0x08,   # outer header (always same)
            0x12,                       # inner type = 0x12 (response)
            _TIME_GROUP_RESPONSE,       # 0x87 = response, time group
            subfunc,                    # 0x01=read or 0x02=set
            0x01,                       # last_data_unit = 1
            0x00, 0x00, 0x00, 0x00,    # error info = no error
        ])

    # ── READ_CLOCK ───────────────────────────────────────────────────────

    def _read_clock(self, session_id, peer_ip, peer_port, parsed) -> bytes:
        now = datetime.datetime.now()
        time_bytes = encode_s7_time(now)

        # data: rc(1)=0xff + transport(1)=0x09 + inner_len(2)=0x000a +
        #       8-byte BCD time + 2 trailing zeros
        # inner_len=10 confirmed from capture (8 time + 2 trailing)
        resp_data = bytes([0xFF, 0x09, 0x00, 0x0A]) + time_bytes + b"\x00\x00"

        log.info("READ_CLOCK from %s:%d (session %s) → %s",
                 peer_ip, peer_port, session_id, now.isoformat(timespec="milliseconds"))

        self._logger.log_event(
            session_id, peer_ip, peer_port, "read_clock",
            parsed.params + parsed.data,
            {"function": "read_clock",
             "time_returned": now.isoformat(timespec="milliseconds")},
        )

        return _build_userdata_response(
            parsed.pdu_reference,
            self._resp_params(_SUBFUNC_READ),
            resp_data,
        )

    # ── SET_CLOCK ────────────────────────────────────────────────────────

    def _set_clock(self, session_id, peer_ip, peer_port, parsed) -> bytes:
        # data: ff 09 00 0a [8-byte BCD time] [00 00]
        data = parsed.data
        requested_time_str = "unknown"
        if len(data) >= 12:
            t = decode_s7_time(data[4:12])
            requested_time_str = time_dict_to_str(t)

        # SET_CLOCK is operationally significant -- attacker may be trying
        # to manipulate timestamps or bypass time-based security controls
        log.warning(
            "SET_CLOCK from %s:%d (session %s): requested time=%s -- "
            "accepted with no auth check (matching real unprotected S7-300 "
            "behavior), Pi system clock NOT actually changed",
            peer_ip, peer_port, session_id, requested_time_str,
        )

        self._logger.log_event(
            session_id, peer_ip, peer_port, "set_clock",
            parsed.params + parsed.data,
            {"function":        "set_clock",
             "time_requested":  requested_time_str,
             "accepted":        True,
             "note":            "Pi system clock unchanged; time logged only"},
        )

        # Ack: rc=0x0a, rest zeros
        resp_data = bytes([0x0A, 0x00, 0x00, 0x00])
        return _build_userdata_response(
            parsed.pdu_reference,
            self._resp_params(_SUBFUNC_SET),
            resp_data,
        )
