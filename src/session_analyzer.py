"""
session_analyzer.py
--------------------
Post-hoc analysis of captured sessions from commands.jsonl.

Reads the JSONL log produced by command_logger.py, groups events into
sessions, computes behavioral features for each session, then classifies
each into one of four categories:

    targeted  -- specific operational intent: reads to plausible DB
                 addresses, writes, or critical commands (STOP, block
                 download). The kind of session that carries actual
                 attack value beyond reconnaissance.

    scanner   -- S7comm-aware reconnaissance: completes the handshake,
                 reads SZL identity data, maybe probes a few DBs, no
                 writes or critical commands. Typical of automated ICS
                 discovery tools (Shodan's S7 module, plcscan, etc.).

    fuzzer    -- automated, systematic, machine-consistent behavior:
                 low timing variance, high request rate, sweeps of
                 function codes or SZL IDs. Distinct from scanner in
                 that fuzzers often try unusual/invalid combinations
                 rather than just reading standard identity data.

    unknown   -- insufficient signal to classify (very short session,
                 COTP handshake only, or conflicting signals).

LIMITATIONS (same philosophy as s7_precheck.py -- stated honestly):
    - A targeted attacker using a scripted tool at machine-consistent
      timing looks like a fuzzer to timing-based features. The DB/address
      specificity and critical-event checks help, but this is not solved.
    - An S7comm-aware fuzzer that happens to probe DB500 at address 26
      looks like a targeted scanner to address-based features.
    - Classification is heuristic, not a ground truth. Treat the output
      as a triage aid, not a definitive verdict.

Usage:
    python3 session_analyzer.py /path/to/commands.jsonl [--json] [--min-requests N]

    --json         Also write machine-readable output to <logfile>.analysis.json
    --min-requests N  Skip sessions with fewer than N S7 requests (default: 1)
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# --- Classification thresholds -------------------------------------------
# Tuned conservatively to minimize false positives rather than maximize
# recall -- a missed targeted session is less harmful than repeatedly
# alerting on a fuzzer as targeted.

FUZZER_RATE_RPS       = 5.0    # requests/sec above this → automated signal
FUZZER_TIMING_CV      = 0.25   # coefficient of variation below this → machine-consistent
FUZZER_MIN_FC_SWEEP   = 4      # distinct function codes in <20 requests → sweep
SCANNER_MIN_SZL_READS = 2      # SZL identity reads → reconnaissance
TARGETED_MAX_RPS      = 3.0    # targeted human ops are slower than this
TARGETED_PLAUSIBLE_DB_RANGE = range(1, 1000)  # DB numbers that look like real config

# Function codes that indicate operational intent beyond reconnaissance
CRITICAL_FUNCTION_NAMES = {
    "plc_stop_attempt",
    "plc_start_attempt",      # PLC Control (warm/cold restart, memory reset)
    "plc_control_attempt",    # catch-all for legacy records before the rename
    "block_download_committed",
    "block_download_request",
    "start_upload",
}

WRITE_FUNCTION_NAMES = {"write_var", "block_download_committed"}
RECON_FUNCTION_NAMES = {"szl_status_read", "read_var", "cpu_services"}


# --- Data structures -----------------------------------------------------

@dataclass
class SessionSummary:
    session_id: str
    peer_ip: str
    peer_port: int
    first_ts: float
    last_ts: float

    total_events: int = 0
    s7_request_count: int = 0

    function_names: set = field(default_factory=set)
    function_codes: set = field(default_factory=set)

    dbs_read: set = field(default_factory=set)
    dbs_written: set = field(default_factory=set)
    addresses: list = field(default_factory=list)

    szl_ids_seen: set = field(default_factory=set)
    critical_events: list = field(default_factory=list)
    write_events: list = field(default_factory=list)

    inter_request_gaps: list = field(default_factory=list)

    snmp_requests: int = 0
    http_requests: int = 0

    @property
    def duration(self) -> float:
        return max(0.001, self.last_ts - self.first_ts)

    @property
    def request_rate(self) -> float:
        return self.s7_request_count / self.duration

    @property
    def timing_cv(self) -> float | None:
        """Coefficient of variation of inter-request gaps. Low = machine-like."""
        if len(self.inter_request_gaps) < 4:
            return None
        mean = statistics.mean(self.inter_request_gaps)
        if mean < 0.0001:
            return 0.0
        return statistics.stdev(self.inter_request_gaps) / mean

    @property
    def has_critical(self) -> bool:
        return bool(self.critical_events)

    @property
    def has_writes(self) -> bool:
        return bool(self.write_events) or bool(self.dbs_written)

    @property
    def plausible_db_access(self) -> bool:
        """True if accessed DBs look like real process configuration."""
        all_dbs = self.dbs_read | self.dbs_written
        return bool(all_dbs) and all(db in TARGETED_PLAUSIBLE_DB_RANGE for db in all_dbs)

    @property
    def classification(self) -> str:
        # Priority 1: critical events = targeted regardless of other signals
        if self.has_critical:
            return "targeted"

        # Priority 2: writes to specific plausible addresses = targeted
        if self.has_writes and self.plausible_db_access:
            if self.request_rate <= TARGETED_MAX_RPS:
                return "targeted"

        # Priority 3: machine-consistent timing + high rate = fuzzer
        cv = self.timing_cv
        if cv is not None and cv < FUZZER_TIMING_CV and self.request_rate > FUZZER_RATE_RPS:
            return "fuzzer"

        # Priority 4: function code sweep (many codes, short session) = fuzzer
        if (len(self.function_names) >= FUZZER_MIN_FC_SWEEP
                and self.s7_request_count <= 20):
            return "fuzzer"

        # Priority 5: S7comm identity reads only = scanner
        if (self.s7_request_count > 0
                and RECON_FUNCTION_NAMES & self.function_names
                and not self.has_writes):
            return "scanner"

        if self.s7_request_count > 0:
            return "unknown"

        return "unknown"

    @property
    def confidence(self) -> str:
        if self.has_critical:
            return "HIGH"
        cv = self.timing_cv
        if cv is not None and self.s7_request_count >= 10:
            return "HIGH"
        if self.s7_request_count >= 5:
            return "MEDIUM"
        return "LOW"


# --- JSONL parsing -------------------------------------------------------

def load_sessions(jsonl_path: Path, min_requests: int) -> list[SessionSummary]:
    raw: dict[str, list[dict]] = defaultdict(list)
    peers: dict[str, tuple[str, int]] = {}

    try:
        with jsonl_path.open() as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"Warning: skipping malformed JSONL line {lineno}: {e}",
                          file=sys.stderr)
                    continue
                sid = event.get("session_id", "unknown")
                raw[sid].append(event)
                if sid not in peers:
                    peers[sid] = (
                        event.get("peer_ip", "?"),
                        event.get("peer_port", 0),
                    )
    except FileNotFoundError:
        print(f"Error: {jsonl_path} not found", file=sys.stderr)
        sys.exit(1)

    sessions = []
    for sid, events in raw.items():
        events.sort(key=lambda e: e.get("ts", 0))
        summary = _build_summary(sid, peers.get(sid, ("?", 0)), events)
        if summary.s7_request_count >= min_requests or summary.has_critical:
            sessions.append(summary)

    sessions.sort(key=lambda s: (
        {"targeted": 0, "fuzzer": 1, "scanner": 2, "unknown": 3}[s.classification],
        -s.s7_request_count,
    ))
    return sessions


def _build_summary(sid: str, peer: tuple[str, int],
                   events: list[dict]) -> SessionSummary:
    timestamps = [e["ts"] for e in events if "ts" in e]
    s = SessionSummary(
        session_id=sid,
        peer_ip=peer[0],
        peer_port=peer[1],
        first_ts=min(timestamps) if timestamps else 0,
        last_ts=max(timestamps) if timestamps else 0,
    )

    prev_request_ts: float | None = None

    for event in events:
        s.total_events += 1
        etype = event.get("event_type", "")
        parsed = event.get("parsed") or {}
        ts = event.get("ts", 0)

        # Critical events
        if etype in CRITICAL_FUNCTION_NAMES:
            s.critical_events.append({
                "type": etype,
                "ts": ts,
                "detail": parsed,
            })

        # Write events
        if etype == "s7_request" and parsed.get("function_name") in WRITE_FUNCTION_NAMES:
            s.write_events.append(parsed)

        # S7 requests
        if etype == "s7_request":
            s.s7_request_count += 1
            fn = parsed.get("function_name")
            fc = parsed.get("function_code")
            if fn:
                s.function_names.add(fn)
            if fc is not None:
                s.function_codes.add(fc)

            # Extract read/write item details (from read_write_parser output)
            for item in parsed.get("items", []):
                db = item.get("db")
                if db is not None:
                    addr = item.get("address", "")
                    if fn in WRITE_FUNCTION_NAMES:
                        s.dbs_written.add(db)
                    else:
                        s.dbs_read.add(db)
                    s.addresses.append(addr)

            # SZL reads
            if "szl_status_read" in (fn or ""):
                s.szl_ids_seen.add(parsed.get("szl_id", "?"))

            # Timing
            if prev_request_ts is not None:
                gap = ts - prev_request_ts
                if 0 < gap < 60:    # ignore gaps > 60s (session pauses)
                    s.inter_request_gaps.append(gap)
            prev_request_ts = ts

        # SZL reads go through as cpu_services
        if etype == "szl_status_read":
            s.szl_ids_seen.add(parsed.get("szl_id", "?"))
            s.function_names.add("szl_read")

        # Block transfer events
        if etype in CRITICAL_FUNCTION_NAMES:
            pass  # already captured above

        # SNMP/HTTP (multi-protocol correlation)
        if etype == "snmp_request":
            s.snmp_requests += 1
        if etype == "http_request":
            s.http_requests += 1

    return s


# --- Report output -------------------------------------------------------

def _ts(ts: float) -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))


def _format_session(s: SessionSummary, verbose: bool = False) -> str:
    lines = []
    tag = f"[{s.classification.upper()}:{s.confidence}]"
    lines.append(
        f"  {tag} {s.peer_ip}:{s.peer_port}  "
        f"session={s.session_id[:12]}  "
        f"{_ts(s.first_ts)}"
    )
    lines.append(
        f"    Duration: {s.duration:.1f}s  "
        f"S7 requests: {s.s7_request_count}  "
        f"Rate: {s.request_rate:.1f} req/s"
    )

    if s.timing_cv is not None:
        timing_label = "machine-consistent" if s.timing_cv < FUZZER_TIMING_CV else "variable"
        lines.append(f"    Timing CV: {s.timing_cv:.3f} ({timing_label})")

    if s.function_names:
        lines.append(f"    Functions: {', '.join(sorted(s.function_names))}")

    if s.dbs_read:
        lines.append(f"    DBs read:  {sorted(s.dbs_read)}")
    if s.dbs_written:
        lines.append(f"    DBs written: {sorted(s.dbs_written)}")
    if s.addresses and verbose:
        lines.append(f"    Addresses: {', '.join(s.addresses[:8])}"
                     + (" ..." if len(s.addresses) > 8 else ""))

    for ce in s.critical_events:
        etype = ce["type"]
        detail = ce.get("detail", {})
        # Make the one-liner meaningful: show the specific operation
        if etype == "plc_stop_attempt":
            transition = detail.get("state_transition", "? → STOP")
            lines.append(f"    !! CRITICAL: PLC STOP  ({transition})")
        elif etype == "plc_start_attempt":
            svc = detail.get("pi_service", "?")
            meaning = detail.get("pi_service_meaning", "")
            transition = detail.get("state_transition", "? → RUN")
            lines.append(f"    !! CRITICAL: PLC START  service={svc} ({meaning})  ({transition})")
        elif etype == "block_download_committed":
            total = detail.get("total_bytes", "?")
            btype = detail.get("block_type", "?")
            bnum = detail.get("block_number", "?")
            lines.append(f"    !! CRITICAL: BLOCK WRITE  type={btype} num={bnum} size={total} bytes")
        else:
            lines.append(f"    !! CRITICAL: {etype}  {detail}")

    if s.snmp_requests or s.http_requests:
        lines.append(
            f"    Also: SNMP={s.snmp_requests} requests  "
            f"HTTP={s.http_requests} requests (same source)"
        )

    return "\n".join(lines)


def print_report(sessions: list[SessionSummary], jsonl_path: Path) -> None:
    if not sessions:
        print("No sessions found (check min-requests threshold and log path)")
        return

    by_class: dict[str, list[SessionSummary]] = defaultdict(list)
    for s in sessions:
        by_class[s.classification].append(s)

    total = len(sessions)
    print(f"\n{'='*65}")
    print(f"  S7 Honeypot Session Analysis")
    print(f"  Source: {jsonl_path}")
    print(f"  Sessions analyzed: {total}")
    for cls in ("targeted", "fuzzer", "scanner", "unknown"):
        count = len(by_class.get(cls, []))
        if count:
            print(f"    {cls.upper():<10} {count:>4}  ({100*count/total:.0f}%)")
    print(f"{'='*65}\n")

    for cls in ("targeted", "fuzzer", "scanner", "unknown"):
        group = by_class.get(cls, [])
        if not group:
            continue
        label = {
            "targeted": "TARGETED (operational intent / attack attempts)",
            "fuzzer":   "FUZZER (automated systematic probing)",
            "scanner":  "SCANNER (S7comm-aware reconnaissance)",
            "unknown":  "UNKNOWN (insufficient signal)",
        }[cls]
        print(f"── {label} ({len(group)}) ──")
        for s in group:
            print(_format_session(s, verbose=(cls == "targeted")))
            print()

    print(f"\nNOTE: classification is heuristic. See session_analyzer.py docstring")
    print(f"for known limitations, especially the fuzzer/targeted overlap case.")


def write_json_report(sessions: list[SessionSummary], out_path: Path) -> None:
    output = []
    for s in sessions:
        output.append({
            "session_id":       s.session_id,
            "peer_ip":          s.peer_ip,
            "peer_port":        s.peer_port,
            "first_ts":         s.first_ts,
            "last_ts":          s.last_ts,
            "duration_s":       round(s.duration, 3),
            "classification":   s.classification,
            "confidence":       s.confidence,
            "s7_request_count": s.s7_request_count,
            "request_rate_rps": round(s.request_rate, 3),
            "timing_cv":        round(s.timing_cv, 4) if s.timing_cv is not None else None,
            "function_names":   sorted(s.function_names),
            "dbs_read":         sorted(s.dbs_read),
            "dbs_written":      sorted(s.dbs_written),
            "addresses":        s.addresses[:20],
            "has_critical":     s.has_critical,
            "critical_events":  s.critical_events,
            "snmp_requests":    s.snmp_requests,
            "http_requests":    s.http_requests,
        })
    out_path.write_text(json.dumps(output, indent=2))
    print(f"JSON report written to {out_path}")


# --- Entry point ---------------------------------------------------------

def _default_jsonl_path(config_path: str) -> Path:
    """Resolve commands.jsonl the same way honeypot.py does: data dir from
    S7HONEYPOT_DATA_DIR or storage.data_dir, substituted into
    logging.jsonl_path. No mount check -- an analyst may be reading a copy."""
    import yaml
    from storage import resolve_data_dir, substitute_data_dir
    cfg = yaml.safe_load(Path(config_path).read_text()) or {}
    data_dir = resolve_data_dir(cfg)
    raw = cfg.get("logging", {}).get("jsonl_path", "${DATA_DIR}/commands.jsonl")
    return Path(substitute_data_dir(raw, data_dir))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Classify S7 honeypot sessions from commands.jsonl"
    )
    parser.add_argument("jsonl_path", nargs="?", default=None,
                        help="Path to commands.jsonl (default: logging.jsonl_path "
                             "from --config, with ${DATA_DIR} resolved)")
    parser.add_argument("--config", default="config.yaml",
                        help="Honeypot config used to locate commands.jsonl "
                             "when no path is given (default: config.yaml)")
    parser.add_argument("--json", action="store_true",
                        help="Also write JSON report to <jsonl_path>.analysis.json")
    parser.add_argument("--min-requests", type=int, default=1,
                        metavar="N", dest="min_requests",
                        help="Skip sessions with fewer than N S7 requests (default: 1)")
    args = parser.parse_args()

    if args.jsonl_path:
        path = Path(args.jsonl_path)
    else:
        try:
            path = _default_jsonl_path(args.config)
        except Exception as e:
            print(f"Could not locate commands.jsonl from {args.config}: {e}\n"
                  f"Pass the path explicitly: session_analyzer.py <commands.jsonl>",
                  file=sys.stderr)
            sys.exit(1)
    sessions = load_sessions(path, args.min_requests)
    print_report(sessions, path)

    if args.json:
        json_path = path.with_suffix(".analysis.json")
        write_json_report(sessions, json_path)


if __name__ == "__main__":
    main()
