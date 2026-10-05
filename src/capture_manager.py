"""
capture_manager.py
-------------------
Starts one tshark process per validated S7 session (not per raw TCP touch),
scoped with a BPF filter to that specific peer IP/port pair so pcaps stay
small, per-attacker, and directly correlatable with the JSONL command log
by session_id.

Requires tshark installed and the running user to have packet-capture
permission (either root, or CAP_NET_RAW/CAP_NET_ADMIN + being in the
`wireshark` group on most distros).
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CaptureSession:
    session_id: str
    peer_ip: str
    peer_port: int
    pcap_path: str
    started_at: float
    proc: subprocess.Popen = field(repr=False)


class CaptureManager:
    def __init__(self, interface: str, pcap_dir: str,
                 max_session_seconds: int = 900,
                 max_session_bytes: int = 50 * 1024 * 1024):
        self.interface = interface
        self.pcap_dir = Path(pcap_dir)
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.max_session_seconds = max_session_seconds
        self.max_session_bytes = max_session_bytes
        self._sessions: dict[str, CaptureSession] = {}

    def start_session(self, peer_ip: str, peer_port: int, local_port: int = 102) -> CaptureSession:
        session_id = uuid.uuid4().hex[:12]
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        pcap_path = self.pcap_dir / f"{ts}_{peer_ip.replace(':', '-')}_{peer_port}_{session_id}.pcap"

        bpf = (
            f"host {peer_ip} and port {local_port}"
            # Exclude pure ACK frames that carry no TCP payload -- these
            # are either Ethernet-padded zero frames (NIC padding small
            # frames to the 64-byte minimum) or keepalives, neither of
            # which contain useful S7comm data. Without this filter they
            # appear in the pcap and Wireshark flags them as malformed
            # because the 6 padding bytes follow the TCP header after
            # IP says there should be 0 bytes there.
            # BPF: (ip[2:2]) is IP total length; (ip[0] & 0xf)*4 is IHL;
            # ((ip[tcp_offset+12] & 0xf0)>>2) is TCP header length.
            # Easier to express as: capture only frames where TCP has data,
            # i.e. IP total length > IHL + TCP data offset.
            # BPF arithmetic: tcp[12] >> 4 gives TCP data offset in words,
            # multiply by 4 for bytes. We compare ip[2:2] (total) against
            # (ip[0]&0xf)*4 (IHL) + (tcp[12]&0xf0)>>2 (TCP header len).
            " and (ip[2:2] > ((ip[0]&0xf)*4 + ((tcp[12]&0xf0)>>2)))"
        )

        # -a duration/filesize give us a hard ceiling per session so a
        # single misbehaving/attacking connection can't fill disk.
        cmd = [
            "tshark",
            "-i", self.interface,
            "-f", bpf,
            "-w", str(pcap_path),
            "-a", f"duration:{self.max_session_seconds}",
            "-a", f"filesize:{self.max_session_bytes // 1024}",  # tshark wants KB
            "-q",
        ]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        session = CaptureSession(
            session_id=session_id,
            peer_ip=peer_ip,
            peer_port=peer_port,
            pcap_path=str(pcap_path),
            started_at=time.time(),
            proc=proc,
        )
        self._sessions[session_id] = session
        return session

    def stop_session(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        try:
            session.proc.send_signal(signal.SIGTERM)
            session.proc.wait(timeout=5)
        except Exception:
            try:
                session.proc.kill()
            except Exception:
                pass

    def stop_all(self) -> None:
        for session_id in list(self._sessions.keys()):
            self.stop_session(session_id)
