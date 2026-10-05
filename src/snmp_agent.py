"""
snmp_agent.py
-------------
Minimal SNMP v1/v2c agent answering GetRequest/GetNextRequest for a fixed
set of Siemens-identity OIDs, plus a single ipAddrTable/ifTable entry
sourced dynamically from network_state.json (written by boot_ip_writer.py)
so the reported IP/MAC always matches the box's actual address.

Deliberately does NOT implement SNMPv3, walks beyond the configured OID
set, or SET requests (responds with an error rather than accepting
writes) -- this only needs to be convincing enough to answer the same
identity queries s7-info-style scanning and Shodan's SNMP module send,
not to be a full agent.

All requests (valid or malformed) are logged via command_logger.py, using
the same JSONL log as the S7 side, so SNMP and S7comm activity from the
same attacker show up correlated by peer_ip in one place.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from pathlib import Path

import yaml

import ber
from command_logger import CommandLogger
from storage import resolve_and_verify, substitute_data_dir, StorageError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("snmp_agent")

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import sys
from paths import Paths as _Paths
NETWORK_STATE_PATH = _Paths.load().network_state

# Standard MIB-II identity OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0"

# IP-MIB ipAddrTable: ipAdEntAddr indexed by the IP itself
OID_IP_AD_ENT_ADDR_PREFIX = "1.3.6.1.2.1.4.20.1.1"
OID_IP_AD_ENT_IF_INDEX_PREFIX = "1.3.6.1.2.1.4.20.1.2"
OID_IP_AD_ENT_NET_MASK_PREFIX = "1.3.6.1.2.1.4.20.1.3"

# IF-MIB ifTable, single interface at ifIndex 1
OID_IF_DESCR_1 = "1.3.6.1.2.1.2.2.1.2.1"
OID_IF_PHYS_ADDRESS_1 = "1.3.6.1.2.1.2.2.1.6.1"


class SNMPIdentity:
    def __init__(self, config_path: str):
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        snmp_cfg  = cfg.get("snmp", {})

        # Store for hot-reload: build_oid_table() calls read_identity()
        # using these on every SNMP response.
        self._config_path = config_path
        self._snmp_cfg    = snmp_cfg

        self.community     = snmp_cfg["community"]
        self.sys_object_id = snmp_cfg["sys_object_id"]
        self.sys_contact   = snmp_cfg.get("sys_contact", "")
        self.sys_location  = snmp_cfg.get("sys_location", "")
        self.sys_services  = snmp_cfg.get("sys_services", 79)
        self.listen_host   = snmp_cfg.get("listen_host", "0.0.0.0")
        self.listen_port   = snmp_cfg.get("listen_port", 161)
        self.start_time    = time.time()
        # sys_name and sys_descr are now derived live in build_oid_table()
        # via read_identity() -- no longer stored as static fields here.

    def load_network_state(self) -> dict:
        if not NETWORK_STATE_PATH.exists():
            raise RuntimeError(
                f"{NETWORK_STATE_PATH} not found -- run boot_ip_writer.py "
                f"before starting the SNMP agent (see systemd unit ordering "
                f"in README)."
            )
        return json.loads(NETWORK_STATE_PATH.read_text())

    def build_oid_table(self) -> dict:
        net = self.load_network_state()
        ip = net["ip_address"]
        netmask = net["netmask"]
        mac_bytes = bytes(int(b, 16) for b in net["mac_address"].split(":"))

        # Re-derive sys_name/sys_descr from the live identity on every build.
        # read_identity() is mtime-cached so this is effectively free when
        # config.yaml has not changed -- but it means editing the file updates
        # SNMP responses immediately without restarting the agent.
        from identity import read_identity
        ident = read_identity(self._config_path)
        sys_name = self._snmp_cfg.get("sys_name") or ident.plc_name
        if self._snmp_cfg.get("sys_descr"):
            sys_descr = self._snmp_cfg["sys_descr"]
        else:
            sys_descr = (
                f"Siemens, SIMATIC S7-300, {ident.module_name}, "
                f"{ident.order_code}, HW: 1, FW: {ident.firmware_version}"
            )
        sys_location = self.sys_location

        # sysUpTime from fake_boot_epoch -- see comment in __init__.
        fake_boot_epoch = net.get("fake_boot_epoch", self.start_time)
        uptime_ticks = int((time.time() - fake_boot_epoch) * 100) & 0xFFFFFFFF

        table = {
            OID_SYS_DESCR:     ber.encode_octet_string(sys_descr),
            OID_SYS_OBJECT_ID: ber.encode_oid(self.sys_object_id),
            OID_SYS_UPTIME:    ber.encode_timeticks(uptime_ticks),
            OID_SYS_CONTACT:   ber.encode_octet_string(self.sys_contact),
            OID_SYS_NAME:      ber.encode_octet_string(sys_name),
            OID_SYS_LOCATION:  ber.encode_octet_string(sys_location),
            OID_SYS_SERVICES:  ber.encode_integer(self.sys_services),
            # IP-MIB ipAddrTable — use encode_ip_address (tag 0x40 APPLICATION 0)
            # not encode_octet_string (tag 0x04) or snmpwalk reports 'Wrong Type'
            f"{OID_IP_AD_ENT_ADDR_PREFIX}.{ip}":    ber.encode_ip_address(ip),
            f"{OID_IP_AD_ENT_IF_INDEX_PREFIX}.{ip}": ber.encode_integer(1),
            f"{OID_IP_AD_ENT_NET_MASK_PREFIX}.{ip}": ber.encode_ip_address(netmask),
            # IF-MIB ifTable — ifDescr should be a Siemens module string, not the
            # Linux kernel interface name. ifPhysAddress is raw 6-byte MAC (not
            # colon-formatted string — snmpwalk formats raw bytes correctly itself)
            OID_IF_DESCR_1: ber.encode_octet_string(
                f"Siemens, SIMATIC NET, {ident.module_name}"
            ),
            OID_IF_PHYS_ADDRESS_1: ber.encode_octet_string(mac_bytes),
        }
        return table


class SNMPAgent:
    def __init__(self, config_path: str = "config.yaml"):
        self.identity = SNMPIdentity(config_path)
        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        try:
            data_dir = resolve_and_verify(cfg)
        except StorageError as e:
            log.error("Storage check failed: %s", e)
            raise

        jsonl_path = substitute_data_dir(cfg["logging"]["jsonl_path"], data_dir)
        self.cmd_logger = CommandLogger(jsonl_path)

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.identity.listen_host, self.identity.listen_port))
        log.info("SNMP agent listening on %s:%d",
                  self.identity.listen_host, self.identity.listen_port)

        while True:
            data, addr = sock.recvfrom(4096)
            peer_ip, peer_port = addr
            self._handle_datagram(sock, data, peer_ip, peer_port)

    def _handle_datagram(self, sock: socket.socket, data: bytes,
                          peer_ip: str, peer_port: int) -> None:
        session_id = f"snmp-{peer_ip}-{peer_port}-{int(time.time() * 1000)}"

        try:
            msg = ber.parse_snmp_message(data)
        except ber.BERError as e:
            # Not a well-formed SNMP packet -- noise filter. Log it as
            # noise (not as a real snmp_request) rather than silently
            # dropping, so you can still see scan volume if you want it,
            # without it polluting the "real command" log semantics.
            self.cmd_logger.log_event(
                session_id, peer_ip, peer_port, "snmp_noise", data,
                {"parse_error": str(e)},
            )
            return

        oid_table = self.identity.build_oid_table()

        parsed = {
            "version": msg.version,
            "community": msg.community,
            "pdu_type": {
                ber.PDU_GET_REQUEST: "GetRequest",
                ber.PDU_GET_NEXT_REQUEST: "GetNextRequest",
                ber.PDU_SET_REQUEST: "SetRequest",
            }.get(msg.pdu_tag, hex(msg.pdu_tag)),
            "request_id": msg.request_id,
            "requested_oids": [oid for oid, _ in msg.varbinds],
            "community_valid": msg.community == self.identity.community,
        }
        self.cmd_logger.log_event(
            session_id, peer_ip, peer_port, "snmp_request", data, parsed
        )

        if msg.community != self.identity.community:
            # Real devices generally just don't respond to a bad community
            # string rather than returning an explicit auth error --
            # matching that (silence) is more realistic than replying with
            # a v1 authenticationFailure trap most default configs don't
            # send anyway.
            log.info("SNMP request from %s with wrong community, ignoring", peer_ip)
            return

        if msg.pdu_tag == ber.PDU_SET_REQUEST:
            log.info("SNMP SET attempted from %s, not implemented -- ignoring", peer_ip)
            return

        response_varbinds = []
        sorted_oids = sorted(oid_table.keys(), key=lambda o: tuple(int(x) for x in o.split(".")))

        for oid, _ in msg.varbinds:
            if msg.pdu_tag == ber.PDU_GET_REQUEST:
                if oid in oid_table:
                    response_varbinds.append((oid, oid_table[oid]))
                else:
                    # noSuchObject-ish: skip rather than crafting exception
                    # varbinds, keeps this simple. A GET for an OID we
                    # don't model just gets no matching entry back.
                    continue
            elif msg.pdu_tag == ber.PDU_GET_NEXT_REQUEST:
                next_oid = self._find_next_oid(oid, sorted_oids)
                if next_oid:
                    response_varbinds.append((next_oid, oid_table[next_oid]))
                else:
                    # No OID after this one — return endOfMibView (RFC 3416)
                    # tag 0x82 = CONTEXT 2 = endOfMibView
                    # Without this, snmpwalk gets a timeout and stops abruptly.
                    response_varbinds.append((oid, b"\x82\x00"))

        if not response_varbinds:
            log.info("No answerable OIDs for request from %s, not responding", peer_ip)
            return

        response = ber.build_get_response(
            msg.version, msg.community, msg.request_id, response_varbinds
        )
        sock.sendto(response, (peer_ip, peer_port))

    @staticmethod
    def _find_next_oid(requested_oid: str, sorted_oids: list[str]) -> str | None:
        req_tuple = tuple(int(x) for x in requested_oid.split("."))
        for oid in sorted_oids:
            if tuple(int(x) for x in oid.split(".")) > req_tuple:
                return oid
        return None


if __name__ == "__main__":
    agent = SNMPAgent(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")
    agent.start()
