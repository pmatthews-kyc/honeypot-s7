"""
test_syn_ack_spoofer.py
------------------------
Tests the packet manipulation and checksum logic in syn_ack_spoofer.py
without requiring netfilterqueue or root access -- builds synthetic
SYN-ACK packets (exactly as the kernel would emit them) and verifies
the rewritten version has correct checksums and the right TCP options.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import struct
from syn_ack_spoofer import rewrite_syn_ack, _checksum, TARGET_WINDOW, TARGET_MSS


def _ip_checksum(header: bytes) -> int:
    h = bytearray(header)
    h[10] = 0
    h[11] = 0
    return _checksum(bytes(h))


def _build_syn_ack(
    src_ip: str = "192.0.2.5",
    dst_ip: str = "192.0.2.20",
    src_port: int = 102,
    dst_port: int = 54321,
    seq: int = 0xDEADBEEF,
    ack: int = 0xCAFEBABE,
    window: int = 65535,         # Linux default -- the one we want to replace
    options: bytes | None = None,
) -> bytes:
    """
    Build a realistic Linux-style SYN-ACK packet with the full default
    option set (MSS + SACK permitted + timestamps + window scale) --
    exactly what the kernel emits before our spoofer gets to it.
    """
    if options is None:
        # Realistic Linux SYN-ACK options:
        #   MSS=1460 (02 04 05 B4)
        #   SACK permitted (04 02)
        #   Timestamps (08 0A [4 bytes val] [4 bytes echo] = 10 bytes)
        #   NOP (01)
        #   Window scale 7 (03 03 07)
        # Total: 4 + 2 + 10 + 1 + 3 = 20 bytes
        options = bytes([
            0x02, 0x04, 0x05, 0xB4,       # MSS=1460
            0x04, 0x02,                    # SACK permitted
            0x08, 0x0A,                    # Timestamps kind=8, len=10
            0x00, 0x00, 0x01, 0x00,        # TSval
            0x00, 0x00, 0x00, 0x00,        # TSecr
            0x01,                          # NOP
            0x03, 0x03, 0x07,              # Window scale 7
        ])

    tcp_header_len = 20 + len(options)
    data_offset = (tcp_header_len // 4) << 4
    flags = 0x12  # SYN + ACK

    def ip_bytes(addr):
        return bytes(int(o) for o in addr.split("."))

    src_ip_b = ip_bytes(src_ip)
    dst_ip_b = ip_bytes(dst_ip)

    # TCP header with zeroed checksum
    tcp = (
        struct.pack(">H", src_port)
        + struct.pack(">H", dst_port)
        + struct.pack(">I", seq)
        + struct.pack(">I", ack)
        + bytes([data_offset, flags])
        + struct.pack(">H", window)
        + b"\x00\x00"     # checksum placeholder
        + b"\x00\x00"     # urgent pointer
        + options
    )
    pseudo = src_ip_b + dst_ip_b + b"\x00\x06" + struct.pack(">H", len(tcp))
    tcp_cs = _checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack(">H", tcp_cs) + tcp[18:]

    total_len = 20 + len(tcp)
    ip = (
        bytes([0x45, 0x00])             # version=4, IHL=5, DSCP/ECN=0
        + struct.pack(">H", total_len)  # total length
        + b"\x00\x00\x40\x00"          # id, flags (DF), frag offset
        + bytes([0x40, 0x06])           # TTL=64, proto=TCP
        + b"\x00\x00"                   # checksum placeholder
        + src_ip_b
        + dst_ip_b
    )
    ip_cs = _checksum(ip)
    ip = ip[:10] + struct.pack(">H", ip_cs) + ip[12:]

    return ip + tcp


def _parse_modified(packet: bytes) -> dict:
    """Parse a modified packet and return key fields for assertion."""
    ip_ihl = (packet[0] & 0x0F) * 4
    tcp = packet[ip_ihl:]

    data_offset = (tcp[12] >> 4) * 4
    window = struct.unpack_from(">H", tcp, 14)[0]
    options = tcp[20:data_offset]
    tcp_checksum = struct.unpack_from(">H", tcp, 16)[0]

    src_ip = packet[12:16]
    dst_ip = packet[16:20]
    pseudo = src_ip + dst_ip + b"\x00\x06" + struct.pack(">H", len(tcp))
    tcp_cs_check = _checksum(pseudo + tcp)

    ip_header = bytearray(packet[:ip_ihl])
    ip_cs_check = _ip_checksum(bytes(ip_header))

    return {
        "window": window,
        "options": options,
        "data_offset": data_offset,
        "tcp_checksum": tcp_checksum,
        "tcp_checksum_valid": (tcp_cs_check == 0),   # 0 = valid (ones complement)
        "ip_checksum_valid": (ip_cs_check == 0),
    }


def test_rewrite_replaces_window():
    pkt = _build_syn_ack()
    modified = rewrite_syn_ack(pkt)
    assert modified is not None, "Should have rewritten this packet"
    parsed = _parse_modified(modified)
    assert parsed["window"] == TARGET_WINDOW, \
        f"Window should be {TARGET_WINDOW}, got {parsed['window']}"
    print(f"Window rewritten {65535} → {parsed['window']}: OK")


def test_rewrite_strips_options_to_mss_only():
    pkt = _build_syn_ack()
    modified = rewrite_syn_ack(pkt)
    parsed = _parse_modified(modified)
    options = parsed["options"]

    # Should be exactly 4 bytes: MSS option only
    assert len(options) == 4, f"Options should be 4 bytes (MSS only), got {len(options)}: {options.hex()}"
    assert options[0] == 2, "First option kind should be MSS (2)"
    assert options[1] == 4, "MSS option length should be 4"
    mss_in_packet = struct.unpack_from(">H", options, 2)[0]
    assert mss_in_packet == TARGET_MSS, \
        f"MSS should be {TARGET_MSS}, got {mss_in_packet}"

    # 4-byte options blob means NO room for SACK(4), timestamps(8), window scale(3)
    # -- verified implicitly by the length check above, but also parse to be sure
    assert options[0] == 2 and options[1] == 4, "Only MSS option should be present"
    print(f"Options stripped to MSS={TARGET_MSS} only ({len(options)} bytes): OK")


def test_tcp_checksum_valid_after_rewrite():
    pkt = _build_syn_ack()
    modified = rewrite_syn_ack(pkt)
    parsed = _parse_modified(modified)
    assert parsed["tcp_checksum_valid"], \
        f"TCP checksum invalid after rewrite (ones-complement sum should be 0)"
    print("TCP checksum valid after rewrite: OK")


def test_ip_checksum_valid_after_rewrite():
    pkt = _build_syn_ack()
    modified = rewrite_syn_ack(pkt)
    ip_ihl = (modified[0] & 0x0F) * 4
    # Verification: ones-complement sum of entire IP header INCLUDING checksum = 0
    assert _checksum(modified[:ip_ihl]) == 0, \
        "IP checksum invalid after rewrite (ones-complement sum should be 0)"
    print("IP checksum valid after rewrite: OK")


def test_non_syn_ack_passes_through_unmodified():
    """SYN-only packets (from the initial handshake direction) must not be touched."""
    pkt = _build_syn_ack()
    tcp_start = (pkt[0] & 0x0F) * 4
    # Change flags byte from 0x12 (SYN+ACK) to 0x02 (SYN only)
    pkt = pkt[:tcp_start + 13] + bytes([0x02]) + pkt[tcp_start + 14:]
    result = rewrite_syn_ack(pkt)
    assert result is None, "SYN-only packet should be passed through unmodified"
    print("Non-SYN-ACK packets not modified: OK")


def test_non_port_102_passes_through():
    pkt = _build_syn_ack(src_port=80)
    result = rewrite_syn_ack(pkt)
    assert result is None, "Port-80 SYN-ACK should not be touched"
    print("Non-port-102 SYN-ACK not modified: OK")


def test_ip_total_length_updated():
    """IP total length must reflect the shorter modified packet."""
    pkt = _build_syn_ack()
    orig_len = struct.unpack_from(">H", pkt, 2)[0]
    modified = rewrite_syn_ack(pkt)
    new_len = struct.unpack_from(">H", modified, 2)[0]
    # Our options are shorter (4 bytes MSS vs 20 bytes Linux default)
    assert new_len < orig_len, \
        f"Modified packet ({new_len}) should be shorter than original ({orig_len})"
    print(f"IP total length updated: {orig_len} → {new_len} bytes: OK")


def test_checksum_function_known_values():
    """RFC 1071 example: all-zero data should produce 0xFFFF (all ones)."""
    assert _checksum(b"\x00" * 20) == 0xFFFF
    # Checksum of data + its own checksum should sum to 0 (valid)
    data = b"\x45\x00\x00\x28\x00\x01\x40\x00\x40\x06\x00\x00\xac\x1e\x1e\x19\xac\x1e\x1e\x14"
    cs = _checksum(data)
    data_with_cs = data[:10] + struct.pack(">H", cs) + data[12:]
    assert _checksum(data_with_cs) == 0
    print("Checksum implementation (RFC 1071): OK")


if __name__ == "__main__":
    test_checksum_function_known_values()
    test_rewrite_replaces_window()
    test_rewrite_strips_options_to_mss_only()
    test_tcp_checksum_valid_after_rewrite()
    test_ip_checksum_valid_after_rewrite()
    test_non_syn_ack_passes_through_unmodified()
    test_non_port_102_passes_through()
    test_ip_total_length_updated()
    print("\nAll SYN-ACK spoofer tests passed.")
