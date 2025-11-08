"""
PCAP Parser
===========

This module provides a lightweight parser for the libpcap file format.  It
supports reading classic pcap files (little or big endian) and extracting
basic network layer information from each packet.  The parser avoids
external dependencies by using only the Python standard library.  It was
inspired by the C++ and JavaScript parsers used in several PCAP analysis
projects but re‑implemented here in pure Python for portability.

The parser produces a list of dictionaries for each packet with the
following keys:

* ``timestamp`` – the packet capture time in milliseconds since the Unix
  epoch.
* ``source_ip`` – the IPv4 address of the sender or ``"Unknown"`` for
  non‑IPv4 packets.
* ``dest_ip`` – the IPv4 address of the receiver or ``"Unknown"`` for
  non‑IPv4 packets.
* ``protocol`` – a string indicating the L4 protocol (``"TCP"``, ``"UDP"``,
  ``"ICMP"``, ``"ARP"`` or ``"IP"`` for other IPv4 protocols).  Non‑IPv4
  frames are labelled ``"Unknown"``.
* ``source_port`` – the TCP/UDP source port if present.
* ``dest_port`` – the TCP/UDP destination port if present.
* ``length`` – the length of the captured frame in bytes.

Unsupported protocols (IPv6, VLAN, PPPoE, etc.) are skipped with
``source_ip``/``dest_ip`` set to ``"Unknown"``.  The capture timestamp
includes microsecond precision by combining the seconds and microseconds
fields from the packet header.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class Packet:
    """Representation of a single network frame.

    Attributes:
        timestamp: Capture time in milliseconds since the epoch.
        source_ip: Source IPv4 address or ``"Unknown"`` for unsupported frames.
        dest_ip: Destination IPv4 address or ``"Unknown"`` for unsupported frames.
        protocol: High level protocol name (``TCP``, ``UDP``, ``ICMP``, ``ARP``, ``IP`` or ``Unknown``).
        source_port: Source port number for TCP/UDP packets.
        dest_port: Destination port number for TCP/UDP packets.
        length: Length of the captured frame.
        payload: Raw bytes of the layer‑4 payload for TCP/UDP packets.  For other
            protocols or unsupported frames this value is ``None``.  The
            payload can be used for SIP parsing, RTP analysis or generic
            string searches.
    """

    timestamp: float
    source_ip: str
    dest_ip: str
    protocol: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    length: int = 0
    payload: Optional[bytes] = None


def _unpack(fmt: str, data: bytes, endian: str) -> tuple:
    """Helper to unpack binary data with configurable endianness.

    Args:
        fmt: struct format string without endianness prefix.
        data: bytes to unpack.
        endian: '<' for little endian or '>' for big endian.

    Returns:
        The unpacked tuple of values.
    """
    return struct.unpack(endian + fmt, data)


def read_pcap(file_path: str) -> List[Packet]:
    """Parse a PCAP file and return a list of Packet objects.

    This function supports little‑endian and big‑endian pcap files.  It
    currently ignores nanosecond‑resolution pcapng files and will return
    an empty list if the magic number does not match known values.

    Args:
        file_path: Path to a .pcap file on disk.

    Returns:
        A list of :class:`Packet` records extracted from the file.
    """
    packets: List[Packet] = []

    with open(file_path, "rb") as f:
        # Read global header (24 bytes)
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            return packets

        magic_number = struct.unpack("<I", global_hdr[:4])[0]
        # Determine endianness based on magic number
        # 0xa1b2c3d4 – little endian, microsecond resolution
        # 0xd4c3b2a1 – big endian, microsecond resolution
        # 0xa1b2cd34 / 0x4d3cb2a1 – nanosecond resolution (unsupported here)
        if magic_number == 0xa1b2c3d4:
            endian = "<"
        elif magic_number == 0xd4c3b2a1:
            endian = ">"
        else:
            # Unknown format
            return packets

        # Skip rest of the header (already read 4 bytes).  For little‑endian
        # reading, the layout is: version_major, version_minor, thiszone,
        # sigfigs, snaplen, network.  We don't need these values for parsing.
        # The pointer is already positioned at the end of the header after
        # reading 24 bytes.

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = _unpack("IIII", pkt_hdr, endian)
            frame_data = f.read(incl_len)
            if len(frame_data) < incl_len:
                break

            timestamp_ms = ts_sec * 1000.0 + ts_usec / 1000.0
            length = incl_len

            # Default values for unsupported frames
            src_ip = "Unknown"
            dst_ip = "Unknown"
            protocol_name = "Unknown"
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            payload: Optional[bytes] = None

            # Minimum Ethernet header size is 14 bytes
            if len(frame_data) >= 14:
                # Ethernet frame: destination MAC (6), source MAC (6), ethertype (2)
                ethertype = struct.unpack("!H", frame_data[12:14])[0]
                # IPv4
                if ethertype == 0x0800 and len(frame_data) >= 14 + 20:
                    # IP header starts at offset 14
                    ip_header = frame_data[14:14 + 20]
                    version_ihl = ip_header[0]
                    version = version_ihl >> 4
                    ihl = (version_ihl & 0x0F) * 4
                    if version == 4 and len(frame_data) >= 14 + ihl:
                        # Source and destination IP addresses
                        src_ip_bytes = frame_data[14 + 12:14 + 16]
                        dst_ip_bytes = frame_data[14 + 16:14 + 20]
                        src_ip = ".".join(str(b) for b in src_ip_bytes)
                        dst_ip = ".".join(str(b) for b in dst_ip_bytes)
                        # Protocol number
                        proto_num = frame_data[14 + 9]
                        if proto_num == 6:
                            protocol_name = "TCP"
                        elif proto_num == 17:
                            protocol_name = "UDP"
                        elif proto_num == 1:
                            protocol_name = "ICMP"
                        else:
                            protocol_name = "IP"
                        # Source/destination ports for TCP/UDP
                        if proto_num in (6, 17) and len(frame_data) >= 14 + ihl + 4:
                            port_offset = 14 + ihl
                            src_port, dst_port = struct.unpack("!HH", frame_data[port_offset:port_offset + 4])
                            # Extract payload for TCP/UDP
                            header_len = 14 + ihl
                            if proto_num == 6 and len(frame_data) >= header_len + 20:
                                # TCP data offset (upper nibble of byte 12 after IP header)
                                data_offset = (frame_data[header_len + 12] >> 4) * 4
                                payload = frame_data[header_len + data_offset:]
                            elif proto_num == 17 and len(frame_data) >= header_len + 8:
                                # UDP header is 8 bytes
                                payload = frame_data[header_len + 8:]
                elif ethertype == 0x0806:
                    # ARP
                    protocol_name = "ARP"
                    # ARP packets carry IP addresses inside but are not decoded here
                    src_ip = "Unknown"
                    dst_ip = "Unknown"
                else:
                    # Unsupported ethertype (IPv6, VLAN, etc.)
                    src_ip = "Unknown"
                    dst_ip = "Unknown"
                    protocol_name = "Unknown"

            packets.append(Packet(
                timestamp=timestamp_ms,
                source_ip=src_ip,
                dest_ip=dst_ip,
                protocol=protocol_name,
                source_port=src_port,
                dest_port=dst_port,
                length=length,
                payload=payload,
            ))

    return packets


def read_pcap_bytes(data: bytes) -> List[Packet]:
    """Parse a PCAP file from an in‑memory bytes object.

    Streamlit's file uploader returns file data as bytes.  To avoid writing
    temporary files to disk, this helper writes the bytes into a temporary
    buffer that mimics a file object.  The parsing logic is identical to
    :func:`read_pcap`, but reads from an in‑memory buffer instead of a
    filename.

    Args:
        data: Raw PCAP file contents.

    Returns:
        A list of :class:`Packet` instances.
    """
    import io
    with io.BytesIO(data) as f:
        packets: List[Packet] = []
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            return packets
        magic_number = struct.unpack("<I", global_hdr[:4])[0]
        if magic_number == 0xa1b2c3d4:
            endian = "<"
        elif magic_number == 0xd4c3b2a1:
            endian = ">"
        else:
            return packets
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = _unpack("IIII", pkt_hdr, endian)
            frame_data = f.read(incl_len)
            if len(frame_data) < incl_len:
                break
            timestamp_ms = ts_sec * 1000.0 + ts_usec / 1000.0
            length = incl_len
            src_ip = "Unknown"
            dst_ip = "Unknown"
            protocol_name = "Unknown"
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            payload: Optional[bytes] = None
            if len(frame_data) >= 14:
                ethertype = struct.unpack("!H", frame_data[12:14])[0]
                if ethertype == 0x0800 and len(frame_data) >= 14 + 20:
                    ip_header = frame_data[14:14 + 20]
                    version_ihl = ip_header[0]
                    version = version_ihl >> 4
                    ihl = (version_ihl & 0x0F) * 4
                    if version == 4 and len(frame_data) >= 14 + ihl:
                        src_ip_bytes = frame_data[14 + 12:14 + 16]
                        dst_ip_bytes = frame_data[14 + 16:14 + 20]
                        src_ip = ".".join(str(b) for b in src_ip_bytes)
                        dst_ip = ".".join(str(b) for b in dst_ip_bytes)
                        proto_num = frame_data[14 + 9]
                        if proto_num == 6:
                            protocol_name = "TCP"
                        elif proto_num == 17:
                            protocol_name = "UDP"
                        elif proto_num == 1:
                            protocol_name = "ICMP"
                        else:
                            protocol_name = "IP"
                        if proto_num in (6, 17) and len(frame_data) >= 14 + ihl + 4:
                            port_offset = 14 + ihl
                            src_port, dst_port = struct.unpack("!HH", frame_data[port_offset:port_offset + 4])
                            # Extract payload based on protocol
                            header_len = 14 + ihl
                            if proto_num == 6 and len(frame_data) >= header_len + 20:
                                data_offset = (frame_data[header_len + 12] >> 4) * 4
                                payload = frame_data[header_len + data_offset:]
                            elif proto_num == 17 and len(frame_data) >= header_len + 8:
                                payload = frame_data[header_len + 8:]
                elif ethertype == 0x0806:
                    protocol_name = "ARP"
                    src_ip = "Unknown"
                    dst_ip = "Unknown"
                else:
                    src_ip = "Unknown"
                    dst_ip = "Unknown"
                    protocol_name = "Unknown"
            packets.append(Packet(
                timestamp=timestamp_ms,
                source_ip=src_ip,
                dest_ip=dst_ip,
                protocol=protocol_name,
                source_port=src_port,
                dest_port=dst_port,
                length=length,
                payload=payload,
            ))
        return packets
