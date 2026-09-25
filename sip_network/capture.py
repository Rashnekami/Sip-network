from __future__ import annotations

import ipaddress
import io
import struct
from dataclasses import replace
from typing import BinaryIO, Iterator

from .models import Packet

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}

LINK_ETHERNET = 1
LINK_RAW = 101
LINK_LINUX_SLL = 113
LINK_LINUX_SLL2 = 276
LINK_LOOPBACK = 108
LINK_NULL = 0


L4_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPV6"}
FRAGMENT_TIMEOUT_S = 30.0


def read_capture(data: bytes) -> list[Packet]:
    if len(data) < 4:
        return []
    if data[:4] in PCAP_MAGIC:
        return reassemble_fragments(list(_read_pcap(io.BytesIO(data))))
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return reassemble_fragments(list(_read_pcapng(io.BytesIO(data))))
    raise ValueError("Formato não reconhecido. Envie um arquivo PCAP ou PCAPNG válido.")


def reassemble_fragments(packets: list[Packet]) -> list[Packet]:
    """Rebuild IPv4/IPv6 datagrams split into fragments.

    Like Wireshark, the reassembled datagram is reported on the packet carrying
    the last fragment to arrive. The other fragments stay in the list (they
    count as traffic) but carry no L4 payload, so SIP/RTP is never parsed twice.
    Incomplete datagrams fall back to decoding the first fragment as-is.
    """
    pending: dict[tuple, list[int]] = {}
    for i, p in enumerate(packets):
        if p.frag_info is None:
            continue
        key = p.frag_info[0]
        idxs = pending.setdefault(key, [])
        if idxs and p.timestamp - packets[idxs[0]].timestamp > FRAGMENT_TIMEOUT_S:
            idxs.clear()  # identification reused after timeout: start a new datagram
        idxs.append(i)
        data = _try_assemble([packets[j].frag_info for j in idxs])
        if data is None:
            continue
        proto = p.frag_info[4]
        whole = _decode_l4(proto, data, replace(p, frag_info=None, fragmented=True,
                                                parse_notes=(f"datagrama remontado de {len(idxs)} fragmentos",)))
        packets[i] = whole
        for j in idxs:
            if j != i:
                packets[j] = replace(packets[j], frag_info=None, payload=b"", src_port=None, dst_port=None,
                                     parse_notes=(f"fragmento remontado no pacote {p.number}",))
        del pending[key]

    for idxs in pending.values():
        for j in idxs:
            fi = packets[j].frag_info
            if fi and fi[1] == 0:
                partial = _decode_l4(fi[4], fi[3], replace(packets[j], frag_info=None,
                                                          parse_notes=("fragmento IP sem remontagem completa",)))
                packets[j] = partial
            else:
                packets[j] = replace(packets[j], frag_info=None,
                                     parse_notes=("fragmento IP sem remontagem completa",))
    return packets


def _try_assemble(frags: list) -> bytes | None:
    last = [f for f in frags if not f[2]]
    if not last:
        return None
    total = last[0][1] + len(last[0][3])
    buf = bytearray(total)
    covered = [False] * total
    for _key, off, _more, chunk, _proto in frags:
        end = min(total, off + len(chunk))
        buf[off:end] = chunk[: end - off]
        for k in range(off, end):
            covered[k] = True
    if not all(covered):
        return None
    return bytes(buf)


def _read_pcap(f: BinaryIO) -> Iterator[Packet]:
    header = f.read(24)
    if len(header) != 24:
        return
    endian, ts_unit = PCAP_MAGIC[header[:4]]
    _major, _minor, _zone, _sig, _snaplen, link_type = struct.unpack(endian + "HHiIII", header[4:24])
    number = 0
    while True:
        ph = f.read(16)
        if not ph:
            break
        if len(ph) != 16:
            break
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", ph)
        frame = f.read(incl_len)
        if len(frame) != incl_len:
            break
        number += 1
        pkt = _decode_frame(frame, number, ts_sec + ts_frac * ts_unit, incl_len, orig_len, link_type)
        yield pkt


def _read_pcapng(f: BinaryIO) -> Iterator[Packet]:
    number = 0
    endian = "<"
    interfaces: dict[int, tuple[int, float]] = {}

    while True:
        block_type_raw = f.read(4)
        if not block_type_raw:
            break
        if len(block_type_raw) != 4:
            break
        length_raw = f.read(4)
        if len(length_raw) != 4:
            break

        if block_type_raw == b"\x0a\x0d\x0d\x0a":
            bom = f.read(4)
            if len(bom) != 4:
                break
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("PCAPNG inválido: byte-order magic desconhecido")
            total_len = struct.unpack(endian + "I", length_raw)[0]
            rest = f.read(total_len - 12)
            if len(rest) != total_len - 12:
                break
            interfaces = {}
            continue

        total_len = struct.unpack(endian + "I", length_raw)[0]
        if total_len < 12:
            raise ValueError("PCAPNG inválido: tamanho de bloco incorreto")
        body = f.read(total_len - 12)
        tail = f.read(4)
        if len(body) != total_len - 12 or len(tail) != 4:
            break
        if struct.unpack(endian + "I", tail)[0] != total_len:
            raise ValueError("PCAPNG inválido: tamanho final do bloco diverge")

        block_type = struct.unpack(endian + "I", block_type_raw)[0]
        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                continue
            link_type = struct.unpack(endian + "H", body[:2])[0]
            ts_resolution = 1e-6
            options = body[8:]
            pos = 0
            while pos + 4 <= len(options):
                code, length = struct.unpack(endian + "HH", options[pos:pos + 4])
                pos += 4
                if code == 0:
                    break
                value = options[pos:pos + length]
                pos += (length + 3) & ~3
                if code == 9 and value:
                    v = value[0]
                    ts_resolution = (2.0 ** -(v & 0x7F)) if (v & 0x80) else (10.0 ** -v)
            interfaces[len(interfaces)] = (link_type, ts_resolution)

        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                continue
            if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            frame = body[20:20 + cap_len]
            if len(frame) != cap_len:
                continue
            link_type, ts_resolution = interfaces.get(if_id, (LINK_ETHERNET, 1e-6))
            ts = ((ts_hi << 32) | ts_lo) * ts_resolution
            number += 1
            yield _decode_frame(frame, number, ts, cap_len, orig_len, link_type)

        elif block_type == 3:  # Simple Packet Block, no timestamp available
            if len(body) < 4:
                continue
            orig_len = struct.unpack(endian + "I", body[:4])[0]
            frame = body[4:]
            link_type, _ = interfaces.get(0, (LINK_ETHERNET, 1e-6))
            number += 1
            yield _decode_frame(frame, number, 0.0, len(frame), orig_len, link_type)


def _decode_frame(frame: bytes, number: int, timestamp: float, cap_len: int, orig_len: int, link_type: int) -> Packet:
    base = Packet(number, timestamp, cap_len, orig_len, link_type)
    try:
        if link_type == LINK_ETHERNET:
            return _decode_ethernet(frame, base)
        if link_type == LINK_RAW:
            return _decode_ip(frame, base)
        if link_type == LINK_LINUX_SLL:
            if len(frame) < 16:
                return replace(base, parse_notes=("SLL truncado",))
            proto = struct.unpack("!H", frame[14:16])[0]
            return _decode_ethertype(proto, frame[16:], base)
        if link_type == LINK_LINUX_SLL2:
            if len(frame) < 20:
                return replace(base, parse_notes=("SLL2 truncado",))
            proto = struct.unpack("!H", frame[:2])[0]
            return _decode_ethertype(proto, frame[20:], base)
        if link_type in (LINK_LOOPBACK, LINK_NULL):
            if len(frame) < 4:
                return replace(base, parse_notes=("loopback truncado",))
            # AF_INET is commonly 2; AF_INET6 varies by platform. Try payload version first.
            return _decode_ip(frame[4:], base)
        return replace(base, parse_notes=(f"linktype {link_type} não suportado",))
    except Exception as exc:
        return replace(base, parse_notes=(f"erro de decode: {exc}",))


def _decode_ethernet(frame: bytes, base: Packet) -> Packet:
    if len(frame) < 14:
        return replace(base, parse_notes=("Ethernet truncado",))
    ethertype = struct.unpack("!H", frame[12:14])[0]
    pos = 14
    vlans: list[int] = []
    while ethertype in (0x8100, 0x88A8, 0x9100, 0x9200):
        if len(frame) < pos + 4:
            return replace(base, vlan_ids=tuple(vlans), parse_notes=("VLAN truncada",))
        tci, ethertype = struct.unpack("!HH", frame[pos:pos + 4])
        vlans.append(tci & 0x0FFF)
        pos += 4
    base = replace(base, vlan_ids=tuple(vlans))
    return _decode_ethertype(ethertype, frame[pos:], base)


def _decode_ethertype(ethertype: int, payload: bytes, base: Packet) -> Packet:
    if ethertype == 0x0800 or ethertype == 0x86DD:
        return _decode_ip(payload, base)
    if ethertype == 0x8864:  # PPPoE session
        if len(payload) < 8:
            return replace(base, protocol="PPPOE", parse_notes=("PPPoE truncado",))
        ppp_proto = struct.unpack("!H", payload[6:8])[0]
        if ppp_proto in (0x0021, 0x0057):
            return _decode_ip(payload[8:], base)
        return replace(base, protocol="PPPOE", parse_notes=(f"PPP proto 0x{ppp_proto:04x}",))
    if ethertype == 0x0806:
        return replace(base, protocol="ARP")
    return replace(base, protocol=f"ETH:0x{ethertype:04x}")


def _decode_ip(data: bytes, base: Packet) -> Packet:
    if not data:
        return base
    version = data[0] >> 4
    if version == 4:
        return _decode_ipv4(data, base)
    if version == 6:
        return _decode_ipv6(data, base)
    return replace(base, parse_notes=(f"versão IP {version} desconhecida",))


def _decode_ipv4(data: bytes, base: Packet) -> Packet:
    if len(data) < 20:
        return replace(base, ip_version=4, parse_notes=("IPv4 truncado",))
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return replace(base, ip_version=4, parse_notes=("IHL IPv4 inválido",))
    total_len = struct.unpack("!H", data[2:4])[0]
    proto = data[9]
    src = str(ipaddress.ip_address(data[12:16]))
    dst = str(ipaddress.ip_address(data[16:20]))
    flags_frag = struct.unpack("!H", data[6:8])[0]
    frag_offset = flags_frag & 0x1FFF
    more_frags = bool(flags_frag & 0x2000)
    fragmented = more_frags or frag_offset != 0
    l4 = data[ihl: min(total_len or len(data), len(data))]
    base = replace(base, src_ip=src, dst_ip=dst, ip_version=4, fragmented=fragmented, dscp=data[1] >> 2)
    if fragmented:
        ident = struct.unpack("!H", data[4:6])[0]
        return replace(base, protocol=L4_NAMES.get(proto, f"IP:{proto}"),
                       frag_info=((4, src, dst, ident, proto), frag_offset * 8, more_frags, l4, proto))
    return _decode_l4(proto, l4, base)


def _decode_ipv6(data: bytes, base: Packet) -> Packet:
    if len(data) < 40:
        return replace(base, ip_version=6, parse_notes=("IPv6 truncado",))
    next_header = data[6]
    traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4)
    payload_len = struct.unpack("!H", data[4:6])[0]
    if payload_len and 40 + payload_len < len(data):
        data = data[:40 + payload_len]
    src = str(ipaddress.ip_address(data[8:24]))
    dst = str(ipaddress.ip_address(data[24:40]))
    pos = 40
    fragmented = False
    frag = None
    for _ in range(12):
        if next_header in (0, 43, 60):  # HBH, routing, destination options
            if len(data) < pos + 2:
                break
            nh = data[pos]
            ext_len = (data[pos + 1] + 1) * 8
            next_header = nh
            pos += ext_len
        elif next_header == 44:  # fragment
            if len(data) < pos + 8:
                break
            nh = data[pos]
            frag_field = struct.unpack("!H", data[pos + 2:pos + 4])[0]
            ident = struct.unpack("!I", data[pos + 4:pos + 8])[0]
            fragmented = True
            frag = (ident, ((frag_field >> 3) & 0x1FFF) * 8, bool(frag_field & 1))
            next_header = nh
            pos += 8
            break  # headers after the fragment header belong to the fragmentable part
        elif next_header == 51:  # AH
            if len(data) < pos + 2:
                break
            nh = data[pos]
            ext_len = (data[pos + 1] + 2) * 4
            next_header = nh
            pos += ext_len
        else:
            break
    base = replace(base, src_ip=src, dst_ip=dst, ip_version=6, fragmented=fragmented, dscp=traffic_class >> 2)
    if frag is not None:
        ident, offset, more = frag
        return replace(base, protocol=L4_NAMES.get(next_header, f"IP6:{next_header}"),
                       frag_info=((6, src, dst, ident, next_header), offset, more, data[pos:], next_header))
    return _decode_l4(next_header, data[pos:], base)


def _decode_l4(proto: int, data: bytes, base: Packet) -> Packet:
    if proto == 17:  # UDP
        if len(data) < 8:
            return replace(base, protocol="UDP", parse_notes=("UDP truncado",))
        sp, dp, length, _checksum = struct.unpack("!HHHH", data[:8])
        payload_end = min(len(data), length) if length >= 8 else len(data)
        return replace(base, protocol="UDP", src_port=sp, dst_port=dp, payload=data[8:payload_end])
    if proto == 6:  # TCP
        if len(data) < 20:
            return replace(base, protocol="TCP", parse_notes=("TCP truncado",))
        sp, dp, seq, ack = struct.unpack("!HHII", data[:12])
        offset = ((data[12] >> 4) & 0x0F) * 4
        flags = data[13]
        if offset < 20 or offset > len(data):
            offset = min(20, len(data))
        return replace(base, protocol="TCP", src_port=sp, dst_port=dp, tcp_seq=seq, tcp_ack=ack, tcp_flags=flags, payload=data[offset:])
    if proto in (1, 58):
        if len(data) >= 2:
            return replace(base, protocol="ICMPV6" if proto == 58 else "ICMP", icmp_type=data[0], icmp_code=data[1], payload=data[4:])
        return replace(base, protocol="ICMPV6" if proto == 58 else "ICMP")
    return replace(base, protocol=f"IP:{proto}", payload=data)
