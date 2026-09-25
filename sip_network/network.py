from __future__ import annotations

import ipaddress
import struct
from typing import Any

from .models import Packet


def analyze_network(packets: list[Packet]) -> list[dict[str, Any]]:
    flows: dict[tuple, dict[str, Any]] = {}
    for p in packets:
        if not p.src_ip or not p.dst_ip:
            continue
        key = (p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol)
        f = flows.setdefault(key, {
            "src_ip": p.src_ip, "dst_ip": p.dst_ip, "src_port": p.src_port, "dst_port": p.dst_port,
            "protocol": p.protocol, "packets": 0, "bytes": 0, "timestamps": [], "tcp_resets": 0,
            "vlans": set(),
        })
        f["packets"] += 1; f["bytes"] += p.original_len; f["timestamps"].append(p.timestamp); f["vlans"].update(p.vlan_ids)
        if p.protocol == "TCP" and p.tcp_flags is not None and (p.tcp_flags & 0x04):
            f["tcp_resets"] += 1
    out = []
    for f in flows.values():
        ts = sorted(t for t in f.pop("timestamps") if t > 0)
        gaps = [(b-a)*1000.0 for a,b in zip(ts, ts[1:])]
        duration = ts[-1]-ts[0] if len(ts) > 1 else 0.0
        f["duration_s"] = round(duration, 3)
        f["avg_interpacket_gap_ms"] = round(sum(gaps)/len(gaps), 3) if gaps else 0.0
        f["max_interpacket_gap_ms"] = round(max(gaps), 3) if gaps else 0.0
        f["pps"] = round(f["packets"] / duration, 2) if duration > 0 else 0.0
        f["kbps"] = round(f["bytes"] * 8 / 1000.0 / duration, 2) if duration > 0 else 0.0
        f["vlans"] = sorted(f["vlans"])
        out.append(f)
    out.sort(key=lambda x: x["bytes"], reverse=True)
    return out


ICMP_UNREACH_TEXT = {
    0: "rede inalcançável", 1: "host inalcançável", 2: "protocolo inalcançável", 3: "porta inalcançável",
    4: "fragmentação necessária (MTU)", 9: "rede proibida administrativamente", 10: "host proibido administrativamente",
    13: "comunicação proibida administrativamente (filtro/ACL)",
}
ICMP6_UNREACH_TEXT = {0: "sem rota", 1: "proibido administrativamente", 3: "endereço inalcançável", 4: "porta inalcançável"}


def analyze_icmp_errors(packets: list[Packet]) -> list[dict[str, Any]]:
    """Decode ICMP/ICMPv6 destination-unreachable errors back to the UDP/TCP flow that triggered them."""
    out: dict[tuple, dict[str, Any]] = {}
    for p in packets:
        inner = None
        # p.payload starts after the 4-byte ICMP type/code/checksum; skip the 4 unused bytes to reach the quoted header.
        if p.protocol == "ICMP" and p.icmp_type == 3 and len(p.payload) >= 32:
            q = p.payload[4:]
            ihl = (q[0] & 0x0F) * 4
            if len(q) >= ihl + 4:
                proto = q[9]
                src = ".".join(str(b) for b in q[12:16]); dst = ".".join(str(b) for b in q[16:20])
                sp, dp = struct.unpack("!HH", q[ihl:ihl + 4])
                inner = (proto, src, dst, sp, dp, ICMP_UNREACH_TEXT.get(p.icmp_code, f"código {p.icmp_code}"))
        elif p.protocol == "ICMPV6" and p.icmp_type == 1 and len(p.payload) >= 48:
            q = p.payload[4:]
            proto = q[6]
            src = str(ipaddress.ip_address(q[8:24])); dst = str(ipaddress.ip_address(q[24:40]))
            sp, dp = struct.unpack("!HH", q[40:44])
            inner = (proto, src, dst, sp, dp, ICMP6_UNREACH_TEXT.get(p.icmp_code, f"código {p.icmp_code}"))
        if inner is None:
            continue
        proto, src, dst, sp, dp, text = inner
        key = (proto, src, dst, sp, dp, p.icmp_code)
        e = out.setdefault(key, {"reporter_ip": p.src_ip, "orig_protocol": {17: "UDP", 6: "TCP"}.get(proto, str(proto)),
                                 "orig_src_ip": src, "orig_dst_ip": dst, "orig_src_port": sp, "orig_dst_port": dp,
                                 "icmp_code": p.icmp_code, "reason": text, "count": 0, "first_at": p.timestamp})
        e["count"] += 1
    return sorted(out.values(), key=lambda e: -e["count"])
