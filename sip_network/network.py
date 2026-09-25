from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import Packet, SipMessage


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


def analyze_sip_security(messages: list[SipMessage]) -> list[dict[str, Any]]:
    by_ip_method: dict[tuple, list[float]] = defaultdict(list)
    targets: dict[str, set[str]] = defaultdict(set)
    for m in messages:
        if not m.is_request or not m.src_ip or not m.method:
            continue
        by_ip_method[(m.src_ip, m.method)].append(m.timestamp)
        if m.to_uri: targets[m.src_ip].add(m.to_uri)
    alerts = []
    for (ip, method), times in by_ip_method.items():
        if len(times) < 10: continue
        duration = max(times)-min(times)
        rate = len(times)/duration if duration > 0 else float(len(times))
        threshold = 20 if method in ("INVITE", "REGISTER", "OPTIONS") else 50
        if rate >= threshold:
            alerts.append({"severity":"warning", "type":"rate", "source_ip":ip, "method":method, "rate_per_s":round(rate,2), "count":len(times), "detail":"Taxa SIP anormalmente alta; validar flood/teste de carga."})
    for ip, unique in targets.items():
        if len(unique) >= 30:
            alerts.append({"severity":"warning", "type":"scan", "source_ip":ip, "targets":len(unique), "detail":"Muitos destinos SIP distintos; possível enumeração/scan."})
    return alerts
