"""Flood and DDoS detection against VoIP infrastructure.

Traffic is bucketed per destination and per second. An event is a run of consecutive seconds above a rate threshold,
so a short burst (a re-INVITE storm, a backup) does not become an attack. Call media (RTP linked to a SIP call) is
excluded from the volumetric count: a busy SBC legitimately receives thousands of RTP packets per second.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

from .config import DEFAULT_THRESHOLDS, Thresholds
from .models import Packet, RtpStream, SipMessage

# UDP services abused for reflection/amplification, by source port.
AMPLIFIERS = {19: "CHARGEN", 53: "DNS", 123: "NTP", 161: "SNMP", 389: "CLDAP", 1900: "SSDP", 3702: "WS-Discovery",
              5353: "mDNS", 11211: "Memcached"}
TIMELINE_POINTS = 120


def _runs(rates: dict[int, float], minimum: float, min_len: int) -> list[tuple[int, int]]:
    """Consecutive seconds (tolerating a 1 s dip) with rate >= minimum, at least min_len seconds long."""
    hot = sorted(s for s, v in rates.items() if v >= minimum)
    runs: list[tuple[int, int]] = []
    for s in hot:
        if runs and s - runs[-1][1] <= 2:
            runs[-1] = (runs[-1][0], s)
        else:
            runs.append((s, s))
    return [(a, b) for a, b in runs if b - a + 1 >= min_len]


def _event(kind: str, sev: str, title: str, target: str, a: int, b: int, rates: dict[int, float],
           byte_rates: dict[int, float], sources: Counter, ports: Counter, detail: str, **extra: Any) -> dict[str, Any]:
    window = [rates.get(s, 0.0) for s in range(a, b + 1)]
    return {
        "type": kind, "severity": sev, "title": title, "target_ip": target,
        "target_port": ports.most_common(1)[0][0] if ports else None,
        "start": float(a), "end": float(b + 1), "duration_s": b - a + 1,
        "peak_pps": round(max(window), 1), "avg_pps": round(sum(window) / len(window), 1),
        "peak_mbps": round(max(byte_rates.get(s, 0.0) for s in range(a, b + 1)) * 8 / 1e6, 3),
        "sources": len(sources),
        "top_sources": [{"ip": ip, "packets": n} for ip, n in sources.most_common(10)],
        "detail": detail, **extra,
    }


def analyze_ddos(packets: list[Packet], sip_messages: list[SipMessage], streams: list[RtpStream],
                 th: Thresholds = DEFAULT_THRESHOLDS) -> dict[str, Any]:
    media = {(s.src_ip, s.src_port, s.dst_ip, s.dst_port) for s in streams if s.call_id}
    # counters[kind][dst][second] = packets; bytes only for volumetric/reflection.
    counters: dict[str, dict[str, dict[int, float]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    vol_bytes: dict[str, dict[int, float]] = defaultdict(lambda: defaultdict(float))
    synack: dict[str, dict[int, float]] = defaultdict(lambda: defaultdict(float))
    total: dict[int, float] = defaultdict(float)
    total_bytes: dict[int, float] = defaultdict(float)
    seconds: set[int] = set()

    for p in packets:
        if p.timestamp <= 0:
            continue
        sec = int(p.timestamp)
        seconds.add(sec)
        total[sec] += 1
        total_bytes[sec] += p.original_len
        if not p.dst_ip:
            continue
        dst = p.dst_ip
        if p.protocol == "TCP" and p.tcp_flags is not None:
            if p.tcp_flags & 0x02 and not p.tcp_flags & 0x10:
                counters["syn"][dst][sec] += 1
            elif p.tcp_flags & 0x12 == 0x12 and p.src_ip:
                synack[p.src_ip][sec] += 1
        elif p.protocol in ("ICMP", "ICMPV6"):
            counters["icmp"][dst][sec] += 1
        elif p.protocol == "UDP" and p.src_port in AMPLIFIERS:
            counters["reflection"][dst][sec] += 1
            vol_bytes["reflection:" + dst][sec] += p.original_len
        if (p.src_ip, p.src_port, p.dst_ip, p.dst_port) not in media:
            counters["volumetric"][dst][sec] += 1
            vol_bytes[dst][sec] += p.original_len
    for m in sip_messages:
        if m.is_request and m.dst_ip and m.timestamp > 0:
            counters["sip"][m.dst_ip][int(m.timestamp)] += 1

    span = (max(seconds) - min(seconds) + 1) if seconds else 0
    min_len = max(1, min(th.ddos_min_seconds, span))
    candidates: list[tuple[str, str, int, int]] = []
    for kind, minimum in (("syn", th.syn_flood_min_pps), ("icmp", th.icmp_flood_min_pps),
                          ("reflection", th.reflection_min_pps), ("sip", th.sip_flood_min_rps),
                          ("volumetric", th.ddos_min_pps)):
        for dst, rates in counters[kind].items():
            for a, b in _runs(rates, minimum, min_len):
                if kind == "volumetric":
                    outside = [rates.get(s, 0.0) for s in range(min(seconds), max(seconds) + 1) if not a <= s <= b]
                    baseline = statistics.median(outside) if outside else 0.0
                    peak = max(rates.get(s, 0.0) for s in range(a, b + 1))
                    if baseline and peak < baseline * th.ddos_baseline_factor:
                        continue
                candidates.append((kind, dst, a, b))
    if not candidates:
        return {"events": [], "timeline": _timeline(total, total_bytes)}

    # Second pass only over packets inside candidate windows, to name the sources.
    wanted: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
    for kind, dst, a, b in candidates:
        wanted[(kind, dst)].append((a, b))
    sources: dict[tuple[str, str, int], Counter] = defaultdict(Counter)
    ports: dict[tuple[str, str, int], Counter] = defaultdict(Counter)
    amp_service: dict[tuple[str, str, int], Counter] = defaultdict(Counter)

    def _hit(kind: str, dst: str, sec: int) -> int | None:
        for a, b in wanted.get((kind, dst), ()):
            if a <= sec <= b:
                return a
        return None

    for p in packets:
        if p.timestamp <= 0 or not p.dst_ip:
            continue
        sec, dst = int(p.timestamp), p.dst_ip
        kinds = []
        if p.protocol == "TCP" and p.tcp_flags is not None and p.tcp_flags & 0x02 and not p.tcp_flags & 0x10:
            kinds.append("syn")
        elif p.protocol in ("ICMP", "ICMPV6"):
            kinds.append("icmp")
        elif p.protocol == "UDP" and p.src_port in AMPLIFIERS:
            kinds.append("reflection")
        if (p.src_ip, p.src_port, p.dst_ip, p.dst_port) not in media:
            kinds.append("volumetric")
        for kind in kinds:
            a = _hit(kind, dst, sec)
            if a is not None:
                sources[(kind, dst, a)][p.src_ip or "?"] += 1
                if p.dst_port is not None:
                    ports[(kind, dst, a)][p.dst_port] += 1
                if kind == "reflection":
                    amp_service[(kind, dst, a)][AMPLIFIERS[p.src_port]] += 1
    for m in sip_messages:
        if m.is_request and m.dst_ip and m.timestamp > 0:
            a = _hit("sip", m.dst_ip, int(m.timestamp))
            if a is not None:
                key = ("sip", m.dst_ip, a)
                sources[key][m.src_ip or "?"] += 1
                if m.dst_port is not None:
                    ports[key][m.dst_port] += 1
                amp_service[key][m.method or "?"] += 1

    events: list[dict[str, Any]] = []
    for kind, dst, a, b in candidates:
        key = (kind, dst, a)
        srcs, rates = sources[key], counters[kind][dst]
        n = len(srcs)
        distributed = n >= th.ddos_distributed_sources
        who = f"{n} origens" + (" (distribuído)" if distributed else "")
        if kind == "syn":
            answered = sum(synack[dst].get(s, 0.0) for s in range(a, b + 1))
            sent = sum(rates.get(s, 0.0) for s in range(a, b + 1))
            ratio = answered / sent if sent else 0.0
            events.append(_event("SYN_FLOOD", "critical", "SYN flood (TCP)", dst, a, b, rates, vol_bytes[dst], srcs, ports[key],
                                 f"{dst} recebeu SYNs a até {max(rates.get(s, 0) for s in range(a, b + 1)):.0f}/s por {b - a + 1}s vindos de {who}; "
                                 f"só {ratio:.0%} foram respondidos com SYN-ACK. A tabela de conexões do servidor (SIP/TLS 5061, painel web) esgota. "
                                 "Ação: SYN cookies, rate limit por origem no firewall e, se distribuído, mitigação na operadora.",
                                 synack_ratio=round(ratio, 3), distributed=distributed))
        elif kind == "icmp":
            events.append(_event("ICMP_FLOOD", "warning", "ICMP flood", dst, a, b, rates, vol_bytes[dst], srcs, ports[key],
                                 f"{dst} recebeu ICMP a até {max(rates.get(s, 0) for s in range(a, b + 1)):.0f}/s por {b - a + 1}s de {who}. "
                                 "Consome banda do link e CPU do roteador. Ação: limitar ICMP no firewall de borda.",
                                 distributed=distributed))
        elif kind == "reflection":
            svc = amp_service[key].most_common(1)[0][0] if amp_service[key] else "UDP"
            refl_bytes = vol_bytes["reflection:" + dst]
            pkts = sum(rates.get(s, 0.0) for s in range(a, b + 1))
            avg_size = sum(refl_bytes.get(s, 0.0) for s in range(a, b + 1)) / pkts if pkts else 0.0
            events.append(_event("REFLECTION_AMPLIFICATION", "critical", f"Ataque de reflexão/amplificação {svc}", dst, a, b, rates,
                                 refl_bytes, srcs, ports[key],
                                 f"{dst} recebeu respostas {svc} que não pediu (porta de origem {next(p for p, s in AMPLIFIERS.items() if s == svc)}), "
                                 f"média de {avg_size:.0f} bytes, de {who}. Servidores {svc} abertos na internet estão sendo usados para "
                                 "amplificar tráfego contra você: o link satura e a voz picota ou cai. Ação: pedir mitigação/blackhole à operadora "
                                 f"e bloquear UDP com origem {svc} no upstream.",
                                 service=svc, avg_packet_bytes=round(avg_size), distributed=distributed))
        elif kind == "sip":
            if n < 3:
                continue  # one or two sources: already reported per source by the SIP security engine
            methods = ", ".join(f"{k} {v}" for k, v in amp_service[key].most_common(3))
            events.append(_event("SIP_FLOOD_DISTRIBUTED", "critical", "Flood SIP distribuído", dst, a, b, rates, vol_bytes[dst], srcs, ports[key],
                                 f"{dst} recebeu até {max(rates.get(s, 0) for s in range(a, b + 1)):.0f} requisições SIP/s por {b - a + 1}s de {who} "
                                 f"({methods}). O PBX/SBC gasta CPU respondendo e chamadas legítimas sofrem timeout. Ação: rate limit (pike/fail2ban), "
                                 "ACL só com IPs de tronco e clientes, e SBC na borda.",
                                 methods=dict(amp_service[key]), distributed=distributed))
        else:
            if any(e["target_ip"] == dst and e["start"] <= b + 1 and a <= e["end"] for e in events):
                continue  # a specific flood already explains this volume
            events.append(_event("DDOS_VOLUMETRIC" if distributed else "DOS_VOLUMETRIC", "critical",
                                 "DDoS volumétrico" if distributed else "Flood volumétrico", dst, a, b, rates, vol_bytes[dst], srcs, ports[key],
                                 f"{dst} recebeu até {max(rates.get(s, 0) for s in range(a, b + 1)):.0f} pacotes/s fora de chamadas por {b - a + 1}s, "
                                 f"de {who}, muito acima do normal da captura. Saturação do link deixa a voz picotando e derruba registros. "
                                 "Ação: identificar as origens abaixo, bloquear no firewall e acionar a operadora se o link estiver cheio.",
                                 distributed=distributed))
    events.sort(key=lambda e: (e["severity"] != "critical", -e["peak_pps"]))
    return {"events": events, "timeline": _timeline(total, total_bytes)}


def _timeline(total: dict[int, float], total_bytes: dict[int, float]) -> list[dict[str, Any]]:
    """Packets and Mbit/s per second across the capture, downsampled for a line chart."""
    if not total:
        return []
    first, last = min(total), max(total)
    step = max(1, -(-(last - first + 1) // TIMELINE_POINTS))
    out = []
    for start in range(first, last + 1, step):
        secs = range(start, min(start + step, last + 1))
        pk = max(total.get(s, 0.0) for s in secs)
        by = max(total_bytes.get(s, 0.0) for s in secs)
        out.append({"t": float(start), "pps": round(pk, 1), "mbps": round(by * 8 / 1e6, 3)})
    return out
