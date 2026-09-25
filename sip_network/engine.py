from __future__ import annotations

from .capture import read_capture
from .diagnostics import diagnose
from .models import AnalysisResult
from .network import analyze_network, analyze_sip_security
from .rtp import analyze_rtp
from .sip import build_calls, extract_sip_messages


def analyze_bytes(data: bytes, filename: str = "capture") -> AnalysisResult:
    packets = read_capture(data)
    if not packets:
        raise ValueError("A captura não contém pacotes decodificáveis.")
    timestamps = [p.timestamp for p in packets if p.timestamp > 0]
    capture_start = min(timestamps) if timestamps else 0.0
    capture_end = max(timestamps) if timestamps else 0.0
    sip_messages = extract_sip_messages(packets)
    calls = build_calls(sip_messages, capture_end)
    streams = analyze_rtp(packets, calls)
    diagnostics = diagnose(calls, streams)
    network = analyze_network(packets)
    security = analyze_sip_security(sip_messages)
    notes = sorted({note for p in packets for note in p.parse_notes})
    return AnalysisResult(
        capture={
            "filename": filename,
            "packets": len(packets),
            "bytes": sum(p.original_len for p in packets),
            "start": capture_start,
            "end": capture_end,
            "duration_s": max(0.0, capture_end - capture_start),
            "sip_messages": len(sip_messages),
            "sip_calls": len(calls),
            "rtp_streams": len(streams),
            "ipv4_packets": sum(1 for p in packets if p.ip_version == 4),
            "ipv6_packets": sum(1 for p in packets if p.ip_version == 6),
            "vlan_packets": sum(1 for p in packets if p.vlan_ids),
            "fragmented_packets": sum(1 for p in packets if p.fragmented),
            "parse_notes": notes[:30],
        },
        calls=calls, rtp_streams=streams, diagnostics=diagnostics,
        network_flows=network, security=security,
    )
