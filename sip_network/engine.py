from __future__ import annotations

from .capture import read_capture
from .config import DEFAULT_THRESHOLDS, Thresholds
from .diagnostics import diagnose
from .kpi import compute_kpis
from .models import AnalysisResult
from .network import analyze_icmp_errors, analyze_network
from .registrations import analyze_registrations, request_transactions
from .rtp import analyze_rtp
from .security import analyze_sip_security
from .sip import build_calls, extract_sip_messages


def analyze_bytes(data: bytes, filename: str = "capture", thresholds: Thresholds = DEFAULT_THRESHOLDS) -> AnalysisResult:
    """Analyse a PCAP/PCAPNG capture held in memory. This is the stable entry point for integrations."""
    packets = read_capture(data)
    if not packets:
        raise ValueError("A captura não contém pacotes decodificáveis.")
    timestamps = [p.timestamp for p in packets if p.timestamp > 0]
    capture_start = min(timestamps) if timestamps else 0.0
    capture_end = max(timestamps) if timestamps else 0.0
    sip_messages = extract_sip_messages(packets)
    calls = build_calls(sip_messages, capture_end)
    streams = analyze_rtp(packets, calls, thresholds.rtp_gap_ms)
    transactions = request_transactions(sip_messages)
    registrations = analyze_registrations(sip_messages)
    security = analyze_sip_security(sip_messages, transactions, calls, thresholds)
    icmp_errors = analyze_icmp_errors(packets)
    diagnostics = diagnose(calls, streams, thresholds, capture_end, security, icmp_errors, registrations)
    network = analyze_network(packets)
    kpis = compute_kpis(calls, streams, sip_messages, registrations)
    kpis["icmp_errors"] = icmp_errors
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
        network_flows=network, security=security, kpis=kpis, registrations=registrations,
    )


def analyze_file(path: str, thresholds: Thresholds = DEFAULT_THRESHOLDS) -> AnalysisResult:
    with open(path, "rb") as f:
        data = f.read()
    return analyze_bytes(data, path.rsplit("/", 1)[-1], thresholds)
