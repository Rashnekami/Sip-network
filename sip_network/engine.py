from __future__ import annotations

from collections import Counter
from typing import Any

from .capture import read_capture
from .config import DEFAULT_THRESHOLDS, Thresholds
from .ddos import analyze_ddos
from .diagnostics import CATEGORY_LABELS, diagnose
from .kpi import compute_kpis
from .models import AnalysisResult
from .nat import analyze_nat
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
    nat = analyze_nat(sip_messages, calls, streams, thresholds)
    ddos = analyze_ddos(packets, sip_messages, streams, thresholds)
    diagnostics = diagnose(calls, streams, thresholds, capture_end, security, icmp_errors, registrations, nat, ddos["events"])
    network = analyze_network(packets)
    kpis = compute_kpis(calls, streams, sip_messages, registrations)
    kpis["icmp_errors"] = icmp_errors
    kpis["traffic_timeline"] = ddos["timeline"]
    kpis["charts"] = build_charts(calls, streams, diagnostics, security, nat, ddos["events"])
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
        nat=nat, ddos=ddos["events"],
    )


SEVERITY_LABELS = {"critical": "Crítico", "warning": "Alerta", "info": "Informativo"}
OUTCOME_LABELS = {"answered": "Atendida", "busy": "Ocupado", "no_answer": "Não atendida", "cancelled": "Cancelada",
                  "rejected": "Recusada", "not_found": "Número inexistente", "auth_failed": "Falha de autenticação",
                  "media_negotiation_failed": "Codec incompatível", "server_error": "Erro do servidor", "timeout": "Timeout",
                  "no_response": "Sem resposta", "client_error": "Erro do cliente", "global_failure": "Falha global",
                  "redirected": "Redirecionada", "in_progress": "Em andamento"}

SECURITY_LABELS = {"scanner": "Scanner SIP", "brute_force": "Força bruta de senha", "enumeration": "Enumeração de ramais",
                   "options_sweep": "Varredura OPTIONS", "rate": "Flood por método", "scan": "Varredura de destinos",
                   "toll_fraud": "Fraude internacional"}


def _pie(counter: Counter, labels: dict[str, str] | None = None, key: str = "key") -> list[dict[str, Any]]:
    return [{key: k, "label": (labels or {}).get(k, str(k)), "value": v} for k, v in counter.most_common() if v]


def build_charts(calls, streams, diagnostics, security, nat, ddos) -> dict[str, list[dict[str, Any]]]:
    """Ready-to-plot {key,label,value} series for donut/pie charts, so every client draws the same numbers."""
    mos_bands = Counter()
    for s in streams:
        if s.mos is None:
            continue
        mos_bands["otimo" if s.mos >= 4.0 else "bom" if s.mos >= 3.6 else "regular" if s.mos >= 3.1 else "ruim"] += 1
    final_codes = Counter(str(c.final_status) for c in calls if c.final_status is not None and c.final_status >= 300)
    return {
        "diagnostics_by_severity": _pie(Counter(d.severity for d in diagnostics), SEVERITY_LABELS),
        "diagnostics_by_category": _pie(Counter(d.category for d in diagnostics), CATEGORY_LABELS),
        "problems_by_category": _pie(Counter(d.category for d in diagnostics if d.severity != "info"), CATEGORY_LABELS),
        "call_outcomes": _pie(Counter(c.outcome for c in calls if c.outcome), OUTCOME_LABELS),
        "sip_error_codes": _pie(final_codes),
        "mos_bands": _pie(mos_bands, {"otimo": "Ótimo (≥ 4,0)", "bom": "Bom (3,6–4,0)", "regular": "Regular (3,1–3,6)", "ruim": "Ruim (< 3,1)"}),
        "security_by_type": _pie(Counter(a["type"] for a in security), SECURITY_LABELS),
        "nat_by_type": _pie(Counter(f["type"] for f in nat), {f["type"]: f["title"] for f in nat}),
        "ddos_by_type": _pie(Counter(e["type"] for e in ddos), {e["type"]: e["title"] for e in ddos}),
    }


def analyze_file(path: str, thresholds: Thresholds = DEFAULT_THRESHOLDS) -> AnalysisResult:
    with open(path, "rb") as f:
        data = f.read()
    return analyze_bytes(data, path.rsplit("/", 1)[-1], thresholds)
