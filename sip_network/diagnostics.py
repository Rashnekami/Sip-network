from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

from .config import DEFAULT_THRESHOLDS, Thresholds
from .models import Diagnostic, RtpStream, SipCall

DSCP_NAMES = {0: "BE", 8: "CS1", 10: "AF11", 16: "CS2", 18: "AF21", 24: "CS3", 26: "AF31", 32: "CS4",
              34: "AF41", 40: "CS5", 46: "EF", 48: "CS6", 56: "CS7"}

OUTCOME_SEVERITY = {
    "no_response": "critical", "server_error": "critical", "timeout": "critical",
    "media_negotiation_failed": "critical", "auth_failed": "warning", "not_found": "warning",
    "rejected": "warning", "client_error": "warning", "global_failure": "warning",
    "busy": "info", "no_answer": "info", "redirected": "info",
}
OUTCOME_HINT = {
    "no_response": "O INVITE não recebeu nenhuma resposta (nem 100 Trying). Verificar rota IP, firewall/ACL, porta e se o destino está ativo.",
    "server_error": "O destino ou um proxy intermediário retornou erro 5xx. Verificar capacidade do tronco, rota e logs do servidor.",
    "timeout": "Timeout de transação (408). O próximo salto não respondeu a tempo; checar rota, DNS SRV e alcance do destino.",
    "media_negotiation_failed": "Negociação de mídia falhou (488/606/415). Comparar codecs oferecidos no SDP com os aceitos pelo destino.",
    "auth_failed": "Credencial recusada: o desafio 401/407 não foi atendido com sucesso. Verificar usuário/senha do tronco ou ramal.",
    "not_found": "Número/usuário inexistente (404/484/604). Verificar formato de discagem e plano de numeração.",
    "rejected": "Chamada recusada (403/603). Verificar permissões, bloqueios, saldo ou ACL no destino.",
}


CATEGORY_LABELS = {"sinalizacao": "Sinalização SIP", "midia": "Mídia/áudio", "nat": "NAT", "seguranca": "Segurança",
                   "ddos": "DDoS/flood", "rede": "Rede/QoS", "registro": "Registro",
                   "webrtc": "WebRTC"}


def category_of(code: str) -> str:
    if code.startswith("WEBRTC_"):
        return "webrtc"
    if code.startswith("SEC_"):
        return "seguranca"
    if code.startswith(("NAT_", "SIP_ALG", "DEVICE_BEHIND_NAT")):
        return "nat"
    if code.startswith("REGISTER_"):
        return "registro"
    if code.startswith(("ICMP_", "IP_")) or code.endswith("_DSCP"):
        return "rede"
    if code.startswith(("RTP_", "RTCP_", "MEDIA_", "LOW_MOS", "ONE_WAY", "NO_RTP")):
        return "midia"
    if code.endswith(("_FLOOD", "_VOLUMETRIC", "_AMPLIFICATION", "_DISTRIBUTED")):
        return "ddos"
    return "sinalizacao"


def _public(ip: str | None) -> bool:
    if not ip: return False
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_unspecified)
    except ValueError:
        return False


def _dscp(v: int | None) -> str:
    if v is None:
        return "?"
    return f"{DSCP_NAMES.get(v, 'DSCP')} ({v})"


def _call_rules(c: SipCall, cstreams: list[RtpStream], th: Thresholds, capture_end: float | None) -> list[Diagnostic]:
    d: list[Diagnostic] = []
    cid = c.call_id
    add = lambda sev, code, title, detail, conf, evidence=None: d.append(Diagnostic(sev, code, title, detail, conf, cid, None, evidence or {}))

    sev = OUTCOME_SEVERITY.get(c.outcome)
    if sev and c.outcome != "no_response":
        cause = f" Q.850 {c.q850_cause} ({c.q850_text})." if c.q850_cause is not None else ""
        add(sev, "SIP_FINAL_FAILURE", "Falha no estabelecimento SIP",
            f"INVITE terminou em {c.final_status} {c.final_reason or ''}.{cause} {OUTCOME_HINT.get(c.outcome, '')}".strip(), "high",
            {"status": c.final_status, "reason": c.final_reason, "outcome": c.outcome, "q850": c.q850_cause, "reason_header": c.reason_header})
    if c.no_response:
        waited = (capture_end - c.started_at) if capture_end else None
        add("critical" if (waited or 0) >= 32 else "warning", "SIP_NO_RESPONSE", "INVITE sem nenhuma resposta",
            OUTCOME_HINT["no_response"] + (f" A captura seguiu por {waited:.0f}s depois do INVITE." if waited is not None else ""),
            "high" if (waited or 0) >= 32 else "medium", {"retransmissions": c.retransmissions, "destination": c.callee_ip})
    if c.missing_ack:
        add("critical", "SIP_MISSING_ACK", "ACK não observado após 2xx do INVITE",
            "O 200 OK do INVITE não recebeu ACK. O destino vai retransmitir o 200 OK e derrubar a chamada em ~32s (Timer H). "
            "Causas comuns: Contact/Record-Route com IP privado, NAT, ALG SIP ou firewall bloqueando o ACK.",
            "high", {"dialogs_without_ack": c.unanswered_ack_dialogs})
    if c.forked:
        add("info", "SIP_FORKED_ANSWER", "Chamada atendida por mais de um destino (forking)",
            f"{sum(1 for x in c.dialogs if x['state'] == 'confirmed')} diálogos confirmados para o mesmo INVITE. O originador deve encerrar os excedentes com BYE.",
            "high", {"dialogs": [x["remote_tag"] for x in c.dialogs]})
    if c.auth_challenges >= th.auth_challenge_loop:
        add("warning", "SIP_AUTH_LOOP", "Desafios de autenticação repetidos",
            f"O INVITE foi desafiado {c.auth_challenges} vezes antes do resultado final. Normalmente indica senha/realm incorretos.", "high",
            {"challenges": c.auth_challenges})
    if c.retransmissions >= th.retransmissions_warning:
        add("warning", "SIP_RETRANSMISSIONS", "Retransmissões SIP elevadas",
            f"{c.retransmissions} mensagens SIP repetidas na mesma transação: perda de pacotes ou destino lento na sinalização.", "medium",
            {"retransmissions": c.retransmissions})
    if c.pdd_ms is not None and c.pdd_ms >= th.pdd_warning_ms:
        add("critical" if c.pdd_ms >= th.pdd_critical_ms else "warning", "SIP_HIGH_PDD", "Pós-discagem (PDD) alto",
            f"{c.pdd_ms / 1000:.1f}s entre o INVITE e a primeira resposta de progresso. Rota longa, destino lento ou failover entre rotas.",
            "high", {"pdd_ms": c.pdd_ms})
    if c.connected and not c.termination_observed:
        add("info", "SIP_TERMINATION_NOT_SEEN", "Término da chamada não observado",
            "A chamada foi atendida mas a captura não mostra BYE. A captura pode ter terminado antes da chamada.", "high")
    if c.connected and c.termination_observed and c.duration_s is not None:
        if 30.0 <= c.duration_s <= 34.0 and (c.missing_ack or c.disconnect_side == "callee"):
            add("critical", "SIP_DROP_32S", "Chamada derrubada em ~32 segundos",
                f"A chamada durou {c.duration_s:.1f}s e foi encerrada pelo lado chamado. É o sintoma clássico de ACK que não chega ao destino (Timer H = 64×T1).",
                "medium", {"duration_s": c.duration_s})
        elif c.session_expires and abs(c.duration_s - c.session_expires) <= 5:
            add("warning", "SIP_SESSION_TIMER_DROP", "Chamada caiu no tempo do session timer",
                f"Duração {c.duration_s:.0f}s coincide com Session-Expires={c.session_expires}s. O refresh (re-INVITE/UPDATE) não foi feito ou não foi respondido.",
                "medium", {"duration_s": c.duration_s, "session_expires": c.session_expires})
        elif c.duration_s < th.short_call_s:
            add("info", "SIP_SHORT_CALL", "Chamada muito curta",
                f"Atendida e encerrada em {c.duration_s:.1f}s pelo {'originador' if c.disconnect_side == 'caller' else 'destino'}. "
                "Muitas chamadas assim costumam indicar áudio mudo ou unidirecional.", "low", {"duration_s": c.duration_s})
    if c.hold_events:
        holds = sum(1 for h in c.hold_events if h["event"] == "hold")
        add("info", "SIP_HOLD", "Chamada colocada em espera",
            f"{holds} evento(s) de espera via re-INVITE/UPDATE. Silêncio durante a espera é esperado.", "high", {"events": c.hold_events})
    if c.transfers:
        add("info", "SIP_TRANSFER", "Transferência (REFER)",
            f"{len(c.transfers)} transferência(s) pedida(s); resultado: {', '.join(str(t['status']) for t in c.transfers)}.", "high",
            {"transfers": c.transfers})

    # Media vs signalling.
    if c.connected and not cstreams:
        add("critical", "NO_RTP_AFTER_ANSWER", "Sem RTP após atendimento",
            "A chamada teve 2xx para o INVITE, porém nenhum fluxo RTP confiável foi associado. Verifique SDP, NAT, firewall e ponto de captura.", "medium")
    elif c.connected and cstreams:
        direction_pairs = {(s.src_ip, s.dst_ip) for s in cstreams if s.packets >= 10}
        reverse_ok = any((b, a) in direction_pairs for a, b in direction_pairs)
        biggest = max(cstreams, key=lambda s: s.packets)
        if biggest.packets >= 20 and not reverse_ok:
            d.append(Diagnostic("critical", "ONE_WAY_AUDIO", "Áudio em apenas uma direção",
                                "Há RTP consistente em uma direção, mas não foi encontrado fluxo reverso equivalente. Possíveis causas: NAT, SDP incorreto, ACL/firewall ou captura assimétrica.",
                                "medium", cid, biggest.stream_id, {"dominant_stream": biggest.stream_id, "packets": biggest.packets}))
        first_rtp = min(s.first_packet_at for s in cstreams if s.first_packet_at is not None)
        if c.connected_at and first_rtp - c.connected_at >= th.media_start_delay_s and (c.early_media_at is None):
            add("warning", "MEDIA_START_DELAY", "Áudio começa atrasado após o atendimento",
                f"O primeiro RTP apareceu {first_rtp - c.connected_at:.1f}s depois do 200 OK: o início da conversa é cortado (clipping).",
                "medium", {"delay_s": round(first_rtp - c.connected_at, 2)})
        if c.terminated_at:
            late = [s for s in cstreams if s.last_packet_at and s.last_packet_at - c.terminated_at >= th.rtp_after_bye_s]
            if late:
                add("warning", "RTP_AFTER_BYE", "RTP continua depois do BYE",
                    f"{len(late)} fluxo(s) seguiram enviando mídia até {max(s.last_packet_at for s in late) - c.terminated_at:.1f}s após o BYE. "
                    "A mídia não foi liberada (BYE não chegou ao outro lado ou gateway travado).", "medium",
                    {"streams": [s.stream_id for s in late]})

    return d


def _stream_rules(s: RtpStream, th: Thresholds) -> list[Diagnostic]:
    d: list[Diagnostic] = []
    add = lambda sev, code, title, detail, conf, evidence: d.append(Diagnostic(sev, code, title, detail, conf, s.call_id, s.stream_id, evidence))
    sev = "critical" if s.loss_percent >= th.loss_critical_pct else "warning" if s.loss_percent >= th.loss_warning_pct else "info" if s.loss_percent >= th.loss_info_pct else None
    if sev:
        add(sev, "RTP_PACKET_LOSS", "Perda de pacotes RTP", f"Perda estimada de {s.loss_percent:.2f}% no fluxo {s.stream_id} ({s.codec}).",
            "high", {"loss_percent": s.loss_percent, "lost": s.lost_packets, "expected": s.expected_packets, "burst_ratio": s.burst_ratio})
    sev = "critical" if s.jitter_ms >= th.jitter_critical_ms else "warning" if s.jitter_ms >= th.jitter_warning_ms else "info" if s.jitter_ms >= th.jitter_info_ms else None
    if sev:
        add(sev, "RTP_JITTER", "Jitter RTP elevado", f"Jitter RFC 3550 estimado em {s.jitter_ms:.2f} ms.", "high", {"jitter_ms": s.jitter_ms})
    if s.mos is not None and s.mos < th.mos_warning:
        add("critical" if s.mos < th.mos_critical else "warning", "LOW_MOS", "Qualidade de voz estimada baixa",
            f"MOS estimado {s.mos:.2f} (R={s.r_factor}). {s.mos_note or ''}", "medium", {"mos": s.mos, "r_factor": s.r_factor, "note": s.mos_note})
    if s.rtcp_remote_loss_pct is not None and s.rtcp_remote_loss_pct >= th.loss_warning_pct and s.rtcp_remote_loss_pct > s.loss_percent + 1:
        add("warning", "RTCP_REMOTE_LOSS", "Perda reportada pelo receptor (RTCP)",
            f"O receptor reporta {s.rtcp_remote_loss_pct:.1f}% de perda neste fluxo, acima dos {s.loss_percent:.1f}% vistos na captura: a perda acontece depois do ponto de captura.",
            "high", {"remote_loss_pct": s.rtcp_remote_loss_pct, "local_loss_pct": s.loss_percent, "remote_jitter_ms": s.rtcp_remote_jitter_ms})
    if s.gaps_over_threshold and s.comfort_noise_packets == 0:
        add("warning", "RTP_GAP", "Interrupções no fluxo de áudio",
            f"{s.gaps_over_threshold} intervalo(s) sem RTP acima de {th.rtp_gap_ms:.0f} ms (maior: {s.max_interarrival_gap_ms:.0f} ms) sem comfort noise sinalizado. "
            "O usuário percebe como áudio picotando ou mudo.", "medium", {"gaps": s.gaps_over_threshold, "max_gap_ms": s.max_interarrival_gap_ms})
    if s.unexpected_payload_types:
        add("warning", "RTP_PT_NOT_NEGOTIATED", "Payload type não negociado no SDP",
            f"O fluxo usa PT {s.unexpected_payload_types}, que não aparece no SDP da chamada. O outro lado pode descartar o áudio (mudo) ou decodificar errado.",
            "high", {"payload_types": s.unexpected_payload_types})
    if s.sdp_destination_match is False:
        add("info", "MEDIA_DEST_MISMATCH", "RTP enviado para endereço fora do SDP",
            f"O fluxo vai para {s.dst_ip}:{s.dst_port}, que não foi anunciado no SDP. Indica NAT/latching (RTP simétrico) ou SBC reescrevendo mídia.",
            "medium", {"dst": f"{s.dst_ip}:{s.dst_port}"})
    if s.packets >= 50 and s.dscp is not None and s.dscp != th.expected_rtp_dscp and not s.webrtc_session:
        add("info", "RTP_DSCP", "RTP sem marcação de QoS esperada",
            f"O fluxo está marcado como {_dscp(s.dscp)} em vez de {_dscp(th.expected_rtp_dscp)}. Sem priorização, a voz disputa fila com dados em links congestionados.",
            "high", {"dscp": s.dscp, "values": s.dscp_values})
    if s.ssrc_changes_on_flow:
        add("info", "RTP_SSRC_CHANGE", "Troca de SSRC no mesmo fluxo",
            f"{s.ssrc_changes_on_flow + 1} SSRCs no mesmo par IP/porta. Normal em transferência/re-INVITE; se inesperado, alguns equipamentos silenciam o áudio.",
            "medium", {"ssrc": s.ssrc})
    if s.out_of_order > 0:
        add("info", "RTP_REORDER", "Pacotes RTP fora de ordem", f"Foram observados {s.out_of_order} pacotes fora de ordem.", "high", {"out_of_order": s.out_of_order})
    if s.duplicates > 0:
        add("info", "RTP_DUPLICATES", "Pacotes RTP duplicados", f"Foram observados {s.duplicates} pacotes duplicados.", "high", {"duplicates": s.duplicates})
    return d


def diagnose(calls: list[SipCall], streams: list[RtpStream], th: Thresholds = DEFAULT_THRESHOLDS,
             capture_end: float | None = None, security: list[dict[str, Any]] | None = None,
             icmp_errors: list[dict[str, Any]] | None = None, registrations: list[dict[str, Any]] | None = None,
             nat: list[dict[str, Any]] | None = None, ddos: list[dict[str, Any]] | None = None,
             webrtc: list[dict[str, Any]] | None = None, lost_fragments: int = 0) -> list[Diagnostic]:
    d: list[Diagnostic] = []
    by_call: dict[str, list[RtpStream]] = defaultdict(list)
    for s in streams:
        if s.call_id: by_call[s.call_id].append(s)
    # Calls placed by an attacking source are the attack itself (already one SEC_* alert), not hundreds of call failures.
    attack_sources = {a["source_ip"] for a in security or [] if a["type"] in ("brute_force", "scanner", "enumeration", "rate", "scan")}
    flood_sources = {ip for e in ddos or [] if e["type"] == "SIP_FLOOD_DISTRIBUTED" for ip in e.get("source_ips", [])}
    for c in calls:
        if c.caller_ip in attack_sources or c.caller_ip in flood_sources:
            continue
        d.extend(_call_rules(c, by_call.get(c.call_id, []), th, capture_end))
    for s in streams:
        d.extend(_stream_rules(s, th))

    sip_dscp = defaultdict(int)
    for c in calls:
        for m in c.messages:
            # Browsers cannot mark WebSocket signalling: no actionable QoS finding there.
            if m.dscp is not None and m.dscp not in th.expected_sip_dscp and m.transport != "WS":
                sip_dscp[(m.src_ip, m.dscp)] += 1
    for (ip, value), n in sip_dscp.items():
        if n >= 5:
            d.append(Diagnostic("info", "SIP_DSCP", "Sinalização SIP sem marcação de QoS",
                                f"{n} mensagens SIP de {ip} marcadas como {_dscp(value)}. Recomenda-se CS3/AF31 para sinalização.",
                                "high", evidence={"source_ip": ip, "dscp": value, "messages": n}))

    for e in icmp_errors or []:
        sev = "critical" if e["icmp_code"] in (3, 9, 10, 13) or e["orig_protocol"] == "UDP" else "warning"
        d.append(Diagnostic(sev, "ICMP_UNREACHABLE", "Destino inalcançável (ICMP)",
                            f"{e['reporter_ip']} respondeu '{e['reason']}' {e['count']}x para {e['orig_protocol']} "
                            f"{e['orig_src_ip']}:{e['orig_src_port']} → {e['orig_dst_ip']}:{e['orig_dst_port']}. "
                            "Porta fechada, serviço parado ou ACL/firewall bloqueando.", "high", evidence=e))

    # Registration failures from a source already flagged as an attacker are the attack, not a customer fault.
    attackers = {a["source_ip"] for a in security or [] if a["type"] in ("brute_force", "scanner", "enumeration")} | flood_sources
    failed_by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in registrations or []:
        if r["source_ip"] in attackers or r["state"] not in ("failed", "no_response"):
            continue
        failed_by_src[r["source_ip"]].append(r)
    for src, regs in failed_by_src.items():
        if len(regs) > 3:
            d.append(Diagnostic("critical", "REGISTER_FAILED", "Registros SIP falhando",
                                f"{len(regs)} AORs a partir de {src} sem registro (status: "
                                f"{', '.join(sorted({str(r['last_status']) for r in regs}))}).", "high",
                                evidence={"source_ip": src, "aors": [r["aor"] for r in regs][:50]}))
            continue
        for r in regs:
            if r["state"] == "failed":
                sev = "critical" if r["credential_rejections"] else "warning"
                d.append(Diagnostic(sev, "REGISTER_FAILED", "Registro SIP falhando",
                                    f"{r['aor']} a partir de {r['source_ip']}: {r['attempts']} tentativa(s), último status {r['last_status']} {r['last_reason'] or ''}."
                                    + (" Senha recusada." if r["credential_rejections"] else ""), "high", evidence=r))
            else:
                d.append(Diagnostic("critical", "REGISTER_NO_RESPONSE", "REGISTER sem resposta",
                                    f"{r['aor']} a partir de {r['source_ip']}: {r['attempts']} REGISTER sem nenhuma resposta do registrar.",
                                    "high", evidence=r))

    for a in security or []:
        d.append(Diagnostic(a["severity"], f"SEC_{a['type'].upper()}", "Alerta de segurança SIP", a["detail"], "medium",
                            evidence={k: v for k, v in a.items() if k not in ("detail", "severity")}))

    for f in nat or []:
        d.append(Diagnostic(f["severity"], f["type"], f["title"], f["detail"], "high" if f["severity"] != "info" else "medium",
                            f.get("call_id"), None, {"source_ip": f.get("source_ip"), **f.get("evidence", {})}, "nat"))
    for e in ddos or []:
        d.append(Diagnostic(e["severity"], e["type"], e["title"], e["detail"], "medium", None, None,
                            {k: v for k, v in e.items() if k not in ("detail", "severity", "title", "type")}, "ddos"))
    for f in webrtc or []:
        d.append(Diagnostic(f["severity"], f["type"], f["title"], f["detail"], "high" if f["severity"] == "critical" else "medium",
                            f.get("call_id"), None, {"source_ip": f.get("source_ip"), "session": f.get("session"), **f.get("evidence", {})},
                            "webrtc"))
    if lost_fragments >= th.fragments_lost_warning:
        d.append(Diagnostic("warning", "IP_FRAGMENTS_LOST", "Fragmentos IP perdidos",
                            f"{lost_fragments} pacote(s) chegaram fragmentados sem todas as partes. Em SIP por UDP isso acontece com INVITE "
                            "grande (SDP com muitos codecs/candidatos) acima do MTU: se um fragmento se perde, a mensagem inteira some "
                            "e a chamada não completa. Usar SIP por TCP, reduzir o SDP ou corrigir o MTU/firewall que descarta fragmentos.",
                            "medium", evidence={"packets": lost_fragments}))
    for x in d:
        if not x.category:
            x.category = category_of(x.code)

    order = {"critical": 0, "warning": 1, "info": 2}
    d.sort(key=lambda x: (order.get(x.severity, 9), x.call_id or "", x.stream_id or ""))
    return d
