from __future__ import annotations

import ipaddress
from collections import defaultdict

from .models import Diagnostic, RtpStream, SipCall
from .sip import is_private_or_local


def _public(ip: str | None) -> bool:
    if not ip: return False
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_unspecified)
    except ValueError:
        return False


def diagnose(calls: list[SipCall], streams: list[RtpStream]) -> list[Diagnostic]:
    d: list[Diagnostic] = []
    by_call: dict[str, list[RtpStream]] = defaultdict(list)
    for s in streams:
        if s.call_id: by_call[s.call_id].append(s)

    for c in calls:
        cid = c.call_id
        if c.final_status and c.final_status >= 400:
            sev = "critical" if c.final_status >= 500 or c.final_status in (408, 480, 486, 487) else "warning"
            d.append(Diagnostic(sev, "SIP_FINAL_FAILURE", "Falha no estabelecimento SIP",
                                f"INVITE terminou em {c.final_status} {c.final_reason or ''}.".strip(), "high", cid,
                                evidence={"status": c.final_status, "reason": c.final_reason}))
        if c.missing_ack:
            d.append(Diagnostic("critical", "SIP_MISSING_ACK", "ACK não observado após 2xx do INVITE",
                                "A resposta final 2xx do INVITE foi observada, mas não apareceu ACK com o mesmo CSeq. Pode ser perda de sinalização, roteamento ou captura incompleta.",
                                "high", cid))
        if c.retransmissions >= 3:
            d.append(Diagnostic("warning", "SIP_RETRANSMISSIONS", "Retransmissões SIP elevadas",
                                f"Foram detectadas {c.retransmissions} mensagens SIP repetidas pela mesma transação.", "medium", cid,
                                evidence={"retransmissions": c.retransmissions}))
        if c.connected and not c.termination_observed:
            d.append(Diagnostic("info", "SIP_TERMINATION_NOT_SEEN", "Término da chamada não observado",
                                "A captura contém uma chamada conectada, mas não mostra BYE/CANCEL. Isso não prova falha; a captura pode ter terminado antes.", "high", cid))

        cstreams = by_call.get(cid, [])
        if c.connected and not cstreams:
            d.append(Diagnostic("critical", "NO_RTP_AFTER_ANSWER", "Sem RTP após atendimento",
                                "A chamada teve 2xx para o INVITE, porém nenhum fluxo RTP confiável foi associado. Verifique SDP, NAT, firewall e ponto de captura.", "medium", cid))
        elif c.connected and cstreams:
            direction_pairs = {(s.src_ip, s.dst_ip) for s in cstreams if s.packets >= 10}
            reverse_ok = any((b, a) in direction_pairs for a, b in direction_pairs)
            biggest = max(cstreams, key=lambda s: s.packets)
            if biggest.packets >= 20 and not reverse_ok:
                d.append(Diagnostic("critical", "ONE_WAY_AUDIO", "Áudio em apenas uma direção",
                                    "Há RTP consistente em uma direção, mas não foi encontrado fluxo reverso equivalente. Possíveis causas: NAT, SDP incorreto, ACL/firewall ou captura assimétrica.",
                                    "medium", cid, evidence={"dominant_stream": biggest.stream_id, "packets": biggest.packets}))

        # NAT evidence from SIP/SDP, without declaring private-to-private routing an error.
        for m in c.messages:
            if m.contact_host and m.src_ip and is_private_or_local(m.contact_host) and _public(m.src_ip):
                d.append(Diagnostic("info", "NAT_CONTACT_MISMATCH", "NAT detectado na sinalização",
                                    f"Contact anuncia {m.contact_host}, enquanto o pacote SIP foi observado vindo de {m.src_ip}. NAT traversal é necessário; isso não é erro por si só.",
                                    "high", cid, evidence={"contact_host":m.contact_host, "observed_source":m.src_ip}))
                break
        private_sdp = [ep for ep in c.media_endpoints if is_private_or_local(ep.get("ip"))]
        if private_sdp:
            public_signaling = any(_public(m.src_ip) or _public(m.dst_ip) for m in c.messages)
            if public_signaling:
                one_way = any(x.call_id == cid and x.code == "ONE_WAY_AUDIO" for x in d)
                d.append(Diagnostic("critical" if one_way else "warning", "PRIVATE_SDP_OVER_PUBLIC_SIGNALING",
                                    "Endereço privado anunciado no SDP",
                                    "O SDP contém endereço de mídia privado em uma chamada observada atravessando endereços públicos. Se não houver SBC/relay/ICE corrigindo a mídia, isso pode causar RTP ausente ou unidirecional.",
                                    "high" if one_way else "medium", cid, evidence={"media_ips":[ep.get("ip") for ep in private_sdp]}))

    for s in streams:
        if s.loss_percent >= 5:
            sev = "critical"
        elif s.loss_percent >= 2:
            sev = "warning"
        elif s.loss_percent >= 1:
            sev = "info"
        else:
            sev = None
        if sev:
            d.append(Diagnostic(sev, "RTP_PACKET_LOSS", "Perda de pacotes RTP",
                                f"Perda estimada de {s.loss_percent:.2f}% no fluxo {s.stream_id} ({s.codec}).",
                                "high", s.call_id, s.stream_id, {"loss_percent":s.loss_percent, "lost":s.lost_packets, "expected":s.expected_packets}))
        if s.jitter_ms >= 50:
            sev = "critical"
        elif s.jitter_ms >= 30:
            sev = "warning"
        elif s.jitter_ms >= 20:
            sev = "info"
        else:
            sev = None
        if sev:
            d.append(Diagnostic(sev, "RTP_JITTER", "Jitter RTP elevado",
                                f"Jitter RFC 3550 estimado em {s.jitter_ms:.2f} ms.", "high", s.call_id, s.stream_id,
                                {"jitter_ms":s.jitter_ms}))
        if s.mos is not None and s.mos < 3.6:
            sev = "critical" if s.mos < 3.1 else "warning"
            d.append(Diagnostic(sev, "LOW_MOS", "Qualidade de voz estimada baixa",
                                f"MOS estimado {s.mos:.2f} (R={s.r_factor}). {s.mos_note or ''}", "medium", s.call_id, s.stream_id,
                                {"mos":s.mos, "r_factor":s.r_factor, "note":s.mos_note}))
        if s.out_of_order > 0:
            d.append(Diagnostic("info", "RTP_REORDER", "Pacotes RTP fora de ordem",
                                f"Foram observados {s.out_of_order} pacotes fora de ordem.", "high", s.call_id, s.stream_id,
                                {"out_of_order":s.out_of_order}))
        if s.duplicates > 0:
            d.append(Diagnostic("info", "RTP_DUPLICATES", "Pacotes RTP duplicados",
                                f"Foram observados {s.duplicates} pacotes duplicados.", "high", s.call_id, s.stream_id,
                                {"duplicates":s.duplicates}))
    order = {"critical":0, "warning":1, "info":2}
    d.sort(key=lambda x: (order.get(x.severity, 9), x.call_id or "", x.stream_id or ""))
    return d
