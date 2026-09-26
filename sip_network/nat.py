"""NAT troubleshooting: who is behind NAT, whether the network compensates for it, and what breaks when it does not.

Every finding carries the evidence a NOC technician needs to act (addresses seen in the packet vs. written in SIP/SDP).
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any

from .config import DEFAULT_THRESHOLDS, Thresholds
from .models import RtpStream, SipCall, SipMessage

CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _ip(value: str | None):
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


def is_private(value: str | None) -> bool:
    ip = _ip(value)
    return bool(ip) and (ip.is_private or ip.is_loopback or ip.is_link_local or (ip.version == 4 and ip in CGNAT))


def is_public(value: str | None) -> bool:
    ip = _ip(value)
    return bool(ip) and ip.is_global and not (ip.version == 4 and ip in CGNAT)


def _host(sent_by: str | None) -> str | None:
    if not sent_by:
        return None
    if sent_by.startswith("["):
        return sent_by[1:].split("]", 1)[0]
    return sent_by.rsplit(":", 1)[0] if sent_by.count(":") == 1 else sent_by


def _finding(sev: str, kind: str, title: str, detail: str, source_ip: str | None, call_id: str | None = None,
             **evidence: Any) -> dict[str, Any]:
    return {"severity": sev, "type": kind, "title": title, "detail": detail, "source_ip": source_ip,
            "call_id": call_id, "evidence": evidence}


def _behind_nat(m: SipMessage) -> bool:
    """The sender wrote a private address in Via/Contact but the packet arrived from another address."""
    via_host = _host(m.via_sent_by)
    for written in (via_host, m.contact_host):
        if written and _ip(written) and written != m.src_ip and is_private(written):
            return True
    return False


def analyze_nat(messages: list[SipMessage], calls: list[SipCall], streams: list[RtpStream],
                th: Thresholds = DEFAULT_THRESHOLDS) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    # 1. Devices behind NAT, per source, from requests they send.
    devices: dict[str, dict[str, Any]] = {}
    for m in messages:
        if not m.is_request or not m.src_ip or not _behind_nat(m):
            continue
        d = devices.setdefault(m.src_ip, {"private": set(), "rport": False, "transport": m.transport, "ua": m.user_agent,
                                          "register_expires": [], "count": 0})
        d["count"] += 1
        for written in (_host(m.via_sent_by), m.contact_host):
            if written and is_private(written):
                d["private"].add(written)
        if m.via_rport:
            d["rport"] = True
        if m.method == "REGISTER":
            v = m.header("expires")
            mm = re.search(r";\s*expires\s*=\s*(\d+)", m.header("contact") or "", re.I)
            exp = int(mm.group(1)) if mm else (int(v) if v and v.strip().isdigit() else None)
            if exp:
                d["register_expires"].append(exp)
    for src, d in devices.items():
        private = sorted(d["private"])
        cgnat = _ip(src) is not None and _ip(src).version == 4 and _ip(src) in CGNAT
        out.append(_finding("info", "DEVICE_BEHIND_NAT", "Dispositivo atrás de NAT",
                            f"{src} escreve {', '.join(private)} no Via/Contact: o aparelho ({d['ua'] or 'UA desconhecido'}) está atrás de NAT"
                            + (" com CGNAT da operadora (100.64.0.0/10), o que dificulta receber chamadas." if cgnat else "."),
                            src, private_addresses=private, messages=d["count"], cgnat=cgnat))
        if not d["rport"] and d["transport"] == "UDP":
            out.append(_finding("warning", "NAT_NO_RPORT", "Dispositivo atrás de NAT sem rport",
                                f"{src} não pede ;rport no Via. As respostas podem ir para o endereço privado e se perder: "
                                "ative rport/NAT keepalive no aparelho ou force_rport no servidor.", src))
        long_exp = [e for e in d["register_expires"] if e > th.nat_register_expires_s]
        if long_exp and d["transport"] == "UDP":
            out.append(_finding("warning", "NAT_REGISTER_EXPIRES_TOO_LONG", "Registro longo demais para o NAT",
                                f"{src} registra com expires={max(long_exp)}s por UDP atrás de NAT. Roteadores costumam fechar a porta UDP "
                                f"em 30–120s: as chamadas de entrada falham até o próximo registro. Use expires ≤ {th.nat_register_expires_s}s "
                                "ou keepalive (OPTIONS/CRLF) a cada 20–30s.", src, expires=max(long_exp)))

    # 2. SIP ALG signatures (router rewriting SIP).
    alg_seen: set[str] = set()
    for m in messages:
        src = m.src_ip or "?"
        if m.content_length_declared is not None and m.body_bytes_actual is not None \
                and m.content_length_declared != m.body_bytes_actual and src not in alg_seen:
            alg_seen.add(src)
            out.append(_finding("critical", "SIP_ALG_CONTENT_LENGTH", "SIP ALG reescrevendo mensagens",
                                f"Mensagem de {src} declara Content-Length {m.content_length_declared} mas carrega {m.body_bytes_actual} bytes. "
                                "É a assinatura clássica de SIP ALG no roteador reescrevendo o SDP. Desative o SIP ALG (\"SIP Helper\"/\"SIP Passthrough\").",
                                src, m.call_id, declared=m.content_length_declared, actual=m.body_bytes_actual, message=m.start_line))
        if m.sdp and m.sdp.origin_ip and src not in alg_seen:
            conn = m.sdp.connection_ip or next((x.connection_ip for x in m.sdp.media if x.connection_ip), None)
            if conn and is_private(m.sdp.origin_ip) and is_public(conn) and conn == m.src_ip:
                alg_seen.add(src)
                out.append(_finding("warning", "SIP_ALG_SDP_REWRITE", "SDP reescrito no caminho (provável SIP ALG)",
                                    f"O SDP de {src} tem o= com {m.sdp.origin_ip} (privado) mas c= com {conn} (o IP público do próprio pacote). "
                                    "Só um ALG/NAT no caminho troca um sem o outro. Se houver áudio mudo ou chamadas caindo, desative o SIP ALG.",
                                    src, m.call_id, origin_ip=m.sdp.origin_ip, connection_ip=conn))

    # 3. Media: private SDP across public signalling, and RTP arriving from somewhere else (latching needed).
    by_call: dict[str, list[RtpStream]] = defaultdict(list)
    for s in streams:
        if s.call_id:
            by_call[s.call_id].append(s)
    for c in calls:
        cid = c.call_id
        public_sig = any(is_public(m.src_ip) or is_public(m.dst_ip) for m in c.messages)
        private_eps = [ep for ep in c.media_endpoints if is_private(ep.get("ip"))]
        cstreams = by_call.get(cid, [])
        directions = {(s.src_ip, s.dst_ip) for s in cstreams if s.packets >= 10}
        one_way = c.connected and bool(directions) and not any((b, a) in directions for a, b in directions)
        no_media = c.connected and not cstreams
        if private_eps and public_sig:
            broken = one_way or no_media
            out.append(_finding("critical" if broken else "warning", "NAT_PRIVATE_SDP", "IP privado no SDP numa chamada pela internet",
                                f"O SDP anuncia {', '.join(sorted({ep['ip'] for ep in private_eps}))} para mídia, mas a sinalização passa por IP público. "
                                + ("O resultado é áudio " + ("unidirecional" if one_way else "ausente") + ": o outro lado envia RTP para um endereço inalcançável. "
                                   if broken else "Se não houver SBC/media relay corrigindo, o áudio falha. ")
                                + "Correção: habilitar NAT/media latching (comedia) no SBC/PBX ou STUN/IP externo no aparelho.",
                                c.caller_ip, cid, media_ips=sorted({ep["ip"] for ep in private_eps}), one_way_audio=one_way, no_media=no_media))
        advertised = {(ep.get("ip"), ep.get("port")) for ep in c.media_endpoints}
        if len({ep.get("side") for ep in c.media_endpoints}) >= 2:
            for s in cstreams:
                if (s.src_ip, s.src_port) not in advertised and (s.dst_ip, s.dst_port) in advertised:
                    adv_same_ip = next((p for ip, p in advertised if ip == s.src_ip), None)
                    how = (f"da porta {s.src_port} em vez da {adv_same_ip} anunciada" if adv_same_ip
                           else f"de {s.src_ip}:{s.src_port}, que não aparece no SDP")
                    out.append(_finding("warning" if one_way else "info", "NAT_MEDIA_SOURCE_MISMATCH", "RTP chegando de endereço diferente do SDP",
                                        f"O fluxo {s.stream_id} chega {how}. Há NAT na mídia: o outro lado precisa responder para o endereço de "
                                        "onde o RTP chega (RTP simétrico/latching), senão o áudio fica mudo nessa direção.",
                                        s.src_ip, cid, stream=s.stream_id, observed=f"{s.src_ip}:{s.src_port}"))
                    break
        if one_way and any(_behind_nat(m) for m in c.messages):
            out.append(_finding("critical", "NAT_ONE_WAY_AUDIO", "Áudio unidirecional causado por NAT",
                                "Chamada com áudio em só uma direção e aparelho atrás de NAT. Causa mais provável: o lado de fora envia RTP para o IP "
                                "privado do SDP ou para uma porta que o NAT não abriu. Verifique SIP ALG, NAT/comedia no servidor e STUN no aparelho.",
                                c.caller_ip, cid))

    order = {"critical": 0, "warning": 1, "info": 2}
    out.sort(key=lambda f: order.get(f["severity"], 9))
    return out
