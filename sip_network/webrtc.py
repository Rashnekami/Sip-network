"""WebRTC media path analysis without encryption keys.

What a capture shows of a WebRTC call, and what this module reads from it:

- ICE connectivity checks (STUN Binding with USERNAME): which candidate pairs were tried, answered and nominated,
  credential errors (401) and role conflicts (487), and consent freshness after the call is up (RFC 7675).
- STUN gathering toward a STUN server (Binding without USERNAME): whether the client learned its public address.
- TURN (RFC 8656): Allocate challenges and failures (credentials, quota, capacity) and whether media is relayed.
- DTLS handshake (RFC 5764): ClientHello/ServerHello, retransmissions, clear-text alerts and the use_srtp extension.
- SRTP: the RTP header is not encrypted, so loss, jitter, gaps and direction are measured by rtp.py like plain RTP.
- The SDP (when SIP over WebSocket is readable): mDNS-only candidates and DTLS-SRTP vs. plain RTP mismatches.

Packets are demultiplexed on the first byte as in RFC 7983 (0-3 STUN, 20-63 DTLS, 64-79 TURN channel, 128-191 RTP).
"""
from __future__ import annotations

import ipaddress
import struct
from collections import defaultdict
from dataclasses import replace
from typing import Any

from .config import DEFAULT_THRESHOLDS, Thresholds
from .models import Packet, RtpStream, SipCall

MAGIC = 0x2112A442
BINDING, ALLOCATE, REFRESH, SEND, DATA, CREATE_PERMISSION, CHANNEL_BIND = 1, 3, 4, 6, 7, 8, 9
TURN_METHODS = {ALLOCATE: "Allocate", REFRESH: "Refresh", CREATE_PERMISSION: "CreatePermission", CHANNEL_BIND: "ChannelBind"}
STUN_ERRORS = {400: "requisição inválida", 401: "não autorizado", 403: "proibido", 420: "atributo desconhecido",
               437: "alocação não confere", 438: "nonce expirado", 441: "credencial errada", 442: "transporte não suportado",
               486: "cota de alocações atingida", 487: "conflito de papel ICE", 500: "erro do servidor", 508: "servidor TURN sem capacidade"}
DTLS_ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure", 42: "bad_certificate",
               43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
               47: "illegal_parameter", 48: "unknown_ca", 51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
               80: "internal_error", 110: "unsupported_extension"}
STUN_PORTS = {3478, 3479, 19302, 19305, 5349}


def _xor_address(value: bytes) -> str | None:
    if len(value) < 8:
        return None
    family = value[1]
    port = struct.unpack("!H", value[2:4])[0] ^ (MAGIC >> 16)
    if family == 1:
        ip = ipaddress.IPv4Address(struct.unpack("!I", value[4:8])[0] ^ MAGIC)
        return f"{ip}:{port}"
    return None


def parse_stun(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 20 or payload[0] & 0xC0:
        return None
    mtype, length, cookie = struct.unpack("!HHI", payload[:8])
    if cookie != MAGIC or 20 + length > len(payload):
        return None
    method = (mtype & 0x000F) | ((mtype & 0x00E0) >> 1) | ((mtype & 0x3E00) >> 2)
    cls = ((mtype & 0x0010) >> 4) | ((mtype & 0x0100) >> 7)
    attrs: dict[int, bytes] = {}
    pos = 20
    while pos + 4 <= 20 + length:
        at, al = struct.unpack("!HH", payload[pos:pos + 4])
        attrs.setdefault(at, payload[pos + 4:pos + 4 + al])
        pos += 4 + ((al + 3) & ~3)
    err = None
    if 0x0009 in attrs and len(attrs[0x0009]) >= 4:
        v = attrs[0x0009]
        err = (v[2] & 0x07) * 100 + v[3]
    return {
        "method": method, "cls": ("request", "indication", "success", "error")[cls], "txid": payload[8:20], "error": err,
        "username": attrs[0x0006].decode("utf-8", "replace") if 0x0006 in attrs else None,
        "integrity": 0x0008 in attrs, "use_candidate": 0x0025 in attrs,
        "controlling": 0x802A in attrs, "controlled": 0x8029 in attrs,
        "mapped": _xor_address(attrs[0x0020]) if 0x0020 in attrs else None,
        "relayed": _xor_address(attrs[0x0016]) if 0x0016 in attrs else None,
        "data": attrs.get(0x0013),
        "software": attrs[0x8022].decode("utf-8", "replace") if 0x8022 in attrs else None,
    }


def parse_dtls(payload: bytes) -> list[dict[str, Any]] | None:
    if len(payload) < 13 or not 20 <= payload[0] <= 63 or payload[1] != 0xFE:
        return None
    records = []
    pos = 0
    while pos + 13 <= len(payload):
        ctype = payload[pos]
        epoch = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
        length = struct.unpack("!H", payload[pos + 11:pos + 13])[0]
        body = payload[pos + 13:pos + 13 + length]
        rec: dict[str, Any] = {"type": ctype, "epoch": epoch}
        if ctype == 22 and epoch == 0 and len(body) >= 12:
            rec["handshake"] = body[0]
            if body[0] == 1:
                rec["use_srtp"] = _client_hello_has_use_srtp(body[12:])
        elif ctype == 21 and epoch == 0 and len(body) >= 2:
            rec["alert"] = (body[0], body[1])
        records.append(rec)
        pos += 13 + length
    return records or None


def _client_hello_has_use_srtp(ch: bytes) -> bool | None:
    try:
        pos = 2 + 32
        pos += 1 + ch[pos]                                   # session id
        pos += 1 + ch[pos]                                   # cookie
        pos += 2 + struct.unpack("!H", ch[pos:pos + 2])[0]   # cipher suites
        pos += 1 + ch[pos]                                   # compression
        end = pos + 2 + struct.unpack("!H", ch[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= min(end, len(ch)):
            et, el = struct.unpack("!HH", ch[pos:pos + 4])
            if et == 14:
                return True
            pos += 4 + el
        return False
    except (IndexError, struct.error):
        return None


def _channel_data(payload: bytes) -> bytes | None:
    if len(payload) < 4 or not 64 <= payload[0] <= 79:
        return None
    length = struct.unpack("!H", payload[2:4])[0]
    return payload[4:4 + length] if 4 + length <= len(payload) else None


def unwrap_turn(packets: list[Packet]) -> list[Packet]:
    """Media relayed through TURN travels inside ChannelData or Send/Data indications; expose the inner payload
    (RTP, STUN, DTLS) so the rest of the engine measures it. Addresses stay client <-> TURN server."""
    out = []
    for p in packets:
        if p.protocol == "UDP" and p.payload:
            inner = _channel_data(p.payload)
            if inner is None and p.payload[0] < 4:
                st = parse_stun(p.payload)
                if st and st["cls"] == "indication" and st["method"] in (SEND, DATA) and st["data"]:
                    inner = st["data"]
            if inner is not None:
                p = replace(p, payload=inner, parse_notes=p.parse_notes + ("mídia dentro de TURN",))
        out.append(p)
    return out


def _ep(ip: str | None, port: int | None) -> str:
    return f"[{ip}]:{port}" if ip and ":" in ip else f"{ip}:{port}"


def scan(packets: list[Packet]) -> dict[str, Any]:
    """First pass over (TURN-unwrapped) packets: STUN/TURN transactions and DTLS records per UDP pair."""
    requests: dict[bytes, dict[str, Any]] = {}
    responses: dict[bytes, dict[str, Any]] = {}
    pairs: dict[frozenset, dict[str, Any]] = {}
    for p in packets:
        if p.protocol != "UDP" or not p.payload or p.src_port is None:
            continue
        b0 = p.payload[0]
        if b0 >= 128 or 4 <= b0 < 20 or b0 > 79:
            continue
        src, dst = _ep(p.src_ip, p.src_port), _ep(p.dst_ip, p.dst_port)
        key = frozenset((src, dst))

        def pair() -> dict[str, Any]:
            return pairs.setdefault(key, {"a": src, "b": dst, "relayed": False, "dtls": defaultdict(list), "first_at": p.timestamp})

        if "mídia dentro de TURN" in p.parse_notes:
            pair()["relayed"] = True
        if b0 < 4:
            st = parse_stun(p.payload)
            if not st:
                continue
            st.update(at=p.timestamp, src=src, dst=dst, number=p.number)
            if st["cls"] == "request":
                if st["txid"] not in requests:
                    st["copies"] = 1
                    requests[st["txid"]] = st
                else:
                    requests[st["txid"]]["copies"] += 1
            elif st["cls"] in ("success", "error"):
                responses.setdefault(st["txid"], st)
            elif st["method"] in (SEND, DATA):
                pair()["relayed"] = True
        elif 20 <= b0 <= 63:
            recs = parse_dtls(p.payload)
            if recs:
                for r in recs:
                    pair()["dtls"][src].append({**r, "at": p.timestamp})
    return {"requests": requests, "responses": responses, "pairs": pairs}


def secure_pairs(state: dict[str, Any]) -> set[frozenset]:
    """UDP pairs whose RTP is SRTP: DTLS was seen on them or ICE checks ran on them."""
    out = {k for k, v in state["pairs"].items() if v["dtls"]}
    for r in state["requests"].values():
        if r["method"] == BINDING and r["username"]:
            out.add(frozenset((r["src"], r["dst"])))
    return out


def _finding(sev: str, kind: str, title: str, detail: str, source_ip: str | None = None, call_id: str | None = None,
             session: str | None = None, **evidence: Any) -> dict[str, Any]:
    return {"severity": sev, "type": kind, "title": title, "detail": detail, "source_ip": source_ip,
            "call_id": call_id, "session": session, "evidence": evidence}


def _ip_of(ep: str) -> str:
    return ep[1:].split("]", 1)[0] if ep.startswith("[") else ep.rsplit(":", 1)[0]


def _dtls_summary(pair: dict[str, Any]) -> dict[str, Any]:
    hello_by: dict[str, int] = defaultdict(int)
    server_hello = False; alerts = []; use_srtp = None; ccs_from = set(); client = None
    first_at = None; encrypted_at: dict[str, float] = {}
    for who, recs in pair["dtls"].items():
        for r in recs:
            first_at = r["at"] if first_at is None else min(first_at, r["at"])
            if r.get("handshake") == 1:
                hello_by[who] += 1; client = client or who
                if r.get("use_srtp") is not None:
                    use_srtp = r["use_srtp"] if use_srtp is None else (use_srtp or r["use_srtp"])
            elif r.get("handshake") == 2:
                server_hello = True
            if r["type"] == 20:
                ccs_from.add(who)
            if r["epoch"] > 0:
                encrypted_at[who] = min(encrypted_at.get(who, r["at"]), r["at"])
            if "alert" in r:
                alerts.append({"by": who, "level": "fatal" if r["alert"][0] == 2 else "warning",
                               "description": DTLS_ALERTS.get(r["alert"][1], str(r["alert"][1])), "at": r["at"]})
    connected = server_hello and len(ccs_from | set(encrypted_at)) >= 2
    done_at = max(encrypted_at.values()) if len(encrypted_at) >= 2 else None
    if not pair["dtls"]:
        state = "not_seen"
    elif any(a["level"] == "fatal" for a in alerts):
        state = "failed"
    elif connected:
        state = "connected"
    elif not server_hello:
        state = "no_answer"
    else:
        state = "incomplete"
    return {"state": state, "client": client, "client_hellos": sum(hello_by.values()), "server_hello": server_hello,
            "use_srtp": use_srtp, "alerts": alerts, "first_at": first_at, "done_at": done_at}


def analyze_webrtc(state: dict[str, Any], streams: list[RtpStream], calls: list[SipCall], websockets: dict[str, Any],
                   capture_end: float, th: Thresholds = DEFAULT_THRESHOLDS) -> dict[str, Any]:
    reqs, resps, pairs = state["requests"], state["responses"], state["pairs"]
    findings: list[dict[str, Any]] = []

    # --- SIP over WebSocket transport ---
    for c in websockets.get("connections", []):
        client_ip = _ip_of(c["client"])
        if c["http_status"] is not None and c["http_status"] != 101:
            findings.append(_finding("critical", "WEBRTC_WS_UPGRADE_FAILED", "Conexão WebSocket recusada",
                                     f"{c['client']} pediu WebSocket em {c['server']}{c['path'] or ''} e recebeu HTTP {c['http_status']} "
                                     f"{c['http_reason'] or ''}. O softphone web não registra nem faz chamadas. Conferir URL/caminho do WebSocket, "
                                     "o subprotocolo 'sip', o Origin permitido e o certificado (wss).", client_ip,
                                     server=c["server"], http_status=c["http_status"], origin=c["origin"]))
        close = c["close"]
        if c["http_status"] != 101:
            continue
        if (close and close["code"] not in (1000, 1001)) or (c["reset_by"] and not close):
            how = (f"fechada por {'cliente' if close['by'] == 'client' else 'servidor'} com código {close['code']} ({close['meaning']})"
                   + (f": {close['reason']}" if close.get("reason") else "")) if close else \
                f"derrubada com TCP RST pelo {'cliente' if c['reset_by'] == 'client' else 'servidor'}"
            findings.append(_finding("warning", "WEBRTC_WS_CLOSED", "Conexão SIP-WebSocket encerrada com erro",
                                     f"A conexão {c['client']} ↔ {c['server']} foi {how}. Enquanto não reconecta, o ramal web fica "
                                     "sem registro e não recebe chamadas. Ver log do servidor WebSocket e timeouts de proxy/balanceador.",
                                     client_ip, server=c["server"], close=close, reset_by=c["reset_by"]))

    # --- STUN gathering (no USERNAME) and TURN control ---
    servers: dict[tuple[str, str], dict[str, Any]] = {}
    for tx, r in reqs.items():
        if r["method"] == BINDING and r["username"]:
            continue
        s = servers.setdefault((r["src"], r["dst"]), {"client": r["src"], "server": r["dst"], "binding": 0, "binding_ok": 0,
                                                       "mapped": None, "allocate": [], "turn_ops": defaultdict(int), "software": None})
        resp = resps.get(tx)
        if r["method"] == BINDING:
            s["binding"] += 1
            if resp and resp["cls"] == "success":
                s["binding_ok"] += 1; s["mapped"] = s["mapped"] or resp["mapped"]
        elif r["method"] == ALLOCATE:
            s["allocate"].append({"at": r["at"], "credentials": r["integrity"], "copies": r["copies"],
                                  "status": None if not resp else ("ok" if resp["cls"] == "success" else resp["error"]),
                                  "relayed": resp["relayed"] if resp else None})
        elif r["method"] in TURN_METHODS:
            s["turn_ops"][TURN_METHODS[r["method"]]] += 1
        if resp and resp.get("software"):
            s["software"] = resp["software"]
    stun_servers, turn_servers = [], []
    for s in servers.values():
        client_ip = _ip_of(s["client"])
        if s["binding"]:
            stun_servers.append({"client": s["client"], "server": s["server"], "requests": s["binding"],
                                 "answered": s["binding_ok"], "public_address": s["mapped"]})
            if s["binding_ok"] == 0 and s["binding"] >= 2:
                findings.append(_finding("warning", "WEBRTC_STUN_UNREACHABLE", "Servidor STUN não respondeu",
                                         f"{s['client']} enviou {s['binding']} consultas STUN para {s['server']} sem resposta. Sem STUN o "
                                         "navegador não descobre o próprio IP público: chamadas para fora da rede local tendem a ficar sem "
                                         "áudio, a menos que haja TURN. Liberar UDP de saída para o servidor STUN (3478/19302).",
                                         client_ip, server=s["server"], requests=s["binding"]))
        if s["allocate"]:
            allocs = s["allocate"]
            ok = [a for a in allocs if a["status"] == "ok"]
            relayed_addr = next((a["relayed"] for a in ok if a["relayed"]), None)
            turn_servers.append({"client": s["client"], "server": s["server"], "allocate_requests": len(allocs),
                                 "allocated": bool(ok), "relayed_address": relayed_addr, "operations": dict(s["turn_ops"]),
                                 "software": s["software"]})
            if ok:
                continue
            failed = [a for a in allocs if isinstance(a["status"], int) and not (a["status"] == 401 and not a["credentials"])]
            if any(a["status"] in (401, 403, 441) for a in failed):
                code = next(a["status"] for a in failed if a["status"] in (401, 403, 441))
                findings.append(_finding("critical", "WEBRTC_TURN_AUTH_FAILED", "Credencial TURN recusada",
                                         f"O servidor TURN {s['server']} recusou a credencial de {s['client']} ({code} {STUN_ERRORS.get(code, '')}). "
                                         "Sem relay, clientes atrás de firewall corporativo ou 4G/CGNAT ficam sem áudio. Conferir usuário/senha "
                                         "TURN (credencial temporária expirada é comum) e o realm.", client_ip, server=s["server"], status=code))
            elif failed:
                code = failed[-1]["status"]
                findings.append(_finding("critical", "WEBRTC_TURN_ALLOCATE_FAILED", "Servidor TURN não alocou relay",
                                         f"Allocate de {s['client']} em {s['server']} falhou com {code} ({STUN_ERRORS.get(code, 'erro')}). "
                                         + ("O servidor atingiu o limite de alocações/usuários: aumentar a cota ou a capacidade do TURN."
                                            if code in (486, 508) else "Conferir configuração do servidor TURN."),
                                         client_ip, server=s["server"], status=code))
            elif all(a["status"] is None for a in allocs) and sum(a["copies"] for a in allocs) >= 2:
                findings.append(_finding("warning", "WEBRTC_TURN_UNREACHABLE", "Servidor TURN não respondeu",
                                         f"{s['client']} tentou alocar relay em {s['server']} {sum(a['copies'] for a in allocs)} vez(es) sem resposta. "
                                         "Porta UDP/TCP do TURN bloqueada ou servidor fora do ar.", client_ip, server=s["server"]))

    # --- ICE sessions (Binding with USERNAME), grouped by the ufrag pair ---
    call_by_ufrag: dict[str, str] = {}
    for c in calls:
        for ep in c.media_endpoints:
            if ep.get("ice_ufrag"):
                call_by_ufrag[ep["ice_ufrag"]] = c.call_id
    groups: dict[frozenset, list[dict[str, Any]]] = defaultdict(list)
    for tx, r in reqs.items():
        if r["method"] == BINDING and r["username"]:
            groups[frozenset(x for x in r["username"].split(":") if x)].append(r)
    by_pair_streams: dict[frozenset, list[RtpStream]] = defaultdict(list)
    for s in streams:
        by_pair_streams[frozenset((_ep(s.src_ip, s.src_port), _ep(s.dst_ip, s.dst_port)))].append(s)
    sessions: list[dict[str, Any]] = []
    session_pairs: set[frozenset] = set()
    for n, (ufrags, checks) in enumerate(sorted(groups.items(), key=lambda kv: min(r["at"] for r in kv[1])), 1):
        sid = f"WRTC-{n:03d}"
        call_id = next((call_by_ufrag[u] for u in ufrags if u in call_by_ufrag), None)
        pair_info: dict[frozenset, dict[str, Any]] = {}
        for r in sorted(checks, key=lambda x: x["at"]):
            key = frozenset((r["src"], r["dst"]))
            pi = pair_info.setdefault(key, {"pair": f"{r['src']} ↔ {r['dst']}", "checks": 0, "answered": 0, "errors": [],
                                            "nominated": False, "first_ok": None, "last_ok": None, "unanswered_after_ok": []})
            pi["checks"] += r["copies"]
            resp = resps.get(r["txid"])
            if resp and resp["cls"] == "success":
                pi["answered"] += 1
                pi["first_ok"] = pi["first_ok"] or resp["at"]
                pi["last_ok"] = resp["at"]; pi["unanswered_after_ok"] = []
                pi["nominated"] = pi["nominated"] or r["use_candidate"]
            elif resp and resp["cls"] == "error":
                pi["errors"].append(resp["error"])
            elif pi["first_ok"] is not None:
                pi["unanswered_after_ok"].append(r["at"])
        session_pairs.update(pair_info)
        ok_pairs = [k for k, v in pair_info.items() if v["answered"]]
        selected = max(ok_pairs, key=lambda k: (pair_info[k]["nominated"], sum(s.packets for s in by_pair_streams[k])), default=None)
        sel = pair_info[selected] if selected else None
        relayed = bool(selected and pairs.get(selected, {}).get("relayed"))
        dtls = _dtls_summary(pairs.get(selected or next(iter(pair_info)), {"dtls": {}}))
        media = by_pair_streams.get(selected, []) if selected else []
        if not media:
            for k in pair_info:
                media = media or by_pair_streams.get(k, [])
        for s in media:
            s.webrtc_session = sid
        dirs = {(s.src_ip, s.src_port) for s in media if s.packets >= 10}
        first_check = min(r["at"] for r in checks)
        first_media = min((s.first_packet_at for s in media if s.first_packet_at), default=None)
        last_media = max((s.last_packet_at for s in media if s.last_packet_at), default=None)
        ice_state = "connected" if sel else ("failed" if sum(v["checks"] for v in pair_info.values()) >= 3 else "checking")
        errors = sorted({e for v in pair_info.values() for e in v["errors"] if e})
        sess = {"session_id": sid, "call_id": call_id, "ufrags": sorted(ufrags), "ice_state": ice_state,
                "candidate_pairs": [dict(v, unanswered_after_ok=len(v["unanswered_after_ok"])) for v in pair_info.values()],
                "selected_pair": sel["pair"] if sel else None, "relayed": relayed, "dtls": dtls,
                "media_streams": [s.stream_id for s in media], "media_directions": len(dirs),
                "ice_errors": errors, "first_check_at": first_check,
                "connected_at": sel["first_ok"] if sel else None, "first_media_at": first_media, "last_media_at": last_media,
                "setup_ms": round((first_media - first_check) * 1000.0, 1) if first_media else None}
        sessions.append(sess)
        who = _ip_of(sorted(checks, key=lambda x: x["at"])[0]["src"])
        total_checks = sum(v["checks"] for v in pair_info.values())

        if ice_state == "failed":
            if any(e == 401 for e in errors):
                findings.append(_finding("critical", "WEBRTC_ICE_AUTH_FAILED", "Checagem ICE recusada (401)",
                                         f"As checagens ICE da sessão {sid} foram recusadas com 401: o usuário/senha ICE (ice-ufrag/ice-pwd) "
                                         "não confere com o SDP. Acontece quando um proxy/SBC altera o SDP ou o navegador reaproveita um SDP antigo.",
                                         who, call_id, sid, errors=errors))
            else:
                findings.append(_finding("critical", "WEBRTC_ICE_FAILED", "ICE falhou: nenhum caminho de mídia funcionou",
                                         f"{total_checks} checagens ICE em {len(pair_info)} par(es) de candidatos sem nenhuma resposta. A mídia "
                                         "não tem por onde passar: firewall bloqueando UDP, candidatos só privados ou falta de servidor TURN. "
                                         "Liberar UDP (ou usar TURN em TCP/TLS 443).", who, call_id, sid,
                                         pairs=[v["pair"] for v in pair_info.values()], checks=total_checks))
            continue
        if 487 in errors:
            findings.append(_finding("info", "WEBRTC_ICE_ROLE_CONFLICT", "Conflito de papel ICE (487)",
                                     "Os dois lados se declararam controlling (ou controlled). O ICE resolve sozinho trocando o papel; "
                                     "se repetir sempre, um dos lados tem ICE mal implementado.", who, call_id, sid))
        if ice_state != "connected":
            continue
        if relayed:
            findings.append(_finding("info", "WEBRTC_TURN_RELAY", "Mídia passando por servidor TURN",
                                     f"A sessão {sid} usa relay TURN ({sel['pair']}). Funciona atrás de firewall restritivo, mas soma atraso "
                                     "e consome banda do servidor TURN.", who, call_id, sid, pair=sel["pair"]))

        if dtls["state"] in ("failed", "no_answer", "incomplete"):
            fatal = [a for a in dtls["alerts"] if a["level"] == "fatal"]
            if fatal:
                a = fatal[0]
                findings.append(_finding("critical", "WEBRTC_DTLS_ALERT", "Handshake DTLS recusado",
                                         f"O {'cliente' if a['by'] == dtls['client'] else 'servidor'} DTLS ({_ip_of(a['by'])}) enviou alerta fatal "
                                         f"'{a['description']}'. Sem DTLS não há chave SRTP: a chamada conecta sem áudio. Causa comum: "
                                         "certificado/fingerprint do SDP não confere com o do DTLS (SDP alterado) ou cifra/perfil SRTP incompatível.",
                                         _ip_of(a["by"]), call_id, sid, alert=a["description"]))
            elif dtls["state"] == "no_answer" and dtls["client_hellos"] >= 2:
                findings.append(_finding("critical", "WEBRTC_DTLS_FAILED", "Handshake DTLS sem resposta",
                                         f"{_ip_of(dtls['client'])} enviou {dtls['client_hellos']} ClientHello DTLS sem ServerHello. O ICE conectou, "
                                         "mas o outro lado não negocia DTLS: gateway sem suporte a DTLS-SRTP, papel a=setup errado "
                                         "(os dois esperando) ou pacote bloqueado.", _ip_of(dtls["client"]), call_id, sid,
                                         client_hellos=dtls["client_hellos"]))
            elif dtls["state"] == "incomplete" and not media:
                findings.append(_finding("critical", "WEBRTC_DTLS_FAILED", "Handshake DTLS não terminou",
                                         f"O servidor DTLS respondeu, mas o handshake não foi concluído ({dtls['client_hellos']} ClientHello). "
                                         "Típico de MTU: os fragmentos grandes do certificado se perdem no caminho (VPN, PPPoE). Reduzir MTU "
                                         "ou checar fragmentação/ICMP.", _ip_of(dtls["client"] or who), call_id, sid,
                                         client_hellos=dtls["client_hellos"]))
            continue
        if dtls["state"] == "connected" and dtls["use_srtp"] is False and not media:
            findings.append(_finding("warning", "WEBRTC_DTLS_NO_SRTP", "DTLS sem extensão use_srtp",
                                     "O DTLS conectou sem negociar SRTP (extensão use_srtp ausente no ClientHello): só canal de dados, "
                                     "nenhuma chave para áudio/vídeo.", who, call_id, sid))
        if not media:
            if dtls["state"] == "connected" and capture_end - (dtls["done_at"] or sel["first_ok"]) >= 2.0:
                findings.append(_finding("critical", "WEBRTC_NO_MEDIA", "ICE e DTLS ok, mas nenhuma mídia SRTP",
                                         f"A sessão {sid} conectou ICE e DTLS e nenhum pacote de áudio/vídeo passou. Microfone mudo/negado no "
                                         "navegador, faixa desativada (a=inactive) ou gateway sem transcodificação.", who, call_id, sid))
            continue
        if len(dirs) == 1:
            s0 = max(media, key=lambda s: s.packets)
            findings.append(_finding("critical", "WEBRTC_ONE_WAY_MEDIA", "Mídia WebRTC em só uma direção",
                                     f"Só {s0.src_ip}:{s0.src_port} envia SRTP no par {sel['pair']}. O outro lado não transmite: microfone "
                                     "negado/mudo, SDP recvonly ou falha de SRTP (chave errada faz o receptor descartar e não responder).",
                                     s0.src_ip, call_id, sid, sender=f"{s0.src_ip}:{s0.src_port}"))
        if sess["setup_ms"] is not None and sess["setup_ms"] >= th.webrtc_setup_warning_ms:
            findings.append(_finding("warning", "WEBRTC_SLOW_SETUP", "Mídia WebRTC demorou a começar",
                                     f"{sess['setup_ms'] / 1000:.1f}s entre a primeira checagem ICE e o primeiro áudio. O usuário atende e "
                                     "não ouve nada no início. Muitos candidatos inúteis (VPN, IPv6 quebrado) ou TURN lento.",
                                     who, call_id, sid, setup_ms=sess["setup_ms"]))
        lost = sel["unanswered_after_ok"]
        if len(lost) >= th.webrtc_consent_lost_checks and lost[-1] - lost[0] >= 4.0:
            media_stopped = any(s.packets >= 10 and s.last_packet_at and capture_end - s.last_packet_at >= 2.0
                                and s.last_packet_at <= lost[-1] for s in media)
            findings.append(_finding("critical" if media_stopped else "warning", "WEBRTC_CONSENT_LOST", "Caminho de mídia caiu no meio da chamada",
                                     f"Depois de conectar, {len(lost)} checagens de consentimento ICE ficaram sem resposta por "
                                     f"{lost[-1] - lost[0]:.0f}s" + (" e a mídia parou" if media_stopped else "")
                                     + ". O caminho de rede quebrou (troca de Wi-Fi/4G, NAT que expirou, firewall). O navegador encerra a "
                                     "mídia após ~30s sem consentimento.", who, call_id, sid, unanswered=len(lost), media_stopped=media_stopped))

    # --- SDP checks on calls that use WebRTC ---
    for c in calls:
        eps = [ep for ep in c.media_endpoints if not ep.get("from_candidate")]
        webrtc_sides = {ep["side"] for ep in eps if ep.get("fingerprint") or "SAVPF" in (ep.get("proto") or "").upper()}
        if not webrtc_sides:
            continue
        plain_sides = {ep["side"] for ep in eps if "/TLS/" not in (ep.get("proto") or "").upper() and not ep.get("fingerprint")} - webrtc_sides
        if plain_sides:
            findings.append(_finding("critical", "WEBRTC_SDP_PROFILE_MISMATCH", "Um lado é WebRTC (DTLS-SRTP) e o outro RTP comum",
                                     f"O {'originador' if 'caller' in webrtc_sides else 'destino'} fala WebRTC (UDP/TLS/RTP/SAVPF com fingerprint) "
                                     f"e o {'destino' if 'caller' in webrtc_sides else 'originador'} respondeu com RTP comum. O navegador exige "
                                     "DTLS-SRTP e ICE: a chamada fica sem áudio ou cai. Habilitar WebRTC no ramal/tronco do PBX "
                                     "(Asterisk: webrtc=yes; FreeSWITCH: perfil com DTLS) ou colocar um SBC/media gateway no meio.",
                                     c.caller_ip, c.call_id, None, webrtc_side=sorted(webrtc_sides), plain_side=sorted(plain_sides)))
        for side in webrtc_sides:
            cands = [cd for ep in eps if ep["side"] == side for cd in ep.get("candidates", [])]
            if not cands:
                continue
            public = [cd for cd in cands if cd["type"] in ("srflx", "prflx", "relay")
                      or (not cd["mdns"] and _is_public(cd["address"]))]
            if public:
                continue
            mdns = all(cd["mdns"] for cd in cands if cd["type"] == "host")
            cstreams = [s for s in streams if s.call_id == c.call_id]
            broken = c.connected and len({(s.src_ip, s.dst_ip) for s in cstreams if s.packets >= 10}) < 2
            findings.append(_finding("critical" if broken else "warning", "WEBRTC_NO_PUBLIC_CANDIDATE",
                                     "SDP WebRTC sem candidato alcançável de fora" + (" (só mDNS .local)" if mdns else ""),
                                     f"O SDP do {'originador' if side == 'caller' else 'destino'} só traz candidatos "
                                     + ("mDNS (.local), que o PBX/SBC não consegue resolver" if mdns else "de IP privado")
                                     + ", sem srflx (STUN) nem relay (TURN). Fora da mesma rede local o áudio não chega"
                                     + (" — é o que aconteceu nesta chamada." if broken else ".")
                                     + " Configurar servidor STUN/TURN no cliente WebRTC.", c.caller_ip, c.call_id, None,
                                     candidates=[f"{cd['type']} {cd['address']}:{cd['port']}" for cd in cands][:10]))

    # WSS: signalling encrypted, so calls are invisible; say so when WebRTC media exists.
    if websockets.get("tls_servers") and not any(c["sip_messages"] for c in websockets.get("connections", [])) and sessions:
        findings.append(_finding("info", "WEBRTC_WSS_ENCRYPTED", "Sinalização WebRTC criptografada (WSS)",
                                 f"A sinalização SIP vai por WebSocket seguro ({', '.join(sorted(websockets['tls_servers']))}) e não pode ser lida "
                                 "sem as chaves TLS: chamadas e códigos SIP não aparecem. ICE, DTLS e a qualidade do SRTP são analisados normalmente.",
                                 None, None, None, servers=sorted(websockets["tls_servers"])))

    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    ws_out = [{k: v for k, v in c.items()} for c in websockets.get("connections", [])]
    return {"sessions": sessions, "findings": findings, "websocket": ws_out, "stun_servers": stun_servers,
            "turn_servers": turn_servers, "wss_servers": websockets.get("tls_servers", {})}


def _is_public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_global
