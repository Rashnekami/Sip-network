"""SIP over WebSocket (RFC 7118), the signalling used by WebRTC softphones and browsers.

Only clear-text ws:// is readable. The HTTP Upgrade is found by content, not by port, since WebSocket servers run on
80, 5066, 8088, 8080 or anything else. Each TCP direction is reassembled, the frames are unmasked and every text
message that is SIP goes to the normal SIP parser with transport "WS". wss:// (TLS) stays encrypted.
"""
from __future__ import annotations

import re
import struct
from collections import defaultdict
from typing import Any

from .models import Packet

WS_CLOSE_CODES = {1000: "fechamento normal", 1001: "saindo (página fechada/servidor reiniciando)", 1002: "erro de protocolo",
                  1003: "tipo de dado não suportado", 1007: "dado inválido", 1008: "violação de política",
                  1009: "mensagem grande demais", 1010: "extensão exigida", 1011: "erro interno do servidor",
                  1012: "servidor reiniciando", 1013: "tente mais tarde", 1015: "falha de TLS"}
# Ports where TLS is very likely wss:// of a PBX/SBC (Asterisk 8089, FreeSWITCH 7443, Kamailio/OpenSIPS 4443/10443).
WSS_PORTS = {443, 4443, 7443, 8089, 8443, 10443}


def _reassemble(pkts: list[Packet]) -> tuple[bytes, list[tuple[int, int, Packet]], bool]:
    """Contiguous bytes of one TCP direction from the lowest sequence number, stopping at the first hole."""
    segs = sorted(((p.tcp_seq or 0, p) for p in pkts if p.payload and p.tcp_seq is not None), key=lambda x: (x[0], x[1].number))
    buf = bytearray(); spans: list[tuple[int, int, Packet]] = []
    next_seq = None; hole = False
    for seq, p in segs:
        if next_seq is None:
            next_seq = seq
        if seq > next_seq:
            hole = True
            break
        overlap = next_seq - seq
        if overlap >= len(p.payload):
            continue
        piece = p.payload[overlap:]
        spans.append((len(buf), len(buf) + len(piece), p))
        buf.extend(piece); next_seq += len(piece)
    return bytes(buf), spans, hole


def _anchor(spans: list[tuple[int, int, Packet]], offset: int) -> Packet | None:
    for s, e, p in spans:
        if s <= offset < e:
            return p
    return spans[-1][2] if spans else None


def _frames(data: bytes, start: int):
    """Yield (offset, fin, opcode, payload) for each complete frame; incomplete tail is ignored."""
    pos = start
    while pos + 2 <= len(data):
        b0, b1 = data[pos], data[pos + 1]
        fin, opcode, masked, length = b0 >> 7, b0 & 0x0F, b1 >> 7, b1 & 0x7F
        hdr = 2
        if length == 126:
            if pos + 4 > len(data): return
            length = struct.unpack("!H", data[pos + 2:pos + 4])[0]; hdr = 4
        elif length == 127:
            if pos + 10 > len(data): return
            length = struct.unpack("!Q", data[pos + 2:pos + 10])[0]; hdr = 10
        mask = b""
        if masked:
            if pos + hdr + 4 > len(data): return
            mask = data[pos + hdr:pos + hdr + 4]; hdr += 4
        end = pos + hdr + length
        if end > len(data) or opcode not in (0, 1, 2, 8, 9, 10):
            return
        payload = data[pos + hdr:end]
        if masked:
            payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        yield pos, fin, opcode, payload
        pos = end


def _from_first_frame(pkts: list[Packet]) -> list[Packet]:
    first = next((p for p in sorted(pkts, key=lambda x: x.number) if p.payload[:1] in (b"\x81", b"\x01", b"\x88", b"\x89", b"\x8a")), None)
    if first is None or first.tcp_seq is None:
        return []
    return [p for p in pkts if p.tcp_seq is not None and ((p.tcp_seq - first.tcp_seq) & 0xFFFFFFFF) < 0x80000000]


def _http_head(data: bytes) -> tuple[str, dict[str, str], int] | None:
    sep = data.find(b"\r\n\r\n")
    if sep < 0:
        return None
    lines = data[:sep].decode("latin-1", "replace").split("\r\n")
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return lines[0], headers, sep + 4


def analyze_websockets(packets: list[Packet]) -> dict[str, Any]:
    by_flow: dict[tuple, list[Packet]] = defaultdict(list)
    upgrades: list[tuple] = []
    for p in packets:
        if p.protocol != "TCP" or p.src_ip is None:
            continue
        by_flow[p.flow4()].append(p)
        if p.payload[:4] == b"GET " and re.search(rb"(?i)\r\nupgrade:\s*websocket", p.payload[:2048]):
            if p.flow4() not in upgrades:
                upgrades.append(p.flow4())

    # Long-lived WebSocket connections: a capture started after the HTTP Upgrade still shows SIP inside text frames.
    # Such flows are picked up from their first frame that carries SIP; masked frames identify the client side.
    midstream: dict[tuple, int] = {}
    known = set(upgrades) | {(k[1], k[0], k[3], k[2]) for k in upgrades}
    for key, pkts in by_flow.items():
        if key in known:
            continue
        for p in sorted(pkts, key=lambda x: x.number):
            if p.payload[:1] == b"\x81":
                frame = next(_frames(p.payload, 0), None)
                if frame and re.match(rb"(?:SIP/2\.0 |[A-Z]+ \S+ SIP/2\.0)", frame[3][:64]):
                    client_side = bool(p.payload[1] & 0x80)
                    ckey = key if client_side else (key[1], key[0], key[3], key[2])
                    if ckey not in upgrades:
                        upgrades.append(ckey)
                    midstream[key] = p.tcp_seq or 0
                    known.update((key, (key[1], key[0], key[3], key[2])))
                    break

    connections: list[dict[str, Any]] = []
    sip: list[tuple[str, Packet, str]] = []
    flows: set[tuple] = set()
    for key in upgrades:
        c_ip, s_ip, c_port, s_port = key
        rkey = (s_ip, c_ip, s_port, c_port)
        flows.update((key, rkey))
        up_pkts, down_pkts = by_flow.get(key, []), by_flow.get(rkey, [])
        if key in midstream or rkey in midstream:
            # Start each direction at its first WebSocket frame (payload starting with a FIN+opcode byte).
            up_pkts = _from_first_frame(up_pkts)
            down_pkts = _from_first_frame(down_pkts)
        up_data, up_spans, up_hole = _reassemble(up_pkts)
        down_data, down_spans, down_hole = _reassemble(down_pkts)
        mid = key in midstream or rkey in midstream
        req = (up_data[:0].decode(), {}, 0) if mid else _http_head(up_data)
        resp = ("HTTP/1.1 101 (conexão já aberta antes da captura)", {}, 0) if mid else _http_head(down_data)
        status = None
        if resp and resp[0].startswith("HTTP/"):
            parts = resp[0].split()
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        conn: dict[str, Any] = {
            "client": f"{c_ip}:{c_port}", "server": f"{s_ip}:{s_port}",
            "path": req[0].split()[1] if req and len(req[0].split()) > 1 else None,
            "subprotocol": (req[1].get("sec-websocket-protocol") if req else None),
            "origin": req[1].get("origin") if req else None,
            "user_agent": req[1].get("user-agent") if req else None,
            "http_status": status, "http_reason": resp[0].split(None, 2)[2] if resp and len(resp[0].split(None, 2)) > 2 else None,
            "opened_at": None if mid else (by_flow[key][0].timestamp if by_flow.get(key) else None),
            "started_before_capture": mid,
            "sip_messages": 0, "pings": 0, "close": None, "reset_by": None, "incomplete": up_hole or down_hole,
        }
        for direction, data, spans, head in (("client", up_data, up_spans, req), ("server", down_data, down_spans, resp)):
            if not head or (direction == "server" and status != 101):
                continue
            pending = bytearray(); pending_at = None
            for off, fin, opcode, payload in _frames(data, head[2]):
                if opcode in (0, 1):
                    if opcode == 1:
                        pending = bytearray(); pending_at = off
                    pending.extend(payload)
                    if fin and pending_at is not None:
                        text = pending.decode("utf-8", "replace")
                        anchor = _anchor(spans, pending_at)
                        if anchor is not None and re.match(r"(?:SIP/2\.0 |[A-Z]+ \S+ SIP/2\.0)", text):
                            sip.append((text, anchor, "WS"))
                            conn["sip_messages"] += 1
                        pending_at = None
                elif opcode == 9:
                    conn["pings"] += 1
                elif opcode == 8 and conn["close"] is None:
                    code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
                    at = _anchor(spans, off)
                    conn["close"] = {"by": direction, "code": code, "meaning": WS_CLOSE_CODES.get(code, "código não padrão") if code else "sem código",
                                     "reason": payload[2:].decode("utf-8", "replace") or None, "at": at.timestamp if at else None}
        for pk, who in ((by_flow.get(key, []), "client"), (by_flow.get(rkey, []), "server")):
            rst = next((p for p in pk if p.tcp_flags is not None and p.tcp_flags & 0x04), None)
            if rst and conn["reset_by"] is None:
                conn["reset_by"] = who; conn["reset_at"] = rst.timestamp
        connections.append(conn)

    # TLS toward typical wss:// ports: WebRTC signalling that cannot be read.
    tls_servers: dict[str, int] = defaultdict(int)
    for p in packets:
        if p.protocol == "TCP" and p.dst_port in WSS_PORTS and p.payload[:3] in (b"\x16\x03\x01", b"\x16\x03\x03") \
                and len(p.payload) > 5 and p.payload[5] == 1:
            tls_servers[f"{p.dst_ip}:{p.dst_port}"] += 1
    return {"connections": connections, "sip": sip, "flows": flows, "tls_servers": dict(tls_servers)}
