from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import replace
from typing import Iterable

from .models import Packet, SipCall, SipMessage
from .sdp import parse_sdp

SIP_METHODS = {
    "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "INFO",
    "PRACK", "UPDATE", "SUBSCRIBE", "NOTIFY", "REFER", "MESSAGE", "PUBLISH"
}
COMPACT = {"v": "via", "f": "from", "t": "to", "i": "call-id", "m": "contact", "l": "content-length", "c": "content-type"}


def _looks_like_sip(payload: bytes) -> bool:
    if not payload:
        return False
    prefix = payload[:40].lstrip()
    if prefix.startswith(b"SIP/2.0"):
        return True
    token = prefix.split(b" ", 1)[0].decode("ascii", "ignore").upper()
    return token in SIP_METHODS


def extract_sip_messages(packets: list[Packet]) -> list[SipMessage]:
    out: list[SipMessage] = []
    # UDP is message-oriented.
    for p in packets:
        if p.protocol == "UDP" and p.payload and (_looks_like_sip(p.payload) or p.src_port in (5060, 5061) or p.dst_port in (5060, 5061)):
            text = p.payload.decode("utf-8", "replace")
            for raw in _split_sip_messages(text):
                msg = parse_sip_message(raw, p)
                if msg:
                    out.append(msg)

    # TCP reassembly by directional stream. TLS/5061 remains encrypted and therefore intentionally unparsed.
    tcp_streams: dict[tuple, list[Packet]] = defaultdict(list)
    for p in packets:
        if p.protocol == "TCP" and p.payload and (p.src_port in (5060, 5061) or p.dst_port in (5060, 5061) or _looks_like_sip(p.payload)):
            tcp_streams[(p.src_ip, p.dst_ip, p.src_port, p.dst_port)].append(p)
    for stream_packets in tcp_streams.values():
        for raw, anchor in _reassemble_tcp_sip(stream_packets):
            msg = parse_sip_message(raw, anchor)
            if msg:
                out.append(msg)

    out.sort(key=lambda m: (m.timestamp, m.packet_number))
    return out


def _unwrap32(seq: int, reference: int) -> int:
    base = reference & ~0xFFFFFFFF
    candidates = [base | seq, (base - (1 << 32)) | seq, (base + (1 << 32)) | seq]
    return min(candidates, key=lambda x: abs(x - reference))


def _reassemble_tcp_sip(packets: list[Packet]) -> list[tuple[str, Packet]]:
    packets = [p for p in packets if p.tcp_seq is not None and p.payload]
    if not packets:
        return []
    packets.sort(key=lambda p: p.timestamp)
    ref = packets[0].tcp_seq or 0
    segs = []
    for p in packets:
        ext = _unwrap32(p.tcp_seq or 0, ref)
        ref = max(ref, ext)
        segs.append((ext, p.payload, p))
    segs.sort(key=lambda x: x[0])

    chunks: list[tuple[bytes, list[tuple[int, int, Packet]]]] = []
    buf = bytearray(); spans: list[tuple[int, int, Packet]] = []; next_seq = None
    for seq, payload, pkt in segs:
        if next_seq is None:
            next_seq = seq
        if seq > next_seq:
            if buf:
                chunks.append((bytes(buf), spans))
            buf = bytearray(); spans = []; next_seq = seq
        overlap = max(0, next_seq - seq)
        if overlap >= len(payload):
            continue
        piece = payload[overlap:]
        start = len(buf); buf.extend(piece); end = len(buf)
        spans.append((start, end, pkt)); next_seq += len(piece)
    if buf:
        chunks.append((bytes(buf), spans))

    results: list[tuple[str, Packet]] = []
    for data, spans in chunks:
        text = data.decode("utf-8", "replace")
        cursor = 0
        while cursor < len(text):
            start = _find_sip_start(text, cursor)
            if start < 0:
                break
            parsed = _extract_one_message(text, start)
            if not parsed:
                break
            raw, end = parsed
            # UTF-8 replacement can shift byte offsets slightly; nearest span is sufficient for timing anchor.
            anchor = spans[0][2]
            for s, e, p in spans:
                if s <= start < e:
                    anchor = p; break
            results.append((raw, anchor))
            cursor = end
    return results


def _find_sip_start(text: str, start: int) -> int:
    pattern = r"(?m)^(?:SIP/2\.0|(?:INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|INFO|PRACK|UPDATE|SUBSCRIBE|NOTIFY|REFER|MESSAGE|PUBLISH)\s+)"
    m = re.search(pattern, text[start:])
    return -1 if not m else start + m.start()


def _extract_one_message(text: str, start: int) -> tuple[str, int] | None:
    sep = text.find("\r\n\r\n", start)
    sep_len = 4
    if sep < 0:
        sep = text.find("\n\n", start); sep_len = 2
    if sep < 0:
        return None
    head = text[start:sep]
    m = re.search(r"(?im)^Content-Length\s*:\s*(\d+)\s*$", head)
    if not m:
        m = re.search(r"(?im)^l\s*:\s*(\d+)\s*$", head)
    length = int(m.group(1)) if m else 0
    end = sep + sep_len + length
    if end > len(text):
        return None
    return text[start:end], end


def _split_sip_messages(text: str) -> list[str]:
    result = []
    cursor = 0
    while cursor < len(text):
        start = _find_sip_start(text, cursor)
        if start < 0:
            break
        parsed = _extract_one_message(text, start)
        if not parsed:
            # UDP without Content-Length or with malformed length: consume remainder.
            result.append(text[start:]); break
        raw, end = parsed; result.append(raw); cursor = end
    if not result and text.strip():
        result.append(text)
    return result


def _first_header(headers: dict[str, list[str]], name: str) -> str | None:
    vals = headers.get(name.lower())
    return vals[0] if vals else None


def _extract_uri(value: str | None) -> str | None:
    if not value: return None
    m = re.search(r"<(sips?:[^>]+)>", value, re.I)
    if m: return m.group(1)
    m = re.search(r"(sips?:[^;\s,]+)", value, re.I)
    return m.group(1) if m else value.split(";", 1)[0].strip()


def _extract_tag(value: str | None) -> str | None:
    if not value: return None
    m = re.search(r"(?:^|;)\s*tag=([^;>\s]+)", value, re.I)
    return m.group(1) if m else None


def _extract_contact_host(uri: str | None) -> str | None:
    if not uri: return None
    s = re.sub(r"^sips?:", "", uri, flags=re.I)
    if "@" in s: s = s.split("@", 1)[1]
    if s.startswith("["):
        return s[1:].split("]", 1)[0]
    return s.split(";", 1)[0].rsplit(":", 1)[0] if s.count(":") == 1 else s.split(";", 1)[0]


def parse_sip_message(raw: str, p: Packet) -> SipMessage | None:
    normalized = raw.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = head.split("\n")
    if not lines: return None
    start_line = lines[0].strip()
    if not start_line: return None
    headers: dict[str, list[str]] = defaultdict(list)
    current = None
    for line in lines[1:]:
        if line.startswith((" ", "\t")) and current:
            headers[current][-1] += " " + line.strip(); continue
        if ":" not in line: continue
        name, value = line.split(":", 1)
        name = COMPACT.get(name.strip().lower(), name.strip().lower())
        headers[name].append(value.strip()); current = name

    is_request = not start_line.upper().startswith("SIP/2.0")
    method = None; status_code = None; reason = None
    if is_request:
        method = start_line.split()[0].upper() if start_line.split() else None
        if method not in SIP_METHODS:
            return None
    else:
        parts = start_line.split(None, 2)
        if len(parts) >= 2 and parts[1].isdigit(): status_code = int(parts[1])
        reason = parts[2] if len(parts) > 2 else None

    cseq_number = None; cseq_method = None
    cseq = _first_header(headers, "cseq")
    if cseq:
        m = re.match(r"\s*(\d+)\s+([A-Z]+)", cseq, re.I)
        if m: cseq_number = int(m.group(1)); cseq_method = m.group(2).upper()

    via = _first_header(headers, "via")
    via_branch = via_sent_by = via_received = via_rport = None
    if via:
        m = re.search(r"SIP/2\.0/\S+\s+([^;\s]+)", via, re.I); via_sent_by = m.group(1) if m else None
        m = re.search(r";branch=([^;\s]+)", via, re.I); via_branch = m.group(1) if m else None
        m = re.search(r";received=([^;\s]+)", via, re.I); via_received = m.group(1) if m else None
        m = re.search(r";rport(?:=([^;\s]+))?", via, re.I); via_rport = (m.group(1) or "present") if m else None

    contact_uri = _extract_uri(_first_header(headers, "contact"))
    content_type = _first_header(headers, "content-type")
    sdp = parse_sdp(body) if ("sdp" in (content_type or "").lower() or "m=" in body) else None

    return SipMessage(
        packet_number=p.number, timestamp=p.timestamp, transport=p.protocol,
        src_ip=p.src_ip, dst_ip=p.dst_ip, src_port=p.src_port, dst_port=p.dst_port,
        start_line=start_line, is_request=is_request, method=method, status_code=status_code, reason=reason,
        call_id=_first_header(headers, "call-id"), cseq_number=cseq_number, cseq_method=cseq_method,
        from_uri=_extract_uri(_first_header(headers, "from")), to_uri=_extract_uri(_first_header(headers, "to")),
        from_tag=_extract_tag(_first_header(headers, "from")), to_tag=_extract_tag(_first_header(headers, "to")),
        via_branch=via_branch, via_sent_by=via_sent_by, via_received=via_received, via_rport=via_rport,
        contact_uri=contact_uri, contact_host=_extract_contact_host(contact_uri),
        user_agent=_first_header(headers, "user-agent"), server=_first_header(headers, "server"),
        content_type=content_type, body=body, sdp=sdp, raw_headers=dict(headers)
    )


def build_calls(messages: list[SipMessage], capture_end: float | None = None) -> list[SipCall]:
    groups: dict[str, list[SipMessage]] = defaultdict(list)
    for m in messages:
        if m.call_id:
            groups[m.call_id].append(m)
    calls: list[SipCall] = []
    for call_id, msgs in groups.items():
        msgs.sort(key=lambda x: (x.timestamp, x.packet_number))
        invite = next((m for m in msgs if m.is_request and m.method == "INVITE"), None)
        invite_cseq = invite.cseq_number if invite else None
        rel = [m for m in msgs if invite_cseq is not None and m.cseq_number == invite_cseq and (m.cseq_method == "INVITE" or m.method == "ACK")]
        provisionals = [m for m in rel if not m.is_request and m.status_code and 100 <= m.status_code < 200]
        answers = [m for m in rel if not m.is_request and m.status_code and 200 <= m.status_code < 300 and m.cseq_method == "INVITE"]
        finals = [m for m in rel if not m.is_request and m.status_code and m.status_code >= 200 and m.cseq_method == "INVITE"]
        answer = answers[0] if answers else None
        ack = next((m for m in msgs if m.is_request and m.method == "ACK" and m.cseq_number == invite_cseq), None)
        term = next((m for m in msgs if m.is_request and m.method in ("BYE", "CANCEL") and (answer is None or m.timestamp >= answer.timestamp)), None)
        first180 = next((m for m in provisionals if m.status_code == 180), None)
        first183 = next((m for m in provisionals if m.status_code == 183), None)
        final = finals[-1] if finals else None

        seen = set(); retrans = 0
        for m in msgs:
            if m.is_request:
                key = (m.method, m.cseq_number, m.via_branch, m.src_ip, m.dst_ip)
            else:
                key = (m.status_code, m.cseq_number, m.cseq_method, m.via_branch, m.src_ip, m.dst_ip)
            if key in seen: retrans += 1
            else: seen.add(key)

        endpoints: list[dict] = []
        for m in msgs:
            if not m.sdp: continue
            for media in m.sdp.media:
                if media.media != "audio" or media.port <= 0: continue
                endpoints.append({
                    "ip": media.connection_ip,
                    "port": media.port,
                    "direction": media.direction,
                    "source_message": m.start_line,
                    "source_ip": m.src_ip,
                    "payload_types": media.payload_types,
                    "codecs": {pt: {"name": c.name, "clock_rate": c.clock_rate, "channels": c.channels} for pt, c in media.codecs.items()},
                    "ptime_ms": media.ptime_ms,
                    "rtcp_port": media.rtcp_port,
                    "rtcp_ip": media.rtcp_ip,
                })

        calls.append(SipCall(
            call_id=call_id,
            from_uri=invite.from_uri if invite else msgs[0].from_uri,
            to_uri=invite.to_uri if invite else msgs[0].to_uri,
            messages=msgs,
            invite_cseq=invite_cseq,
            started_at=invite.timestamp if invite else msgs[0].timestamp,
            ended_at=term.timestamp if term else (capture_end if (answer and capture_end) else msgs[-1].timestamp),
            connected_at=answer.timestamp if answer else None,
            terminated_at=term.timestamp if term else None,
            first_provisional_at=provisionals[0].timestamp if provisionals else None,
            ringing_at=first180.timestamp if first180 else None,
            early_media_at=first183.timestamp if first183 else None,
            final_status=final.status_code if final else None,
            final_reason=final.reason if final else None,
            missing_ack=bool(answer and not ack),
            termination_observed=term is not None,
            retransmissions=retrans,
            media_endpoints=endpoints,
        ))
    calls.sort(key=lambda c: c.started_at)
    return calls


def is_private_or_local(host: str | None) -> bool:
    if not host: return False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False
