from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from .models import Packet, SipCall, SipMessage
from .q850 import SIP_TO_Q850, cause_text, parse_reason
from .sdp import parse_sdp

SIP_METHODS = {
    "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "INFO",
    "PRACK", "UPDATE", "SUBSCRIBE", "NOTIFY", "REFER", "MESSAGE", "PUBLISH"
}
COMPACT = {"v": "via", "f": "from", "t": "to", "i": "call-id", "m": "contact", "l": "content-length", "c": "content-type",
           "e": "content-encoding", "k": "supported", "s": "subject", "r": "refer-to", "b": "referred-by", "x": "session-expires", "o": "event", "u": "allow-events"}


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
            raws = _split_sip_messages(text)
            for raw in raws:
                msg = parse_sip_message(raw, p)
                if msg:
                    if len(raws) == 1:
                        _measure_body(msg, p.payload)
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


def _measure_body(msg: SipMessage, payload: bytes) -> None:
    cl = msg.header("content-length")
    if cl is None or not cl.strip().isdigit():
        return
    sep = payload.find(b"\r\n\r\n")
    if sep < 0:
        return
    msg.content_length_declared = int(cl.strip())
    msg.body_bytes_actual = len(payload) - sep - 4


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
        content_type=content_type, body=body, sdp=sdp, raw_headers=dict(headers), dscp=p.dscp
    )


OUTCOME_BY_STATUS = {
    486: "busy", 600: "busy",
    480: "no_answer", 408: "timeout",
    404: "not_found", 484: "not_found", 604: "not_found", 410: "not_found",
    401: "auth_failed", 407: "auth_failed",
    403: "rejected", 603: "rejected",
    488: "media_negotiation_failed", 606: "media_negotiation_failed", 415: "media_negotiation_failed",
    487: "cancelled",
}


def classify_outcome(status: int | None, connected: bool, cancelled: bool, any_response: bool) -> str:
    if connected:
        return "answered"
    if not any_response:
        return "no_response"
    if status is None:
        return "cancelled" if cancelled else "in_progress"
    if cancelled and status in (487, 200):
        return "cancelled"
    if status in OUTCOME_BY_STATUS:
        return OUTCOME_BY_STATUS[status]
    if 300 <= status < 400:
        return "redirected"
    if 500 <= status < 600:
        return "server_error"
    if 400 <= status < 500:
        return "client_error"
    if status >= 600:
        return "global_failure"
    return "unknown"


def _is_hold(media) -> str | None:
    if media.direction in ("sendonly", "inactive"):
        return media.direction
    if media.connection_ip in ("0.0.0.0", "::"):
        return "c=0.0.0.0"
    return None


def _sender_side(m: SipMessage, caller_tag: str | None) -> str:
    """Which party sent this message: requests carry the sender's tag in From,
    responses echo the From of the request they answer."""
    from_caller = m.from_tag == caller_tag
    return "caller" if from_caller == m.is_request else "callee"


def _ms(a: float | None, b: float | None) -> float | None:
    if a is None or b is None:
        return None
    return round((b - a) * 1000.0, 1)


def _session_expires(msgs: list[SipMessage]) -> int | None:
    for m in msgs:
        v = m.header("session-expires")
        if v:
            mm = re.match(r"\s*(\d+)", v)
            if mm:
                return int(mm.group(1))
    return None


def build_calls(messages: list[SipMessage], capture_end: float | None = None) -> list[SipCall]:
    """Group SIP messages into calls (one per Call-ID that carries an INVITE).

    Inside a call, the RFC 3261 dialog model is kept: every remote tag that
    answered the initial INVITE is its own dialog, so forked answers, ACKs and
    in-dialog requests (re-INVITE, UPDATE, REFER, BYE) are matched per dialog.
    Digest challenges (401/407) followed by a new INVITE are treated as part
    of the same call attempt, not as its final result.
    """
    groups: dict[str, list[SipMessage]] = defaultdict(list)
    for m in messages:
        if m.call_id:
            groups[m.call_id].append(m)
    calls: list[SipCall] = []
    for call_id, msgs in groups.items():
        msgs.sort(key=lambda x: (x.timestamp, x.packet_number))
        initial_invites = [m for m in msgs if m.is_request and m.method == "INVITE" and not m.to_tag]
        if not initial_invites:
            # REGISTER/OPTIONS/SUBSCRIBE/MESSAGE transactions are reported by registrations/KPIs, not as calls.
            continue
        invite = initial_invites[0]
        caller_tag = invite.from_tag
        initial_cseqs = sorted({m.cseq_number for m in initial_invites if m.cseq_number is not None})
        last_cseq = initial_cseqs[-1] if initial_cseqs else invite.cseq_number
        invite_responses = [m for m in msgs if not m.is_request and m.cseq_method == "INVITE" and m.cseq_number in initial_cseqs]

        auth_challenges = sum(1 for m in invite_responses if m.status_code in (401, 407) and m.cseq_number != last_cseq)
        # The last challenged INVITE with no retry keeps its 401/407 as the final result.
        rel = [m for m in invite_responses if m.cseq_number == last_cseq]
        provisionals_all = [m for m in invite_responses if m.status_code and 100 <= m.status_code < 200]
        trying = next((m for m in provisionals_all if m.status_code == 100), None)
        progress = [m for m in provisionals_all if m.status_code > 100]
        first180 = next((m for m in progress if m.status_code == 180), None)
        first183 = next((m for m in progress if m.status_code == 183), None)
        answers = [m for m in rel if m.status_code and 200 <= m.status_code < 300]
        finals = [m for m in rel if m.status_code and m.status_code >= 200]
        answer = answers[0] if answers else None
        final = answer or (finals[-1] if finals else None)

        # Dialogs: one per remote tag seen on a 101-299 response to the initial INVITE.
        dialogs: dict[str, dict] = {}
        for m in invite_responses:
            if not m.to_tag or not m.status_code or not (101 <= m.status_code < 300):
                continue
            d = dialogs.setdefault(m.to_tag, {
                "remote_tag": m.to_tag, "first_response_at": m.timestamp, "state": "early",
                "answered_at": None, "ack_at": None, "cseq": m.cseq_number,
                "remote_contact": m.contact_uri, "remote_user_agent": m.server or m.user_agent,
                "remote_ip": m.src_ip,
            })
            if 200 <= m.status_code < 300 and d["answered_at"] is None:
                d["state"] = "confirmed"; d["answered_at"] = m.timestamp; d["cseq"] = m.cseq_number
        acks = [m for m in msgs if m.is_request and m.method == "ACK"]
        for d in dialogs.values():
            if d["state"] != "confirmed":
                continue
            ack = next((a for a in acks if a.cseq_number == d["cseq"] and a.timestamp >= d["answered_at"] and (a.to_tag == d["remote_tag"] or not a.to_tag)), None)
            if ack:
                d["ack_at"] = ack.timestamp
        confirmed = [d for d in dialogs.values() if d["state"] == "confirmed"]
        # 2xx without to-tag is malformed but happens; fall back to CSeq-only ACK matching.
        if answer and not confirmed:
            ack = next((a for a in acks if a.cseq_number == answer.cseq_number and a.timestamp >= answer.timestamp), None)
            missing_ack_dialogs = [] if ack else ["(sem tag)"]
        else:
            missing_ack_dialogs = [d["remote_tag"] for d in confirmed if d["ack_at"] is None]
        main_tag = answer.to_tag if answer else None

        def in_main_dialog(m: SipMessage) -> bool:
            if not main_tag:
                return True
            return main_tag in (m.from_tag, m.to_tag)

        cancel = next((m for m in msgs if m.is_request and m.method == "CANCEL"), None)
        bye = next((m for m in msgs if m.is_request and m.method == "BYE" and answer and m.timestamp >= answer.timestamp and in_main_dialog(m)), None)
        if bye is None and answer:
            bye = next((m for m in msgs if m.is_request and m.method == "BYE" and m.timestamp >= answer.timestamp), None)
        term = bye or (cancel if not answer else None)

        disconnect_side = disconnect_method = None
        reason_src = None
        if term is not None:
            disconnect_method = term.method
            disconnect_side = "caller" if term.from_tag == caller_tag else "callee"
            reason_src = term
        elif final is not None and final.status_code >= 300:
            disconnect_method = f"{final.status_code}"
            disconnect_side = "callee"
            reason_src = final
        reason_header = reason_src.header("reason") if reason_src else None
        q850, _q_text = parse_reason(reason_header)
        if q850 is None and final is not None and final.status_code >= 300:
            q850 = SIP_TO_Q850.get(final.status_code)
        if q850 is None and term is not None and term.method == "BYE":
            q850 = 16

        # In-dialog activity: re-INVITE/UPDATE (hold/resume), REFER (transfer).
        reinvite_cseqs = set(); hold_events: list[dict] = []; transfers: list[dict] = []
        held = False
        for m in msgs:
            if not m.is_request or not m.to_tag:
                continue
            side = _sender_side(m, caller_tag)
            if m.method == "INVITE":
                reinvite_cseqs.add((m.from_tag, m.cseq_number))
            if m.method in ("INVITE", "UPDATE") and m.sdp:
                audio = [x for x in m.sdp.media if x.media == "audio"]
                kind = next((k for k in (_is_hold(x) for x in audio) if k), None)
                if kind and not held:
                    held = True
                    hold_events.append({"at": m.timestamp, "event": "hold", "by": side, "method": m.method, "how": kind})
                elif not kind and held and audio:
                    held = False
                    hold_events.append({"at": m.timestamp, "event": "resume", "by": side, "method": m.method})
            if m.method == "REFER":
                resp = next((r for r in msgs if not r.is_request and r.cseq_method == "REFER" and r.cseq_number == m.cseq_number and r.status_code and r.status_code >= 200), None)
                if not any(t["cseq"] == m.cseq_number and t["by"] == side for t in transfers):
                    transfers.append({"at": m.timestamp, "by": side, "cseq": m.cseq_number, "refer_to": m.header("refer-to"),
                                      "referred_by": m.header("referred-by"), "status": resp.status_code if resp else None})

        seen = set(); retrans = 0
        for m in msgs:
            if m.is_request:
                key = (m.method, m.cseq_number, m.via_branch, m.src_ip, m.dst_ip)
            else:
                key = (m.status_code, m.cseq_number, m.cseq_method, m.via_branch, m.src_ip, m.dst_ip, m.to_tag)
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
                    "side": _sender_side(m, caller_tag),
                    "at": m.timestamp,
                    "payload_types": media.payload_types,
                    "codecs": {pt: {"name": c.name, "clock_rate": c.clock_rate, "channels": c.channels} for pt, c in media.codecs.items()},
                    "ptime_ms": media.ptime_ms,
                    "rtcp_port": media.rtcp_port,
                    "rtcp_ip": media.rtcp_ip,
                })

        negotiated: list[str] = []
        answer_sdp = next((m.sdp for m in msgs if not m.is_request and m.sdp and m.cseq_method == "INVITE" and m.cseq_number in initial_cseqs), None)
        if answer_sdp:
            audio = next((x for x in answer_sdp.media if x.media == "audio" and x.port > 0), None)
            if audio:
                negotiated = [audio.codecs[pt].name if pt in audio.codecs else f"PT{pt}" for pt in audio.payload_types]

        callee_msg = answer or final or (progress[0] if progress else None)
        any_response = bool(invite_responses)
        started = invite.timestamp
        first_progress_or_final = next((m for m in invite_responses if m.status_code and m.status_code > 100), None)
        if answer:
            end_ts = term.timestamp if term else (capture_end or msgs[-1].timestamp)
            duration = round(max(0.0, end_ts - answer.timestamp), 3)
        else:
            duration = None
        outcome = classify_outcome(final.status_code if final else None, answer is not None, cancel is not None, any_response)

        calls.append(SipCall(
            call_id=call_id,
            from_uri=invite.from_uri,
            to_uri=invite.to_uri,
            messages=msgs,
            invite_cseq=last_cseq,
            started_at=started,
            ended_at=term.timestamp if term else (capture_end if (answer and capture_end) else msgs[-1].timestamp),
            connected_at=answer.timestamp if answer else None,
            terminated_at=term.timestamp if term else None,
            first_provisional_at=provisionals_all[0].timestamp if provisionals_all else None,
            ringing_at=first180.timestamp if first180 else None,
            early_media_at=first183.timestamp if first183 else None,
            final_status=final.status_code if final else None,
            final_reason=final.reason if final else None,
            missing_ack=bool(missing_ack_dialogs),
            termination_observed=term is not None,
            retransmissions=retrans,
            media_endpoints=endpoints,
            outcome=outcome,
            caller_ip=invite.src_ip,
            callee_ip=invite.dst_ip,
            pdd_ms=_ms(started, first_progress_or_final.timestamp if first_progress_or_final else None),
            setup_time_ms=_ms(started, answer.timestamp if answer else None),
            ring_time_ms=_ms(first180.timestamp if first180 else None, answer.timestamp if answer else None),
            trying_ms=_ms(started, trying.timestamp if trying else None),
            duration_s=duration,
            disconnect_side=disconnect_side,
            disconnect_method=disconnect_method,
            q850_cause=q850,
            q850_text=cause_text(q850),
            reason_header=reason_header,
            auth_challenges=auth_challenges,
            invite_attempts=len(initial_cseqs),
            no_response=not any_response,
            dialogs=list(dialogs.values()),
            forked=len(confirmed) > 1,
            early_dialogs=len(dialogs),
            reinvites=len(reinvite_cseqs),
            hold_events=hold_events,
            transfers=transfers,
            caller_user_agent=invite.user_agent,
            callee_user_agent=(callee_msg.server or callee_msg.user_agent) if callee_msg else None,
            p_asserted_identity=invite.header("p-asserted-identity"),
            diversion=invite.header("diversion"),
            negotiated_codecs=negotiated,
            unanswered_ack_dialogs=missing_ack_dialogs,
            session_expires=_session_expires(msgs),
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
