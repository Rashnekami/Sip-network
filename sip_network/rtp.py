from __future__ import annotations

import statistics
import struct
from collections import defaultdict
from dataclasses import dataclass

from .emodel import estimate_mos
from .models import Packet, RtpPacket, RtpStream, SipCall
from .rtcp import looks_like_rtcp, parse_rtcp_reports
from .sdp import STATIC_AUDIO

DTMF_SYMBOLS = {i: str(i) for i in range(10)} | {10: "*", 11: "#", 12: "A", 13: "B", 14: "C", 15: "D", 16: "F"}


@dataclass(slots=True)
class ParsedRtp:
    marker: int
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    header_len: int
    padding_len: int
    payload_len: int
    raw_payload: bytes


def parse_rtp(payload: bytes) -> ParsedRtp | None:
    if len(payload) < 12 or looks_like_rtcp(payload):
        return None
    b0, b1 = payload[0], payload[1]
    if b0 >> 6 != 2:
        return None
    padding = (b0 >> 5) & 1; extension = (b0 >> 4) & 1; cc = b0 & 0x0F
    marker = (b1 >> 7) & 1; pt = b1 & 0x7F
    seq = struct.unpack("!H", payload[2:4])[0]
    ts, ssrc = struct.unpack("!II", payload[4:12])
    pos = 12 + cc * 4
    if pos > len(payload): return None
    if extension:
        if pos + 4 > len(payload): return None
        ext_words = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
        pos += 4 + ext_words * 4
        if pos > len(payload): return None
    padding_len = payload[-1] if padding else 0
    if padding_len > len(payload) - pos: return None
    end = len(payload) - padding_len if padding_len else len(payload)
    return ParsedRtp(marker, pt, seq, ts, ssrc, pos, padding_len, max(0, end - pos), payload[pos:end])


def _endpoint_match(call: SipCall, p: Packet, pt: int) -> int:
    score = 0
    for ep in call.media_endpoints:
        ip = ep.get("ip"); port = ep.get("port")
        if ip and port and ((p.src_ip == ip and p.src_port == port) or (p.dst_ip == ip and p.dst_port == port)):
            score = max(score, 6)
        elif port and (p.src_port == port or p.dst_port == port):
            score = max(score, 3)
        if pt in ep.get("payload_types", []):
            score += 1
    participant_ips = {m.src_ip for m in call.messages} | {m.dst_ip for m in call.messages}
    if p.src_ip in participant_ips: score += 1
    if p.dst_ip in participant_ips: score += 1
    end = call.terminated_at or call.ended_at
    if call.started_at - 2 <= p.timestamp <= end + 5: score += 2
    return score


def _choose_call(calls: list[SipCall], p: Packet, pt: int) -> str | None:
    scored = sorted((( _endpoint_match(c, p, pt), c.call_id) for c in calls), reverse=True)
    if not scored or scored[0][0] < 4:
        return None
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        return None
    return scored[0][1]


def _codec_for(call: SipCall | None, pt: int) -> tuple[str, int, float | None]:
    if call:
        for ep in call.media_endpoints:
            codecs = ep.get("codecs", {})
            c = codecs.get(pt) or codecs.get(str(pt))
            if c:
                return str(c.get("name", f"PT{pt}")).upper(), int(c.get("clock_rate") or 8000), ep.get("ptime_ms")
    if pt in STATIC_AUDIO:
        name, rate, _channels = STATIC_AUDIO[pt]
        return name, rate, None
    return f"PT{pt}", 8000, None


def _unwrap16(seq: int, highest_ext: int | None) -> int:
    if highest_ext is None:
        return seq
    base = highest_ext & ~0xFFFF
    candidates = [base | seq, (base - 0x10000) | seq, (base + 0x10000) | seq]
    return min(candidates, key=lambda x: abs(x - highest_ext))


def _burst_ratio(ext_sequences: list[int]) -> float:
    uniq = sorted(set(ext_sequences))
    if len(uniq) < 2: return 1.0
    expected = uniq[-1] - uniq[0] + 1
    lost = expected - len(uniq)
    if lost <= 0: return 1.0
    present = set(uniq); bursts = []; run = 0
    for s in range(uniq[0], uniq[-1] + 1):
        if s not in present:
            run += 1
        elif run:
            bursts.append(run); run = 0
    if run: bursts.append(run)
    observed = statistics.mean(bursts) if bursts else 1.0
    p = lost / expected
    random_expected = 1.0 / max(1e-9, 1.0 - p)
    return max(1.0, observed / random_expected)


def _infer_clock_rate(pkts: list[RtpPacket]) -> int:
    estimates = []
    for a, b in zip(pkts, pkts[1:]):
        dt = b.timestamp - a.timestamp
        tsd = (b.rtp_timestamp - a.rtp_timestamp) & 0xFFFFFFFF
        if 0.002 < dt < 1.0 and 0 < tsd < 10_000_000:
            estimates.append(tsd / dt)
    if not estimates: return 8000
    med = statistics.median(estimates)
    candidates = [8000, 11025, 16000, 22050, 32000, 44100, 48000, 90000]
    return min(candidates, key=lambda x: abs(x - med))


def _ep(ip, port) -> str:
    return f"[{ip}]:{port}" if ip and ":" in ip else f"{ip}:{port}"


def _media_kind(call: SipCall | None, pt: int, clock_rate: int) -> str:
    if call:
        for ep in call.media_endpoints:
            if pt in ep.get("payload_types", []):
                return ep.get("media", "audio")
    return "video" if clock_rate == 90000 else "audio"


def _hold_windows(call: SipCall | None) -> list[tuple[float, float]]:
    if not call or not call.hold_events:
        return []
    out = []; start = None
    for h in call.hold_events:
        if h["event"] == "hold" and start is None:
            start = h["at"]
        elif h["event"] == "resume" and start is not None:
            out.append((start, h["at"])); start = None
    if start is not None:
        out.append((start, float("inf")))
    return out


def analyze_rtp(packets: list[Packet], calls: list[SipCall], gap_threshold_ms: float = 500.0,
                secure_pairs: set[frozenset] | None = None) -> list[RtpStream]:
    """secure_pairs: UDP pairs known to carry SRTP (ICE/DTLS seen). Their RTCP report blocks are encrypted and ignored."""
    secure_pairs = secure_pairs or set()
    candidates: dict[tuple, list[tuple[Packet, ParsedRtp]]] = defaultdict(list)
    for p in packets:
        if p.protocol != "UDP" or not p.payload:
            continue
        r = parse_rtp(p.payload)
        if not r: continue
        key = (p.src_ip, p.dst_ip, p.src_port, p.dst_port, r.ssrc)
        candidates[key].append((p, r))

    reports = parse_rtcp_reports(packets)
    report_rtts: dict[int, list[float]] = defaultdict(list)
    last_report: dict[int, object] = {}
    for rr in reports:
        if rr.rtt_ms is not None:
            report_rtts[rr.source_ssrc].append(rr.rtt_ms)
        last_report[rr.source_ssrc] = rr
    calls_by_id = {c.call_id: c for c in calls}

    # SSRCs per flow and media kind: with BUNDLE (WebRTC) audio and video share the 5-tuple legitimately.
    def _kind_of(rows) -> str:
        p0, r0 = rows[0]
        call = calls_by_id.get(_choose_call(calls, p0, r0.payload_type) or "")
        name, rate, _ = _codec_for(call, r0.payload_type)
        return _media_kind(call, r0.payload_type, rate if not name.startswith("PT") else _infer_clock_rate(
            [RtpPacket(p.number, p.timestamp, None, None, None, None, 0, r.payload_type, r.sequence, r.timestamp, r.ssrc, 0, 0)
             for p, r in rows[:50]]))
    kind_of_key = {key: _kind_of(sorted(rows, key=lambda x: x[0].timestamp)) for key, rows in candidates.items()}
    ssrcs_per_flow: dict[tuple, set[int]] = defaultdict(set)
    for key in candidates:
        ssrcs_per_flow[key[:4] + (kind_of_key[key],)].add(key[4])

    streams: list[RtpStream] = []
    idx = 0
    for key, rows in candidates.items():
        rows.sort(key=lambda x: (x[0].timestamp, x[0].number))
        # RTP heuristic fallback requires at least 3 packets and reasonable sequence continuity,
        # unless SDP produced a strong endpoint match.
        first_p, first_r = rows[0]
        call_id = _choose_call(calls, first_p, first_r.payload_type)
        seqs = [r.sequence for _, r in rows]
        sequential_pairs = sum(1 for a, b in zip(seqs, seqs[1:]) if ((b - a) & 0xFFFF) in range(1, 100))
        continuity = sequential_pairs / max(1, len(seqs) - 1)
        if call_id is None and (len(rows) < 3 or continuity < 0.5):
            continue

        call = calls_by_id.get(call_id) if call_id else None
        codec, clock_rate, signaled_ptime = _codec_for(call, first_r.payload_type)
        rtp_packets = [RtpPacket(p.number, p.timestamp, p.src_ip, p.dst_ip, p.src_port, p.dst_port,
                                 r.marker, r.payload_type, r.sequence, r.timestamp, r.ssrc,
                                 r.payload_len, r.header_len, r.padding_len) for p, r in rows]
        codec_inferred = False
        if codec.startswith("PT"):
            clock_rate = _infer_clock_rate(rtp_packets)
            # Without SDP: a dynamic PT at 48 kHz is Opus in practice (WebRTC and modern softphones).
            if clock_rate == 48000 and first_r.payload_type >= 96:
                codec, codec_inferred = "OPUS", True
        kind = _media_kind(call, first_r.payload_type, clock_rate)
        secure = frozenset((_ep(first_p.src_ip, first_p.src_port), _ep(first_p.dst_ip, first_p.dst_port))) in secure_pairs \
            or bool(call and any("SAVP" in (ep.get("proto") or "").upper() for ep in call.media_endpoints))

        highest = None; ext_seqs = []; duplicates = 0; ooo = 0; seen = set()
        for rp in rtp_packets:
            ext = _unwrap16(rp.sequence, highest)
            if ext in seen:
                duplicates += 1
            else:
                if highest is not None and ext < highest:
                    ooo += 1
                seen.add(ext)
            highest = ext if highest is None else max(highest, ext)
            ext_seqs.append(ext)
        unique = len(seen)
        expected = (max(seen) - min(seen) + 1) if seen else 0
        lost = max(0, expected - unique)
        loss_pct = (lost * 100.0 / expected) if expected else 0.0

        # RFC 3550 jitter. A new talkspurt (marker bit) or a pause longer than the gap threshold (hold, VAD) restarts
        # the RTP timestamp base on many devices; that jump is a resync, not network jitter.
        jitter = 0.0; prev_transit = None; prev_arrival = None
        for rp in rtp_packets:
            arrival_units = rp.timestamp * clock_rate
            transit = arrival_units - rp.rtp_timestamp
            resync = rp.marker or (prev_arrival is not None and (rp.timestamp - prev_arrival) * 1000.0 >= gap_threshold_ms)
            if prev_transit is not None and not resync:
                d = transit - prev_transit
                jitter += (abs(d) - jitter) / 16.0
            prev_transit = transit; prev_arrival = rp.timestamp
        jitter_ms = jitter * 1000.0 / clock_rate if clock_rate else 0.0

        gaps_ms = [max(0.0, (b.timestamp - a.timestamp) * 1000.0) for a, b in zip(rtp_packets, rtp_packets[1:])]
        max_gap = max(gaps_ms) if gaps_ms else 0.0
        duration = max(0.0, rtp_packets[-1].timestamp - rtp_packets[0].timestamp) if len(rtp_packets) > 1 else 0.0
        payload_bytes = sum(r.payload_len for _, r in rows)
        bitrate = payload_bytes * 8 / 1000.0 / duration if duration > 0 else 0.0

        inferred_ptime = None
        ts_deltas = []
        for a, b in zip(rtp_packets, rtp_packets[1:]):
            dseq = (b.sequence - a.sequence) & 0xFFFF
            dts = (b.rtp_timestamp - a.rtp_timestamp) & 0xFFFFFFFF
            if dseq == 1 and dts > 0:
                ts_deltas.append(dts * 1000.0 / clock_rate)
        if ts_deltas:
            inferred_ptime = statistics.median(ts_deltas)
        ptime = signaled_ptime or inferred_ptime

        # RFC 4733: every packet of one key press shares the RTP timestamp, so count events per timestamp.
        dtmf_events: list[int] = []
        seen_event_ts: set[int] = set()
        for p, r in rows:
            is_telephone_event = False
            if call:
                for ep in call.media_endpoints:
                    c = ep.get("codecs", {}).get(r.payload_type) or ep.get("codecs", {}).get(str(r.payload_type))
                    if c and str(c.get("name", "")).upper() == "TELEPHONE-EVENT":
                        is_telephone_event = True; break
            if is_telephone_event and not secure and len(r.raw_payload) >= 4 and r.timestamp not in seen_event_ts:
                seen_event_ts.add(r.timestamp)
                dtmf_events.append(r.raw_payload[0])
        dtmf_digits = "".join(DTMF_SYMBOLS.get(e, "?") for e in dtmf_events)

        burst = _burst_ratio(ext_seqs)
        rtts = [] if secure else report_rtts.get(first_r.ssrc, [])
        rtt = statistics.median(rtts) if rtts else None
        one_way = rtt / 2.0 if rtt is not None else None
        if kind == "audio":
            mos, rf, note = estimate_mos(codec, loss_pct, burst, one_way)
            if codec_inferred:
                note = f"{note} Codec inferido (sem SDP)."
        else:
            mos = rf = note = None

        dscp_values: dict[int, int] = defaultdict(int)
        for p, _r in rows:
            if p.dscp is not None:
                dscp_values[p.dscp] += 1
        dscp = max(dscp_values, key=dscp_values.get) if dscp_values else None
        # Silence while the call is on hold is expected: ignore gaps inside hold windows (with a little slack).
        holds = _hold_windows(call)
        gaps_over = sum(1 for g, (a, b) in zip(gaps_ms, zip(rtp_packets, rtp_packets[1:])) if g >= gap_threshold_ms
                        and not any(h0 - 1.0 <= a.timestamp and b.timestamp <= h1 + 1.0 for h0, h1 in holds))
        cn_packets = sum(1 for _p, r in rows if r.payload_type == 13 or _codec_for(call, r.payload_type)[0] == "CN")
        unexpected: list[int] = []
        dest_match = None
        if call and call.media_endpoints:
            offered = {pt for ep in call.media_endpoints for pt in ep.get("payload_types", [])}
            unexpected = sorted({r.payload_type for _p, r in rows} - offered)
            # Only judge the destination when both offer and answer were captured.
            if len({ep.get("side") for ep in call.media_endpoints}) >= 2 and not any(ep.get("ice") for ep in call.media_endpoints):
                dest_match = any(ep.get("ip") == first_p.dst_ip and ep.get("port") == first_p.dst_port for ep in call.media_endpoints)
        rep = None if secure else last_report.get(first_r.ssrc)
        remote_loss = remote_cum = remote_jitter = None
        if rep is not None:
            remote_loss = round(rep.fraction_lost, 2)
            remote_cum = rep.cumulative_lost
            remote_jitter = round(rep.jitter * 1000.0 / clock_rate, 2) if clock_rate else None

        idx += 1
        streams.append(RtpStream(
            stream_id=f"RTP-{idx:03d}", call_id=call_id,
            src_ip=first_p.src_ip, dst_ip=first_p.dst_ip, src_port=first_p.src_port, dst_port=first_p.dst_port,
            ssrc=first_r.ssrc, payload_type=first_r.payload_type, codec=codec, clock_rate=clock_rate,
            packets=len(rtp_packets), unique_packets=unique, expected_packets=expected, lost_packets=lost,
            loss_percent=round(loss_pct, 3), duplicates=duplicates, out_of_order=ooo,
            jitter_ms=round(jitter_ms, 3), max_interarrival_gap_ms=round(max_gap, 3), duration_s=round(duration, 3),
            bitrate_kbps=round(bitrate, 2), ptime_ms=round(ptime, 2) if ptime else None,
            burst_ratio=round(burst, 3), dtmf_events=dtmf_events, dtmf_digits=dtmf_digits,
            rtt_ms=round(rtt, 2) if rtt is not None else None, mos=mos, r_factor=rf, mos_note=note,
            dscp=dscp, dscp_values=dict(dscp_values),
            first_packet_at=rtp_packets[0].timestamp, last_packet_at=rtp_packets[-1].timestamp,
            gaps_over_threshold=gaps_over, comfort_noise_packets=cn_packets,
            unexpected_payload_types=unexpected, ssrc_changes_on_flow=len(ssrcs_per_flow[key[:4] + (kind_of_key[key],)]) - 1,
            rtcp_remote_loss_pct=remote_loss, rtcp_remote_cumulative_lost=remote_cum,
            rtcp_remote_jitter_ms=remote_jitter, sdp_destination_match=dest_match,
            media_kind=kind, secure=secure, codec_inferred=codec_inferred,
        ))
    return streams
