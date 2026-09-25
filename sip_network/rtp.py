from __future__ import annotations

import math
import statistics
import struct
from collections import defaultdict
from dataclasses import dataclass

from .emodel import estimate_mos
from .models import Packet, RtpPacket, RtpStream, SipCall
from .rtcp import looks_like_rtcp, parse_rtcp_reports
from .sdp import STATIC_AUDIO


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


def analyze_rtp(packets: list[Packet], calls: list[SipCall]) -> list[RtpStream]:
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
    for rr in reports:
        if rr.rtt_ms is not None:
            report_rtts[rr.source_ssrc].append(rr.rtt_ms)

    calls_by_id = {c.call_id: c for c in calls}
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
        if codec.startswith("PT"):
            clock_rate = _infer_clock_rate(rtp_packets)

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

        jitter = 0.0; prev_transit = None
        for rp in rtp_packets:
            arrival_units = rp.timestamp * clock_rate
            transit = arrival_units - rp.rtp_timestamp
            if prev_transit is not None:
                d = transit - prev_transit
                jitter += (abs(d) - jitter) / 16.0
            prev_transit = transit
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

        dtmf_events = []
        for p, r in rows:
            is_telephone_event = False
            if call:
                for ep in call.media_endpoints:
                    c = ep.get("codecs", {}).get(r.payload_type) or ep.get("codecs", {}).get(str(r.payload_type))
                    if c and str(c.get("name", "")).upper() == "TELEPHONE-EVENT":
                        is_telephone_event = True; break
            if is_telephone_event and len(r.raw_payload) >= 4:
                event = r.raw_payload[0]
                if event not in dtmf_events: dtmf_events.append(event)

        burst = _burst_ratio(ext_seqs)
        rtts = report_rtts.get(first_r.ssrc, [])
        rtt = statistics.median(rtts) if rtts else None
        one_way = rtt / 2.0 if rtt is not None else None
        mos, rf, note = estimate_mos(codec, loss_pct, burst, one_way)

        idx += 1
        streams.append(RtpStream(
            stream_id=f"RTP-{idx:03d}", call_id=call_id,
            src_ip=first_p.src_ip, dst_ip=first_p.dst_ip, src_port=first_p.src_port, dst_port=first_p.dst_port,
            ssrc=first_r.ssrc, payload_type=first_r.payload_type, codec=codec, clock_rate=clock_rate,
            packets=len(rtp_packets), unique_packets=unique, expected_packets=expected, lost_packets=lost,
            loss_percent=round(loss_pct, 3), duplicates=duplicates, out_of_order=ooo,
            jitter_ms=round(jitter_ms, 3), max_interarrival_gap_ms=round(max_gap, 3), duration_s=round(duration, 3),
            bitrate_kbps=round(bitrate, 2), ptime_ms=round(ptime, 2) if ptime else None,
            burst_ratio=round(burst, 3), dtmf_events=dtmf_events,
            rtt_ms=round(rtt, 2) if rtt is not None else None, mos=mos, r_factor=rf, mos_note=note,
        ))
    return streams
