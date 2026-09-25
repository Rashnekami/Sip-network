"""Tiny PCAP writer used by the tests to build realistic SIP/RTP scenarios without binary fixtures."""
from __future__ import annotations

import ipaddress
import struct


def _ip4(s):
    return ipaddress.IPv4Address(s).packed


def udp_datagram(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ipv4(src, dst, l4, proto=17, dscp=0, ident=1, frag_offset=0, more=False):
    flags = (0x2000 if more else 0) | (frag_offset // 8)
    return struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, 20 + len(l4), ident, flags, 64, proto, 0, _ip4(src), _ip4(dst)) + l4


def ipv6(src, dst, l4, next_header=17, frag=None):
    ext = b""
    nh = next_header
    if frag is not None:
        ident, offset, more = frag
        ext = struct.pack("!BBHI", next_header, 0, (offset // 8) << 3 | (1 if more else 0), ident)
        nh = 44
    body = ext + l4
    return struct.pack("!IHBB16s16s", 6 << 28, len(body), nh, 64,
                       ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed) + body


def ether(ip_packet, v6=False):
    return b"\x00" * 12 + (b"\x86\xdd" if v6 else b"\x08\x00") + ip_packet


def udp_frame(src, dst, sport, dport, payload, dscp=0):
    return ether(ipv4(src, dst, udp_datagram(sport, dport, payload), dscp=dscp))


def pcap(frames):
    """frames: iterable of (timestamp_seconds, frame_bytes)."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)]
    for t, f in frames:
        sec = int(t); usec = int(round((t - sec) * 1e6))
        out.append(struct.pack("<IIII", sec, usec, len(f), len(f)) + f)
    return b"".join(out)


def rtp(seq, ts, ssrc, pt=0, payload=b"\xff" * 160, marker=0):
    return struct.pack("!BBHII", 0x80, (marker << 7) | pt, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc) + payload


def sdp(ip, port, pts=(0, 101), direction="sendrecv", extra=""):
    lines = ["v=0", f"o=- 1 1 IN IP4 {ip}", "s=-", f"c=IN IP4 {ip}", "t=0 0",
             f"m=audio {port} RTP/AVP {' '.join(str(p) for p in pts)}", "a=rtpmap:0 PCMU/8000"]
    if 101 in pts:
        lines += ["a=rtpmap:101 telephone-event/8000", "a=fmtp:101 0-16"]
    lines += ["a=ptime:20", f"a={direction}"]
    body = "\r\n".join(lines) + "\r\n" + extra
    return body


class Sip:
    """Builds SIP messages for one Call-ID between caller A and callee B."""

    def __init__(self, call_id="call-1", a="10.0.0.1", b="10.0.0.2", from_user="1000", to_user="2000",
                 from_tag="a1", ua="TestPhone/1.0"):
        self.call_id, self.a, self.b = call_id, a, b
        self.from_user, self.to_user, self.from_tag, self.ua = from_user, to_user, from_tag, ua

    def request(self, method, cseq, to_tag=None, body="", extra="", branch=None, cseq_method=None, from_side="a"):
        src_is_a = from_side == "a"
        f_tag = self.from_tag if src_is_a else to_tag
        t_tag = to_tag if src_is_a else self.from_tag
        f_user, t_user = (self.from_user, self.to_user) if src_is_a else (self.to_user, self.from_user)
        host = self.a if src_is_a else self.b
        lines = [f"{method} sip:{t_user}@{self.b if src_is_a else self.a} SIP/2.0",
                 f"Via: SIP/2.0/UDP {host}:5060;branch={branch or f'z9hG4bK-{self.call_id}-{method}-{cseq}-{from_side}'}",
                 f"From: <sip:{f_user}@{host}>;tag={f_tag}",
                 f"To: <sip:{t_user}@x>" + (f";tag={t_tag}" if t_tag else ""),
                 f"Call-ID: {self.call_id}", f"CSeq: {cseq} {cseq_method or method}",
                 f"Contact: <sip:{f_user}@{host}:5060>", f"User-Agent: {self.ua}"]
        return self._finish(lines, body, extra)

    def response(self, code, reason, cseq, method="INVITE", to_tag=None, body="", extra="", branch=None, req_from_side="a"):
        req_src_is_a = req_from_side == "a"
        host = self.a if req_src_is_a else self.b
        f_user, t_user = (self.from_user, self.to_user) if req_src_is_a else (self.to_user, self.from_user)
        f_tag = self.from_tag if req_src_is_a else to_tag
        t_tag = to_tag if req_src_is_a else self.from_tag
        lines = [f"SIP/2.0 {code} {reason}",
                 f"Via: SIP/2.0/UDP {host}:5060;branch={branch or f'z9hG4bK-{self.call_id}-{method}-{cseq}-{req_from_side}'}",
                 f"From: <sip:{f_user}@{host}>;tag={f_tag}",
                 f"To: <sip:{t_user}@x>" + (f";tag={t_tag}" if t_tag else ""),
                 f"Call-ID: {self.call_id}", f"CSeq: {cseq} {method}", "Server: TestServer/2.0"]
        return self._finish(lines, body, extra)

    @staticmethod
    def _finish(lines, body, extra):
        if extra:
            lines += [x for x in extra.split("\r\n") if x]
        if body:
            lines.append("Content-Type: application/sdp")
        lines.append(f"Content-Length: {len(body.encode())}")
        return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()

    def a_to_b(self, t, payload, dscp=0):
        return (t, udp_frame(self.a, self.b, 5060, 5060, payload, dscp))

    def b_to_a(self, t, payload, dscp=0):
        return (t, udp_frame(self.b, self.a, 5060, 5060, payload, dscp))


def rtp_flow(src, dst, sport, dport, t0, count, ssrc, pt=0, ptime=0.02, seq0=1000, dscp=46, skip=(), gap_after=None, gap_s=0.0):
    frames = []
    t = t0
    for i in range(count):
        if gap_after is not None and i == gap_after:
            t += gap_s
        if i not in skip:
            frames.append((t, udp_frame(src, dst, sport, dport, rtp(seq0 + i, 160 * i, ssrc, pt), dscp)))
        t += ptime
    return frames


def basic_call(call_id="call-1", t0=100.0, talk_s=3.0, a="10.0.0.1", b="10.0.0.2", with_bye=True, rtp_both=True,
               caller_ack=True, dscp=46, to_user="2000", port_a=40000, port_b=50000, ssrc_a=111, ssrc_b=222):
    s = Sip(call_id, a, b, to_user=to_user)
    frames = [
        s.a_to_b(t0, s.request("INVITE", 1, body=sdp(a, port_a))),
        s.b_to_a(t0 + 0.05, s.response(100, "Trying", 1)),
        s.b_to_a(t0 + 1.0, s.response(180, "Ringing", 1, to_tag="b1")),
        s.b_to_a(t0 + 3.0, s.response(200, "OK", 1, to_tag="b1", body=sdp(b, port_b))),
    ]
    if caller_ack:
        frames.append(s.a_to_b(t0 + 3.05, s.request("ACK", 1, to_tag="b1")))
    n = int(talk_s / 0.02)
    frames += rtp_flow(a, b, port_a, port_b, t0 + 3.1, n, ssrc=ssrc_a, dscp=dscp)
    if rtp_both:
        frames += rtp_flow(b, a, port_b, port_a, t0 + 3.1, n, ssrc=ssrc_b, dscp=dscp)
    if with_bye:
        end = t0 + 3.1 + talk_s + 0.1
        frames.append(s.a_to_b(end, s.request("BYE", 2, to_tag="b1")))
        frames.append(s.b_to_a(end + 0.05, s.response(200, "OK", 2, method="BYE", to_tag="b1")))
    return frames
