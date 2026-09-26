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


def ipv6(src, dst, l4, next_header=17, frag=None, dscp=0):
    ext = b""
    nh = next_header
    if frag is not None:
        ident, offset, more = frag
        ext = struct.pack("!BBHI", next_header, 0, (offset // 8) << 3 | (1 if more else 0), ident)
        nh = 44
    body = ext + l4
    return struct.pack("!IHBB16s16s", (6 << 28) | (dscp << 22), len(body), nh, 64,
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


# --- Building blocks for the test lab (tests/lab.py): VLAN, IPv6/UDP, TCP, RTCP, STUN/TURN, DTLS, WebSocket ---

def vlan_ether(ip_packet, vlan_id):
    return b"\x00" * 12 + b"\x81\x00" + struct.pack("!H", vlan_id) + b"\x08\x00" + ip_packet


def udp6_frame(src, dst, sport, dport, payload, dscp=0):
    return ether(ipv6(src, dst, udp_datagram(sport, dport, payload), dscp=dscp), v6=True)


def tcp_segment(sport, dport, seq, ack, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0) + payload


def tcp_frame(src, dst, sport, dport, seq, ack, flags, payload=b"", dscp=0):
    return ether(ipv4(src, dst, tcp_segment(sport, dport, seq, ack, flags, payload), proto=6, dscp=dscp))


class TcpConn:
    """A TCP connection with consistent sequence numbers. send() splits payloads at mss like a real stack."""
    SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04

    def __init__(self, c_ip, c_port, s_ip, s_port, isn_c=1000, isn_s=5000):
        self.c, self.s = (c_ip, c_port), (s_ip, s_port)
        self.seq = {"c": isn_c, "s": isn_s}

    def _frame(self, t, side, flags, payload=b""):
        (sip, sp), (dip, dp) = (self.c, self.s) if side == "c" else (self.s, self.c)
        other = "s" if side == "c" else "c"
        return (t, tcp_frame(sip, dip, sp, dp, self.seq[side], self.seq[other], flags, payload))

    def handshake(self, t):
        f = [self._frame(t, "c", self.SYN)]
        self.seq["c"] += 1
        f.append(self._frame(t + 0.01, "s", self.SYN | self.ACK))
        self.seq["s"] += 1
        f.append(self._frame(t + 0.02, "c", self.ACK))
        return f

    def send(self, t, side, payload, mss=1400):
        out = []
        for i in range(0, len(payload), mss):
            chunk = payload[i:i + mss]
            out.append(self._frame(t + i / mss * 0.0005, side, self.PSH | self.ACK, chunk))
            self.seq[side] += len(chunk)
        return out

    def rst(self, t, side):
        return [self._frame(t, side, self.RST | self.ACK)]


def rtcp_sr(ssrc, report_ssrc=None, fraction=0, cumulative=0, highest=0, jitter=0):
    blocks = b""
    if report_ssrc is not None:
        blocks = struct.pack("!IB", report_ssrc, fraction) + cumulative.to_bytes(3, "big") + struct.pack("!IIII", highest, jitter, 0, 0)
    body = struct.pack("!IIIII", ssrc, 0, 0, 0, 0) + struct.pack("!I", 0) + blocks
    words = (4 + len(body)) // 4 - 1
    return struct.pack("!BBH", 0x80 | (1 if blocks else 0), 200, words) + body


def rtcp_rr(ssrc, report_ssrc, fraction=0, cumulative=0, highest=0, jitter=0):
    block = struct.pack("!IB", report_ssrc, fraction) + cumulative.to_bytes(3, "big") + struct.pack("!IIII", highest, jitter, 0, 0)
    body = struct.pack("!I", ssrc) + block
    return struct.pack("!BBH", 0x81, 201, (4 + len(body)) // 4 - 1) + body


STUN_MAGIC = 0x2112A442


def stun_attr(t, value):
    pad = (4 - len(value) % 4) % 4
    return struct.pack("!HH", t, len(value)) + value + b"\x00" * pad


def stun_xor_addr(t, ip, port):
    x = int(ipaddress.IPv4Address(ip)) ^ STUN_MAGIC
    return stun_attr(t, struct.pack("!BBHI", 0, 1, port ^ (STUN_MAGIC >> 16), x))


def stun(method, cls, txid, attrs=b""):
    """cls: 0 request, 1 indication, 2 success, 3 error."""
    mtype = (method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2)
    mtype |= ((cls & 1) << 4) | ((cls & 2) << 7)
    return struct.pack("!HHI", mtype, len(attrs), STUN_MAGIC) + txid + attrs


def stun_error(code, reason=b""):
    return stun_attr(0x0009, struct.pack("!HBB", 0, code // 100, code % 100) + reason)


def channel_data(channel, data):
    return struct.pack("!HH", channel, len(data)) + data


def dtls_record(ctype, epoch, seq, body):
    return struct.pack("!BHH", ctype, 0xFEFD, epoch) + seq.to_bytes(6, "big") + struct.pack("!H", len(body)) + body


def dtls_handshake(msg_type, msg_seq, body):
    n = len(body)
    return bytes([msg_type]) + n.to_bytes(3, "big") + struct.pack("!H", msg_seq) + (0).to_bytes(3, "big") + n.to_bytes(3, "big") + body


def dtls_client_hello(use_srtp=True):
    exts = b""
    if use_srtp:
        exts += struct.pack("!HH", 14, 5) + b"\x00\x02\x00\x01\x00"
    exts += struct.pack("!HH", 10, 4) + b"\x00\x02\x00\x17"
    body = b"\xfe\xfd" + b"\x11" * 32 + b"\x00" + b"\x00" + struct.pack("!H", 4) + b"\xc0\x2b\xc0\x2f" + b"\x01\x00" \
        + struct.pack("!H", len(exts)) + exts
    return dtls_handshake(1, 0, body)


def ws_frame(payload, opcode=1, mask=False):
    """RFC 6455 frame. Browsers mask client->server frames; servers never mask."""
    m = 0x80 if mask else 0
    n = len(payload)
    hdr = bytes([0x80 | opcode]) + (bytes([m | n]) if n < 126 else bytes([m | 126]) + struct.pack("!H", n))
    if not mask:
        return hdr + payload
    key = b"\x37\xfa\x21\x3d"
    return hdr + key + bytes(c ^ key[i % 4] for i, c in enumerate(payload))
