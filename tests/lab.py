"""Laboratório de pcaps: uma captura sintética por anomalia, com o diagnóstico que o analisador precisa dar.

Cada cenário declara:
- expect: códigos que TÊM de aparecer (qualquer severidade);
- allow: códigos que podem aparecer como consequência do mesmo problema.
Qualquer outro código, de qualquer severidade, é alarme falso. Cenários sem expect são capturas limpas: nada pode aparecer.

Os pcaps são determinísticos (sementes fixas). tools/make_lab_pcaps.py grava todos em disco; tests/test_lab.py roda o
motor em cada um e falha se algo esperado não for detectado ou se surgir alarme falso.
"""
from __future__ import annotations

import os
import random
import struct
import zlib
from dataclasses import dataclass, field
from typing import Callable

from pcapgen import (TcpConn, channel_data, dtls_client_hello, dtls_handshake, dtls_record, ether, ipv4, ipv6, pcap,
                     rtcp_rr, rtcp_sr, stun, stun_attr, stun_error, stun_xor_addr, tcp_frame, udp6_frame, udp_datagram,
                     udp_frame, vlan_ether, ws_frame)


@dataclass
class Scenario:
    id: str
    category: str
    title: str
    what: str
    expect: tuple[str, ...]
    allow: tuple[str, ...]
    build: Callable[[], list]
    check: Callable | None = None

    @property
    def filename(self) -> str:
        return f"{self.id}.pcap"

    def pcap(self) -> bytes:
        frames = self.build()
        frames.sort(key=lambda f: f[0])
        return pcap(frames)


SCENARIOS: list[Scenario] = []
CATEGORIES = {"limpo": "Capturas limpas (não pode haver alarme)", "sinalizacao": "Sinalização SIP", "midia": "Mídia / qualidade de áudio",
              "nat": "NAT", "seguranca": "Segurança SIP", "ddos": "DDoS e floods", "webrtc": "WebRTC", "misto": "Cenário misto"}
T0 = 1_750_000_000.0  # 2025-06-15 UTC: realistic absolute timestamps


def _h(*x) -> int:
    """Stable hash (Python's hash() of str changes per process)."""
    return zlib.crc32(repr(x).encode())


def scenario(id: str, category: str, title: str, what: str, expect=(), allow=(), check=None):
    def deco(fn):
        SCENARIOS.append(Scenario(id, category, title, what, tuple(expect), tuple(allow), fn, check))
        return fn
    return deco


# ---------------------------------------------------------------------------------------------------------------
# SIP / SDP / RTP builders
# ---------------------------------------------------------------------------------------------------------------

CODECS = {  # name: (payload type, payload bytes per 20 ms, rtpmap)
    "PCMU": (0, 160, "PCMU/8000"), "PCMA": (8, 160, "PCMA/8000"), "G729": (18, 20, "G729/8000"),
    "G722": (9, 160, "G722/8000"), "OPUS": (111, 80, "opus/48000/2"),
}


def sdp_body(ip, port, codec="PCMU", direction="sendrecv", dtmf=True, origin_ip=None, extra_codecs=(), v6=False):
    fam = "IP6" if v6 else "IP4"
    pts = [CODECS[codec][0]] + [CODECS[c][0] for c in extra_codecs] + ([101] if dtmf else [])
    lines = ["v=0", f"o=- 20 1 IN {fam} {origin_ip or ip}", "s=-", f"c=IN {fam} {ip}", "t=0 0",
             f"m=audio {port} RTP/AVP {' '.join(map(str, pts))}"]
    for c in (codec, *extra_codecs):
        lines.append(f"a=rtpmap:{CODECS[c][0]} {CODECS[c][2]}")
    if codec == "G729":
        lines.append("a=fmtp:18 annexb=no")
    if dtmf:
        lines += ["a=rtpmap:101 telephone-event/8000", "a=fmtp:101 0-16"]
    lines += ["a=ptime:20", f"a={direction}"]
    return "\r\n".join(lines) + "\r\n"


def sip_text(start, headers, body=""):
    lines = [start] + [f"{k}: {v}" for k, v in headers]
    if body:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body.encode())}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


class Dialog:
    """SIP messages of one Call-ID between A (caller) and B, transported as the scenario wants."""

    def __init__(self, call_id, a="10.0.0.1", b="10.0.0.2", from_user="1000", to_user="2000", a_port=5060, b_port=5060,
                 transport="UDP", sip_dscp=24, ua_a="Yealink SIP-T46U 108.86", ua_b="Asterisk PBX 20.5.0", vlan=None, v6=False,
                 via_host=None, contact_host=None, rport=True, domain="pbx.exemplo.com.br", sig_src=None):
        self.call_id, self.a, self.b = call_id, a, b
        self.from_user, self.to_user, self.a_port, self.b_port = from_user, to_user, a_port, b_port
        self.transport, self.sip_dscp, self.ua_a, self.ua_b, self.vlan, self.v6 = transport, sip_dscp, ua_a, ua_b, vlan, v6
        self.via_host, self.contact_host, self.rport, self.domain = via_host or a, contact_host or a, rport, domain
        self.sig_src = sig_src or a  # address the packets really come from (differs from a behind NAT)
        self.tag_a, self.tag_b = f"ta{_h(call_id) % 10**6}", f"tb{_h(call_id) % 10**6}"
        self.tcp = None
        self.branch_n = 0

    @staticmethod
    def _hp(host, port=None):
        h = f"[{host}]" if ":" in host else host
        return f"{h}:{port}" if port else h

    def _via(self, host, port, branch):
        return f"SIP/2.0/{self.transport} {self._hp(host, port)};branch={branch}" + (";rport" if self.rport else "")

    def req(self, method, cseq, from_b=False, body="", to_tag=True, extra=(), branch=None, cseq_method=None, uri_user=None):
        self.branch_n += 1
        branch = branch or f"z9hG4bK{_h((self.call_id, method, cseq, from_b)) % 10**8}"
        if not from_b:
            via = self._via(self.via_host, self.a_port, branch)
            frm = f"<sip:{self.from_user}@{self.domain}>;tag={self.tag_a}"
            to = f"<sip:{uri_user or self.to_user}@{self.domain}>" + (f";tag={self.tag_b}" if to_tag else "")
            contact, ua = f"<sip:{self.from_user}@{self._hp(self.contact_host, self.a_port)}>", self.ua_a
            ruri = f"sip:{uri_user or self.to_user}@{self._hp(self.b)}"
        else:
            via = self._via(self.b, self.b_port, branch)
            frm = f"<sip:{self.to_user}@{self.domain}>;tag={self.tag_b}"
            to = f"<sip:{self.from_user}@{self.domain}>;tag={self.tag_a}"
            contact, ua = f"<sip:{self.to_user}@{self._hp(self.b, self.b_port)}>", self.ua_b
            ruri = f"sip:{self.from_user}@{self._hp(self.contact_host)}"
        headers = [("Via", via), ("Max-Forwards", "70"), ("From", frm), ("To", to), ("Call-ID", self.call_id),
                   ("CSeq", f"{cseq} {cseq_method or method}"), ("Contact", contact), ("User-Agent", ua), *extra]
        return sip_text(f"{method} {ruri} SIP/2.0", headers, body)

    def resp(self, code, reason, cseq, method="INVITE", body="", to_tag=True, extra=(), to_b=False, branch=None):
        """Response to a request sent by A (default) or by B (to_b=True)."""
        branch = branch or f"z9hG4bK{_h((self.call_id, method, cseq, to_b)) % 10**8}"
        if not to_b:
            via = self._via(self.via_host, self.a_port, branch) + (f";received={self.sig_src}" if self.sig_src != self.via_host else "")
            frm = f"<sip:{self.from_user}@{self.domain}>;tag={self.tag_a}"
            to = f"<sip:{self.to_user}@{self.domain}>" + (f";tag={self.tag_b}" if to_tag else "")
            ua = ("Server", self.ua_b)
        else:
            via = self._via(self.b, self.b_port, branch)
            frm = f"<sip:{self.to_user}@{self.domain}>;tag={self.tag_b}"
            to = f"<sip:{self.from_user}@{self.domain}>;tag={self.tag_a}"
            ua = ("User-Agent", self.ua_a)
        headers = [("Via", via), ("From", frm), ("To", to), ("Call-ID", self.call_id), ("CSeq", f"{cseq} {method}"), ua, *extra]
        if 200 <= code < 300 and method == "INVITE":
            headers.append(("Contact", f"<sip:{self.to_user}@{self._hp(self.b, self.b_port)}>" if not to_b else f"<sip:{self.from_user}@{self._hp(self.contact_host)}>"))
        return sip_text(f"SIP/2.0 {code} {reason}", headers, body)

    def wire(self, t, payload, from_b=False):
        src, dst = (self.b, self.sig_src) if from_b else (self.sig_src, self.b)
        sp, dp = (self.b_port, self.a_port) if from_b else (self.a_port, self.b_port)
        if self.transport == "TCP":
            if self.tcp is None:
                self.tcp = TcpConn(self.sig_src, self.a_port, self.b, self.b_port)
                pre = self.tcp.handshake(t - 0.05)
            else:
                pre = []
            return pre + self.tcp.send(t, "s" if from_b else "c", payload)
        if self.v6:
            return [(t, udp6_frame(src, dst, sp, dp, payload, self.sip_dscp))]
        ip = ipv4(src, dst, udp_datagram(sp, dp, payload), dscp=self.sip_dscp)
        return [(t, vlan_ether(ip, self.vlan) if self.vlan else ether(ip))]


def media(src, dst, sport, dport, t0, seconds, ssrc, codec="PCMU", rng=None, dscp=46, loss=0.0, burst=1, jitter_ms=0.0,
          outage=None, dup_every=0, pt=None, v6=False, vlan=None, secure=False, seq0=None, ptime=0.02, stop_at=None):
    """One RTP direction. outage=(start_s, length_s) drops packets (network outage); jitter shifts arrival times."""
    rng = rng or random.Random(ssrc)
    pt_c, size, _ = CODECS[codec]
    pt = pt_c if pt is None else pt
    step = 960 if codec == "OPUS" else 160
    seq0 = rng.randrange(1000, 30000) if seq0 is None else seq0
    ts0 = rng.randrange(0, 2 ** 31)
    frames = []
    n = int(round(seconds / ptime))
    drop_left = 0
    for i in range(n):
        t = t0 + i * ptime
        if stop_at is not None and t >= stop_at:
            break
        if outage and outage[0] <= i * ptime < outage[0] + outage[1]:
            continue
        if drop_left:
            drop_left -= 1
            continue
        if loss and rng.random() < loss / burst:
            drop_left = burst - 1
            continue
        if secure:
            hdr = struct.pack("!BBHII", 0x90, pt, (seq0 + i) & 0xFFFF, (ts0 + i * step) & 0xFFFFFFFF, ssrc) \
                + b"\xbe\xde\x00\x01" + bytes([0x10, rng.randrange(256), 0, 0])
            payload = hdr + rng.randbytes(size) + rng.randbytes(10)
        else:
            payload = struct.pack("!BBHII", 0x80, pt, (seq0 + i) & 0xFFFF, (ts0 + i * step) & 0xFFFFFFFF, ssrc) + b"\xd5" * size
        arrival = t + (abs(rng.gauss(0, jitter_ms / 1000.0)) if jitter_ms else 0.0)
        copies = 2 if dup_every and i % dup_every == dup_every - 1 else 1
        for k in range(copies):
            if v6:
                frame = udp6_frame(src, dst, sport, dport, payload, dscp)
            else:
                ip = ipv4(src, dst, udp_datagram(sport, dport, payload), dscp=dscp)
                frame = vlan_ether(ip, vlan) if vlan else ether(ip)
            frames.append((arrival + k * 0.0003, frame))
    return frames


def call(cid, t0, a="10.0.0.1", b="10.0.0.2", codec="PCMU", talk=4.0, ring_s=1.5, pdd_s=0.3, bye_from_b=False, bye=True,
         rtp_a=True, rtp_b=True, kw_a=None, kw_b=None, port_a=40000, port_b=50000, ssrc_a=None, ssrc_b=None,
         media_a=None, media_b=None, sdp_a=None, sdp_b=None, rtcp=False, media_delay=0.05, ack=True, dlg=None,
         extra_invite=(), extra_200=(), rtp_after_bye=0.0, seed=1, dscp=46, **dlg_kw):
    """A complete answered call. media_a/media_b: (ip, port) where RTP really comes from, if not the SDP address."""
    rng = random.Random(seed)
    d = dlg or Dialog(cid, a, b, **dlg_kw)
    v6 = d.v6
    f = []
    f += d.wire(t0, d.req("INVITE", 1, body=sdp_a or sdp_body(d.a, port_a, codec, v6=v6), to_tag=False, extra=extra_invite))
    f += d.wire(t0 + 0.02, d.resp(100, "Trying", 1, to_tag=False), from_b=True)
    f += d.wire(t0 + pdd_s, d.resp(180, "Ringing", 1), from_b=True)
    t_ans = t0 + pdd_s + ring_s
    f += d.wire(t_ans, d.resp(200, "OK", 1, body=sdp_b or sdp_body(d.b, port_b, codec, v6=v6), extra=extra_200), from_b=True)
    if ack:
        f += d.wire(t_ans + 0.03, d.req("ACK", 1))
    tm = t_ans + media_delay
    ssrc_a = ssrc_a or rng.randrange(1, 2 ** 32)
    ssrc_b = ssrc_b or rng.randrange(1, 2 ** 32)
    ma = media_a or (d.sig_src if d.sig_src != d.a else d.a, port_a)
    mb = media_b or (d.b, port_b)
    common = dict(v6=v6, vlan=d.vlan, dscp=dscp)
    if rtp_a:
        f += media(ma[0], mb[0], ma[1], mb[1], tm, talk + rtp_after_bye, ssrc_a, codec, random.Random(seed * 7 + 1), **{**common, **(kw_a or {})})
    if rtp_b:
        f += media(mb[0], ma[0], mb[1], ma[1], tm, talk + rtp_after_bye, ssrc_b, codec, random.Random(seed * 7 + 2), **{**common, **(kw_b or {})})
    if rtcp and not v6:
        for k in range(1, int(talk // 5) + 1):
            f.append((tm + 5 * k, udp_frame(ma[0], mb[0], ma[1] + 1, mb[1] + 1, rtcp_sr(ssrc_a, ssrc_b), dscp)))
            f.append((tm + 5 * k + 0.1, udp_frame(mb[0], ma[0], mb[1] + 1, ma[1] + 1, rtcp_sr(ssrc_b, ssrc_a), dscp)))
    if bye:
        t_end = tm + talk + 0.02
        f += d.wire(t_end, d.req("BYE", 2 if not bye_from_b else 1, from_b=bye_from_b), from_b=bye_from_b)
        f += d.wire(t_end + 0.04, d.resp(200, "OK", 2 if not bye_from_b else 1, method="BYE", to_b=bye_from_b), from_b=not bye_from_b)
    return f


def failed_call(cid, t0, code, reason, a="10.0.0.1", b="10.0.0.2", extra=(), ring=False, to_user="2000", **kw):
    d = Dialog(cid, a, b, to_user=to_user, **kw)
    f = d.wire(t0, d.req("INVITE", 1, body=sdp_body(a, 40000), to_tag=False))
    f += d.wire(t0 + 0.02, d.resp(100, "Trying", 1, to_tag=False), from_b=True)
    if ring:
        f += d.wire(t0 + 0.5, d.resp(180, "Ringing", 1), from_b=True)
    f += d.wire(t0 + (4.0 if ring else 0.4), d.resp(code, reason, 1, extra=extra), from_b=True)
    f += d.wire(t0 + (4.05 if ring else 0.45), d.req("ACK", 1))
    return f


def register(d: Dialog, t0, final=200, challenge=True, expires=300, aor_user=None, cseq0=1, ok_reason="OK"):
    user = aor_user or d.from_user
    reg_to = [("Expires", str(expires))]
    f = []

    def rq(cseq, creds):
        h = [("Via", d._via(d.via_host, d.a_port, f"z9hG4bKr{cseq}{_h(d.call_id) % 10**5}")), ("Max-Forwards", "70"),
             ("From", f"<sip:{user}@{d.domain}>;tag={d.tag_a}"), ("To", f"<sip:{user}@{d.domain}>"), ("Call-ID", d.call_id),
             ("CSeq", f"{cseq} REGISTER"), ("Contact", f"<sip:{user}@{d.contact_host}:{d.a_port}>;expires={expires}"),
             ("User-Agent", d.ua_a), *reg_to]
        if creds:
            h.append(("Authorization", f'Digest username="{user}", realm="{d.domain}", nonce="abc", uri="sip:{d.domain}", response="0123456789abcdef"'))
        return sip_text(f"REGISTER sip:{d.domain} SIP/2.0", h)

    def rs(cseq, code, reason, extra=()):
        h = [("Via", d._via(d.via_host, d.a_port, f"z9hG4bKr{cseq}{_h(d.call_id) % 10**5}") + (f";received={d.sig_src}" if d.sig_src != d.via_host else "")),
             ("From", f"<sip:{user}@{d.domain}>;tag={d.tag_a}"), ("To", f"<sip:{user}@{d.domain}>;tag=srv"), ("Call-ID", d.call_id),
             ("CSeq", f"{cseq} REGISTER"), ("Server", d.ua_b), *extra]
        return sip_text(f"SIP/2.0 {code} {reason}", h)

    cseq = cseq0
    if challenge:
        f += d.wire(t0, rq(cseq, False))
        f += d.wire(t0 + 0.03, rs(cseq, 401, "Unauthorized", [("WWW-Authenticate", f'Digest realm="{d.domain}", nonce="abc", algorithm=MD5')]), from_b=True)
        cseq += 1
    f += d.wire(t0 + 0.1, rq(cseq, challenge))
    if final:
        extra = [("Contact", f"<sip:{user}@{d.contact_host}:{d.a_port}>;expires={expires}")] if final == 200 else []
        f += d.wire(t0 + 0.13, rs(cseq, final, ok_reason if final == 200 else {403: "Forbidden", 404: "Not Found"}.get(final, "Error"), extra), from_b=True)
    return f


# ---------------------------------------------------------------------------------------------------------------
# Capturas limpas
# ---------------------------------------------------------------------------------------------------------------

@scenario("limpo01_chamada_normal_g711", "limpo", "Chamada normal G.711 com RTCP",
          "Ramal 1000 liga para 2000, toca, atende, fala 8 s com RTP nos dois sentidos, RTCP e desliga com BYE.")
def _():
    return call("limpo01@lab", T0, talk=8.0, rtcp=True)


@scenario("limpo02_varias_chamadas_codecs", "limpo", "Várias chamadas G.729, G.711a e G.722",
          "Quatro chamadas simultâneas por um PBX com codecs diferentes, todas atendidas e encerradas normalmente.")
def _():
    f = []
    for i, codec in enumerate(("G729", "PCMA", "G722", "G729")):
        f += call(f"limpo02-{i}@lab", T0 + i * 0.7, a=f"10.0.1.{10 + i}", b="10.0.0.2", codec=codec, talk=5.0,
                  port_a=40000 + i * 2, port_b=50000 + i * 2, seed=20 + i)
    return f


@scenario("limpo03_sip_tcp", "limpo", "Chamada com SIP sobre TCP (INVITE segmentado)",
          "Sinalização por TCP com INVITE grande quebrado em dois segmentos TCP; a chamada completa normalmente.")
def _():
    long_sdp = sdp_body("10.0.0.1", 40000, "PCMU", extra_codecs=("PCMA", "G729", "G722")) + "a=x-filler:" + "x" * 1200 + "\r\n"
    return call("limpo03@lab", T0, transport="TCP", sdp_a=long_sdp, talk=4.0)


@scenario("limpo04_ipv6", "limpo", "Chamada em IPv6", "Chamada completa entre dois endereços IPv6 globais.")
def _():
    return call("limpo04@lab", T0, a="2001:db8:10::1", b="2001:db8:20::2", v6=True, talk=4.0)


@scenario("limpo05_vlan", "limpo", "Chamada em VLAN de voz", "Pacotes com tag 802.1Q (VLAN 110), como numa porta espelhada de switch.")
def _():
    return call("limpo05@lab", T0, vlan=110, talk=4.0)


@scenario("limpo06_espera_e_retorno", "limpo", "Chamada colocada em espera e retomada",
          "Durante a conversa o ramal coloca em espera (re-INVITE sendonly), fica 4 s sem enviar áudio e retoma (sendrecv).",
          expect=("SIP_HOLD",))
def _():
    d = Dialog("limpo06@lab")
    f = call("limpo06@lab", T0, talk=2.0, bye=False, dlg=d, rtp_a=False, rtp_b=False)
    t = T0 + 1.8 + 0.05
    ma, mb = ("10.0.0.1", 40000), ("10.0.0.2", 50000)
    ra, rb = random.Random(61), random.Random(62)
    # Talk 2 s, hold 4 s (A stops sending, B sends music on hold), resume 2 s. Same SSRC and sequence across hold.
    f += media(ma[0], mb[0], ma[1], mb[1], t, 2.0, 6101, rng=ra, seq0=100)
    f += media(mb[0], ma[0], mb[1], ma[1], t, 8.0, 6102, rng=rb, seq0=500)
    f += d.wire(t + 2.0, d.req("INVITE", 2, body=sdp_body("10.0.0.1", 40000, direction="sendonly")))
    f += d.wire(t + 2.05, d.resp(200, "OK", 2, body=sdp_body("10.0.0.2", 50000, direction="recvonly")), from_b=True)
    f += d.wire(t + 2.08, d.req("ACK", 2))
    f += d.wire(t + 6.0, d.req("INVITE", 3, body=sdp_body("10.0.0.1", 40000)))
    f += d.wire(t + 6.05, d.resp(200, "OK", 3, body=sdp_body("10.0.0.2", 50000)), from_b=True)
    f += d.wire(t + 6.08, d.req("ACK", 3))
    f += media(ma[0], mb[0], ma[1], mb[1], t + 6.1, 1.9, 6101, rng=random.Random(63), seq0=200)
    f += d.wire(t + 8.1, d.req("BYE", 4))
    f += d.wire(t + 8.15, d.resp(200, "OK", 4, method="BYE"), from_b=True)
    return f


@scenario("limpo07_dtmf_rfc2833", "limpo", "Chamada com DTMF RFC 2833 (URA)",
          "Chamada para uma URA em que o cliente digita 1, 2 e # por telephone-event, no mesmo fluxo RTP do áudio.",
          check=lambda r: [] if any(s.dtmf_digits == "12#" for s in r.rtp_streams) else ["dígitos DTMF não lidos"])
def _():
    f = call("limpo07@lab", T0, talk=6.0, rtp_a=False, seed=7)
    t0 = T0 + 1.8 + 0.05
    events = {100 + k * 50 + j: (digit, j) for k, digit in enumerate((1, 2, 11)) for j in range(4)}
    for i in range(300):
        seq, t = 1000 + i, t0 + i * 0.02
        if i in events:
            digit, j = events[i]
            start = i - j
            payload = struct.pack("!BBHII", 0x80 | 0, (0x80 if j == 0 else 0) | 101, seq, 160 * start, 7001) \
                + struct.pack("!BBH", digit, (0x80 if j == 3 else 0) | 10, 160 * (j + 1))
        else:
            payload = struct.pack("!BBHII", 0x80, 0, seq, 160 * i, 7001) + b"\xd5" * 160
        f.append((t, udp_frame("10.0.0.1", "10.0.0.2", 40000, 50000, payload, 46)))
    return f


@scenario("limpo08_registros_com_desafio", "limpo", "Registros com desafio 401 (normal)",
          "Três aparelhos registram: primeiro REGISTER recebe 401, o segundo com credencial recebe 200 OK.")
def _():
    f = []
    for i in range(3):
        d = Dialog(f"limpo08-{i}@lab", a=f"10.0.2.{20 + i}", b="10.0.0.2", from_user=str(3000 + i))
        f += register(d, T0 + i * 0.5)
    return f


@scenario("limpo09_invite_com_407", "limpo", "INVITE com autenticação de proxy (407)",
          "O PBX desafia o INVITE com 407, o aparelho reenvia com credencial e a chamada completa.")
def _():
    d = Dialog("limpo09@lab")
    f = d.wire(T0, d.req("INVITE", 1, body=sdp_body(d.a, 40000), to_tag=False))
    f += d.wire(T0 + 0.02, d.resp(407, "Proxy Authentication Required", 1, extra=[("Proxy-Authenticate", 'Digest realm="pbx", nonce="n1"')]), from_b=True)
    f += d.wire(T0 + 0.04, d.req("ACK", 1))
    d2 = Dialog("limpo09@lab")
    auth = [("Proxy-Authorization", 'Digest username="1000", realm="pbx", nonce="n1", uri="sip:2000@10.0.0.2", response="abc"')]
    return f + call("limpo09@lab", T0 + 0.1, dlg=_Cseq(d2, 2), extra_invite=auth, talk=3.0)


class _Cseq:
    """Wraps a Dialog so the INVITE transaction of call() uses a later CSeq (retry after a challenge)."""

    def __init__(self, d, base):
        self.d, self.base = d, base

    def __getattr__(self, k):
        return getattr(self.d, k)

    def req(self, method, cseq, **kw):
        return self.d.req(method, cseq + self.base - 1, **kw)

    def resp(self, code, reason, cseq, **kw):
        return self.d.resp(code, reason, cseq + self.base - 1, **kw)


@scenario("limpo10_cancelada", "limpo", "Chamada cancelada pelo originador",
          "O telefone toca e quem ligou desiste: CANCEL, 200 OK e 487 Request Terminated. Não é falha de rede.")
def _():
    d = Dialog("limpo10@lab")
    f = d.wire(T0, d.req("INVITE", 1, body=sdp_body(d.a, 40000), to_tag=False))
    f += d.wire(T0 + 0.3, d.resp(180, "Ringing", 1), from_b=True)
    f += d.wire(T0 + 6.0, d.req("CANCEL", 1, to_tag=False))
    f += d.wire(T0 + 6.02, d.resp(200, "OK", 1, method="CANCEL"), from_b=True)
    f += d.wire(T0 + 6.03, d.resp(487, "Request Terminated", 1), from_b=True)
    f += d.wire(T0 + 6.05, d.req("ACK", 1))
    return f


@scenario("limpo11_ocupado_e_nao_atende", "limpo", "Ocupado (486) e não atende (480)",
          "Uma chamada recebe 486 Busy Here e outra toca até 480 Temporarily Unavailable. São comportamentos do usuário, não da rede.",
          expect=("SIP_FINAL_FAILURE",),
          check=lambda r: [] if all(d.severity == "info" for d in r.diagnostics) else ["ocupado/não atende não pode ser alerta"])
def _():
    return (failed_call("limpo11-a@lab", T0, 486, "Busy Here", extra=[("Reason", 'Q.850;cause=17;text="User busy"')])
            + failed_call("limpo11-b@lab", T0 + 2, 480, "Temporarily Unavailable", ring=True, to_user="2001"))


@scenario("limpo12_transferencia", "limpo", "Transferência assistida (REFER)",
          "Durante a chamada o ramal transfere com REFER, recebe 202 Accepted e NOTIFY 200.", expect=("SIP_TRANSFER",))
def _():
    d = Dialog("limpo12@lab")
    f = call("limpo12@lab", T0, dlg=d, talk=4.0, bye=False)
    t = T0 + 1.8 + 4.1
    f += d.wire(t, d.req("REFER", 2, extra=[("Refer-To", "<sip:3000@pbx.exemplo.com.br>"), ("Referred-By", "<sip:1000@pbx.exemplo.com.br>")]))
    f += d.wire(t + 0.03, d.resp(202, "Accepted", 2, method="REFER"), from_b=True)
    f += d.wire(t + 0.5, d.req("NOTIFY", 1, from_b=True, extra=[("Event", "refer"), ("Subscription-State", "terminated")]), from_b=True)
    f += d.wire(t + 0.52, d.resp(200, "OK", 1, method="NOTIFY", to_b=True), from_b=False)
    f += d.wire(t + 0.6, d.req("BYE", 3))
    f += d.wire(t + 0.62, d.resp(200, "OK", 3, method="BYE"), from_b=True)
    return f


@scenario("limpo13_muitas_chamadas_simultaneas", "limpo", "Pico legítimo: 45 chamadas simultâneas",
          "45 chamadas G.729 ao mesmo tempo no mesmo PBX (mais de 2.000 pacotes/s de RTP). É tráfego legítimo: não pode virar alerta de DDoS.")
def _():
    f = []
    for i in range(45):
        f += call(f"limpo13-{i}@lab", T0 + i * 0.02, a=f"10.0.3.{10 + i}", codec="G729", talk=5.0, port_a=40000 + 2 * i,
                  port_b=20000 + 2 * i, seed=100 + i, pdd_s=0.2, ring_s=0.5)
    return f


@scenario("limpo14_mensagem_malformada", "limpo", "Lixo e SIP malformado na porta 5060",
          "Pacotes quebrados e texto que não é SIP chegam na 5060 no meio de uma chamada normal. O analisador não pode travar nem inventar chamadas.")
def _():
    f = call("limpo14@lab", T0, talk=3.0)
    junk = [b"\x00\x01garbage\xff" * 5, b"HELLO WORLD\r\n\r\n", b"INVITE\r\n", b"SIP/2.0\r\n", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 999\r\n\r\nabc"]
    for i, j in enumerate(junk):
        f.append((T0 + 0.5 + i * 0.1, udp_frame("198.51.100.77", "10.0.0.2", 5060, 5060, j)))
    return f


# ---------------------------------------------------------------------------------------------------------------
# Sinalização SIP
# ---------------------------------------------------------------------------------------------------------------

@scenario("sip01_invite_sem_resposta", "sinalizacao", "INVITE sem nenhuma resposta",
          "O aparelho manda INVITE para um destino que não responde nada (nem 100 Trying) e retransmite por 32 s.",
          expect=("SIP_NO_RESPONSE",), allow=("SIP_RETRANSMISSIONS",))
def _():
    d = Dialog("sip01@lab", b="10.0.0.99")
    f, t, iv = [], T0, 0.5
    for _ in range(7):
        f += d.wire(t, d.req("INVITE", 1, body=sdp_body(d.a, 40000), to_tag=False))
        t += iv; iv = min(iv * 2, 4.0)
    f.append((T0 + 36.0, udp_frame("10.0.0.1", "10.0.0.2", 5060, 5060, Dialog("sip01-keep@lab").req("OPTIONS", 1, to_tag=False))))
    return f


@scenario("sip02_ack_perdido_queda_32s", "sinalizacao", "ACK não chega: chamada cai em 32 s",
          "O 200 OK é respondido, mas o ACK nunca chega ao destino. O destino retransmite o 200 OK e derruba a chamada com BYE aos ~32 s.",
          expect=("SIP_MISSING_ACK", "SIP_DROP_32S"), allow=("SIP_RETRANSMISSIONS",))
def _():
    d = Dialog("sip02@lab")
    f = call("sip02@lab", T0, dlg=d, ack=False, bye=False, codec="G729", talk=32.0)
    t_ans = T0 + 1.8
    for k, dt in enumerate((0.5, 1.5, 3.5, 7.5, 11.5, 15.5, 19.5)):
        f += d.wire(t_ans + dt, d.resp(200, "OK", 1, body=sdp_body(d.b, 50000, "G729")), from_b=True)
    f += d.wire(t_ans + 32.1, d.req("BYE", 1, from_b=True, extra=[("Reason", 'SIP;cause=408;text="ACK timeout"')]), from_b=True)
    f += d.wire(t_ans + 32.15, d.resp(200, "OK", 1, method="BYE", to_b=True))
    return f


def _fail(sid, code, reason, title, what, expect=("SIP_FINAL_FAILURE",), extra=(), allow=(), check=None):
    @scenario(sid, "sinalizacao", title, what, expect=expect, allow=allow, check=check)
    def _():
        return failed_call(f"{sid}@lab", T0, code, reason, extra=extra)


_fail("sip03_numero_inexistente_404", 404, "Not Found", "Número inexistente (404)", "O tronco responde 404 Not Found para o número discado.")
_fail("sip04_recusada_403", 403, "Forbidden", "Chamada recusada (403)", "O PBX recusa a chamada com 403 Forbidden (sem permissão, bloqueio ou saldo).")
_fail("sip05_erro_servidor_503", 503, "Service Unavailable", "Tronco indisponível (503)",
      "A operadora responde 503 Service Unavailable com Retry-After: rota sem capacidade.", extra=[("Retry-After", "30")],
      check=lambda r: [] if any(d.severity == "critical" and d.code == "SIP_FINAL_FAILURE" for d in r.diagnostics) else ["503 deveria ser crítico"])
_fail("sip06_timeout_408", 408, "Request Timeout", "Timeout de transação (408)", "Um proxy no caminho devolve 408 porque o próximo salto não respondeu.")
_fail("sip07_codec_incompativel_488", 488, "Not Acceptable Here", "Codec incompatível (488)",
      "O destino só aceita G.729 e o INVITE oferece só G.711: 488 Not Acceptable Here.",
      check=lambda r: [] if r.calls[0].outcome == "media_negotiation_failed" else [f"outcome {r.calls[0].outcome}"])
_fail("sip08_loop_483", 483, "Too Many Hops", "Loop de roteamento (483)", "A chamada fica girando entre dois servidores até estourar o Max-Forwards: 483 Too Many Hops.")


@scenario("sip09_senha_errada_invite", "sinalizacao", "Senha errada no INVITE (407 repetido)",
          "O tronco desafia com 407, o aparelho responde com credencial errada e recebe 407 de novo, duas vezes, até desistir.",
          expect=("SIP_AUTH_LOOP", "SIP_FINAL_FAILURE"))
def _():
    d = Dialog("sip09@lab")
    f = []
    auth = [("Proxy-Authorization", 'Digest username="1000", realm="pbx", nonce="n", uri="sip:2000@10.0.0.2", response="bad"')]
    for k in range(3):
        f += d.wire(T0 + k * 0.2, d.req("INVITE", k + 1, body=sdp_body(d.a, 40000), to_tag=False, extra=auth if k else ()))
        f += d.wire(T0 + k * 0.2 + 0.02, d.resp(407, "Proxy Authentication Required", k + 1, extra=[("Proxy-Authenticate", 'Digest realm="pbx", nonce="n"')]), from_b=True)
        f += d.wire(T0 + k * 0.2 + 0.04, d.req("ACK", k + 1))
    return f


@scenario("sip10_pdd_alto", "sinalizacao", "Pós-discagem alto (12 s até tocar)",
          "A rota demora 12 s para devolver 180 Ringing: o cliente acha que a ligação não completou.", expect=("SIP_HIGH_PDD",))
def _():
    return call("sip10@lab", T0, pdd_s=12.0, ring_s=2.0, talk=3.0)


@scenario("sip11_retransmissoes", "sinalizacao", "Retransmissões SIP (link com perda)",
          "O INVITE e o 200 OK precisam ser reenviados várias vezes antes de passar; a chamada completa mas demora.",
          expect=("SIP_RETRANSMISSIONS",))
def _():
    d = Dialog("sip11@lab")
    f = d.wire(T0, d.req("INVITE", 1, body=sdp_body(d.a, 40000), to_tag=False))
    f += d.wire(T0 + 0.5, d.req("INVITE", 1, body=sdp_body(d.a, 40000), to_tag=False))
    f += d.wire(T0 + 1.5, d.req("INVITE", 1, body=sdp_body(d.a, 40000), to_tag=False))
    f += call("sip11@lab", T0 + 1.52, dlg=_Skip(d), talk=3.0, pdd_s=0.3)
    t_ans = T0 + 1.52 + 1.8
    f += d.wire(t_ans + 0.5, d.resp(200, "OK", 1, body=sdp_body(d.b, 50000)), from_b=True)
    return f


class _Skip:
    """Dialog wrapper whose first INVITE is not sent again (the scenario already sent it)."""

    def __init__(self, d):
        self.d, self.first = d, True

    def __getattr__(self, k):
        return getattr(self.d, k)

    def wire(self, t, payload, from_b=False):
        if self.first and payload.startswith(b"INVITE"):
            self.first = False
            return []
        return self.d.wire(t, payload, from_b)


@scenario("sip12_session_timer", "sinalizacao", "Queda no session timer (90 s)",
          "A chamada negocia Session-Expires 90 s, ninguém faz o refresh e o destino derruba a chamada aos 90 s.",
          expect=("SIP_SESSION_TIMER_DROP",))
def _():
    return call("sip12@lab", T0, codec="G729", talk=90.0, bye_from_b=True,
                extra_invite=[("Session-Expires", "90;refresher=uac"), ("Supported", "timer")],
                extra_200=[("Session-Expires", "90;refresher=uac"), ("Require", "timer")])


@scenario("sip13_registro_senha_errada", "sinalizacao", "Registro com senha errada",
          "O ramal registra, recebe 401, reenvia com credencial e leva 403 Forbidden: senha errada.", expect=("REGISTER_FAILED",))
def _():
    return register(Dialog("sip13@lab", a="10.0.2.50", from_user="4001"), T0, final=403)


@scenario("sip14_registro_sem_resposta", "sinalizacao", "Registrar não responde",
          "O ramal manda REGISTER e retransmite, mas o servidor de registro não responde nada.", expect=("REGISTER_NO_RESPONSE",))
def _():
    d = Dialog("sip14@lab", a="10.0.2.60", b="10.0.0.9", from_user="4002")
    f = []
    for k, dt in enumerate((0, 0.5, 1.5, 3.5, 7.5)):
        f += register(d, T0 + dt, final=None, challenge=False)
    return f


@scenario("sip15_icmp_porta_fechada", "sinalizacao", "Destino devolve ICMP porta inalcançável",
          "O INVITE vai para um servidor com o serviço SIP parado; o host devolve ICMP port unreachable a cada tentativa.",
          expect=("ICMP_UNREACHABLE", "SIP_NO_RESPONSE"), allow=("SIP_RETRANSMISSIONS",))
def _():
    d = Dialog("sip15@lab", b="10.0.0.30")
    f, t, iv = [], T0, 0.5
    for _ in range(4):
        inv = d.req("INVITE", 1, body=sdp_body(d.a, 40000), to_tag=False)
        f += d.wire(t, inv)
        quoted = ipv4("10.0.0.1", "10.0.0.30", udp_datagram(5060, 5060, inv))[:28]
        icmp = struct.pack("!BBHI", 3, 3, 0, 0) + quoted
        f.append((t + 0.001, ether(ipv4("10.0.0.30", "10.0.0.1", icmp, proto=1))))
        t += iv; iv *= 2
    return f


@scenario("sip16_invite_fragmentado_perdido", "sinalizacao", "INVITE grande fragmentado com fragmento perdido",
          "O INVITE (SDP enorme) passa de 1500 bytes e é fragmentado em IP; o segundo fragmento se perde sempre e a chamada não completa.",
          expect=("IP_FRAGMENTS_LOST",), allow=("SIP_NO_RESPONSE", "SIP_RETRANSMISSIONS"))
def _():
    d = Dialog("sip16@lab")
    body = sdp_body("10.0.0.1", 40000, extra_codecs=("PCMA", "G729", "G722")) + "a=x-filler:" + "y" * 1600 + "\r\n"
    f = []
    for k in range(3):
        inv = d.req("INVITE", 1, body=body, to_tag=False)
        l4 = udp_datagram(5060, 5060, inv)
        first = l4[:1480]
        f.append((T0 + k * 0.5, ether(ipv4("10.0.0.1", "10.0.0.2", first, ident=700 + k, more=True))))
    return f


# ---------------------------------------------------------------------------------------------------------------
# Mídia / qualidade
# ---------------------------------------------------------------------------------------------------------------

@scenario("midia01_perda_3pct", "midia", "Perda de pacotes de 3%", "Link com 3% de perda aleatória nos dois sentidos.",
          expect=("RTP_PACKET_LOSS",))
def _():
    return call("midia01@lab", T0, talk=10.0, kw_a={"loss": 0.03}, kw_b={"loss": 0.03}, seed=11)


@scenario("midia02_perda_rajada_12pct", "midia", "Perda de 12% em rajadas (voz robotizada)",
          "Perda em rajadas de 4 pacotes (Wi-Fi ruim ou link saturado). O MOS despenca.",
          expect=("RTP_PACKET_LOSS", "LOW_MOS"))
def _():
    return call("midia02@lab", T0, talk=10.0, kw_a={"loss": 0.12, "burst": 4}, kw_b={"loss": 0.12, "burst": 4}, seed=12)


@scenario("midia03_jitter_alto", "midia", "Jitter alto (~60 ms)", "Rede congestionada: os pacotes chegam com variação de atraso grande.",
          expect=("RTP_JITTER",), allow=("RTP_PACKET_LOSS", "RTP_REORDER"))
def _():
    return call("midia03@lab", T0, talk=8.0, kw_a={"jitter_ms": 70}, kw_b={"jitter_ms": 70}, seed=13)


@scenario("midia04_audio_unidirecional", "midia", "Áudio em só uma direção",
          "A chamada completa, mas só o originador envia RTP; o outro lado não manda áudio (ACL ou roteamento).",
          expect=("ONE_WAY_AUDIO",))
def _():
    return call("midia04@lab", T0, talk=6.0, rtp_b=False)


@scenario("midia05_sem_audio", "midia", "Chamada atendida sem nenhum áudio", "200 OK e ACK normais, mas nenhum RTP em nenhum sentido.",
          expect=("NO_RTP_AFTER_ANSWER",))
def _():
    return call("midia05@lab", T0, talk=6.0, rtp_a=False, rtp_b=False)


@scenario("midia06_audio_picotando", "midia", "Áudio picotando (quedas de 1 s)",
          "Duas quedas de rede de ~1 s durante a conversa: o usuário ouve buracos no áudio.",
          expect=("RTP_GAP",), allow=("RTP_PACKET_LOSS", "LOW_MOS"))
def _():
    return call("midia06@lab", T0, talk=10.0, kw_a={"outage": (3.0, 1.0)}, kw_b={"outage": (6.0, 1.2)}, seed=16)


@scenario("midia07_payload_nao_negociado", "midia", "Codec enviado diferente do negociado",
          "O SDP negocia G.711 (PT 0), mas um lado manda G.729 (PT 18): do outro lado o áudio fica mudo ou ruído.",
          expect=("RTP_PT_NOT_NEGOTIATED",))
def _():
    return call("midia07@lab", T0, talk=5.0, kw_b={"pt": 18})


@scenario("midia08_rtp_apos_bye", "midia", "RTP continua depois do BYE",
          "A chamada é encerrada, mas o gateway continua mandando áudio por 5 s (mídia presa).", expect=("RTP_AFTER_BYE",))
def _():
    return call("midia08@lab", T0, talk=4.0, rtp_after_bye=5.0)


@scenario("midia09_audio_atrasado", "midia", "Áudio começa 3 s depois de atender",
          "O primeiro RTP só aparece 3 s depois do 200 OK: o começo da conversa é cortado.", expect=("MEDIA_START_DELAY",))
def _():
    return call("midia09@lab", T0, talk=5.0, media_delay=3.0)


@scenario("midia10_sem_qos", "midia", "Voz sem marcação de QoS (DSCP 0)",
          "RTP e SIP saem com DSCP 0 (best effort) em vez de EF/CS3: sem prioridade em link congestionado.",
          expect=("RTP_DSCP", "SIP_DSCP"))
def _():
    f = call("midia10@lab", T0, talk=5.0, dscp=0, sip_dscp=0)
    f += call("midia10b@lab", T0 + 1, talk=4.0, dscp=0, sip_dscp=0, port_a=40002, port_b=50002, seed=2)
    return f


@scenario("midia11_perda_depois_da_captura", "midia", "Perda vista só pelo receptor (RTCP)",
          "Na captura não falta nenhum pacote, mas o RTCP do receptor informa 9% de perda: a perda acontece depois do ponto de captura.",
          expect=("RTCP_REMOTE_LOSS",))
def _():
    f = call("midia11@lab", T0, talk=10.0, ssrc_a=1111, ssrc_b=2222)
    for k in range(1, 3):
        f.append((T0 + 1.85 + 5 * k, udp_frame("10.0.0.2", "10.0.0.1", 50001, 40001, rtcp_rr(2222, 1111, fraction=23, cumulative=40 * k), 46)))
    return f


@scenario("midia12_troca_ssrc", "midia", "Troca de SSRC no meio da chamada",
          "O gateway troca o SSRC do fluxo no meio da chamada sem re-INVITE; alguns aparelhos silenciam o áudio.", expect=("RTP_SSRC_CHANGE",))
def _():
    f = call("midia12@lab", T0, talk=3.0, bye=False)
    f += media("10.0.0.2", "10.0.0.1", 50000, 40000, T0 + 1.85 + 3.0, 3.0, 777777, rng=random.Random(5))
    d = Dialog("midia12@lab")
    f += d.wire(T0 + 8.0, d.req("BYE", 2)) + d.wire(T0 + 8.05, d.resp(200, "OK", 2, method="BYE"), from_b=True)
    return f


@scenario("midia13_duplicados", "midia", "Pacotes RTP duplicados", "Um espelhamento mal configurado duplica 1 em cada 10 pacotes RTP.",
          expect=("RTP_DUPLICATES",))
def _():
    return call("midia13@lab", T0, talk=5.0, kw_a={"dup_every": 10})


@scenario("midia14_g729_perda_mos_ruim", "midia", "G.729 com 5% de perda (MOS ruim)",
          "Codec comprimido é mais sensível: 5% de perda em G.729 já deixa a voz ruim.", expect=("RTP_PACKET_LOSS", "LOW_MOS"))
def _():
    return call("midia14@lab", T0, codec="G729", talk=10.0, kw_a={"loss": 0.06, "burst": 2}, kw_b={"loss": 0.06, "burst": 2}, seed=14)


# ---------------------------------------------------------------------------------------------------------------
# NAT
# ---------------------------------------------------------------------------------------------------------------

@scenario("nat01_sem_rport_expires_longo", "nat", "Aparelho atrás de NAT sem rport e com registro de 1 h",
          "Telefone 192.168.1.10 atrás do roteador 177.10.0.5 registra por UDP com expires 3600 e sem ;rport.",
          expect=("DEVICE_BEHIND_NAT", "NAT_NO_RPORT", "NAT_REGISTER_EXPIRES_TOO_LONG"))
def _():
    d = Dialog("nat01@lab", a="192.168.1.10", b="200.10.0.5", sig_src="177.10.0.5", rport=False, from_user="5001")
    return register(d, T0, expires=3600)


@scenario("nat02_sip_alg_content_length", "nat", "SIP ALG corrompendo o Content-Length",
          "O roteador do cliente reescreve o SDP (troca o IP) e não corrige o Content-Length.", expect=("SIP_ALG_CONTENT_LENGTH",),
          allow=("DEVICE_BEHIND_NAT", "NAT_PRIVATE_SDP", "SIP_FINAL_FAILURE"))
def _():
    d = Dialog("nat02@lab", a="192.168.1.10", b="200.10.0.5", sig_src="177.10.0.5")
    inv = d.req("INVITE", 1, body=sdp_body("192.168.1.10", 40000), to_tag=False)
    inv = inv.replace(b"c=IN IP4 192.168.1.10", b"c=IN IP4 177.10.0.5").replace(b"o=- 20 1 IN IP4 192.168.1.10", b"o=- 20 1 IN IP4 177.10.0.5")
    f = d.wire(T0, inv)
    f += d.wire(T0 + 0.05, d.resp(100, "Trying", 1, to_tag=False), from_b=True)
    f += d.wire(T0 + 0.1, d.resp(488, "Not Acceptable Here", 1), from_b=True)
    f += d.wire(T0 + 0.12, d.req("ACK", 1))
    return f


@scenario("nat03_sip_alg_sdp", "nat", "SIP ALG reescrevendo o SDP pela metade",
          "O ALG troca o c= pelo IP público mas deixa o o= com o IP privado: assinatura de ALG no caminho.",
          expect=("SIP_ALG_SDP_REWRITE",), allow=("DEVICE_BEHIND_NAT",))
def _():
    return call("nat03@lab", T0, a="192.168.1.10", b="200.10.0.5", sig_src="177.10.0.5", talk=4.0,
                sdp_a=sdp_body("177.10.0.5", 40000, origin_ip="192.168.1.10"), media_a=("177.10.0.5", 40000))


@scenario("nat04_ip_privado_sdp_audio_mudo", "nat", "IP privado no SDP: cliente não ouve nada",
          "Telefone atrás de NAT anuncia 192.168.1.10 no SDP; o PBX manda o áudio para esse IP privado e ele nunca chega.",
          expect=("NAT_PRIVATE_SDP", "NAT_ONE_WAY_AUDIO", "ONE_WAY_AUDIO"), allow=("DEVICE_BEHIND_NAT", "NAT_MEDIA_SOURCE_MISMATCH"))
def _():
    return call("nat04@lab", T0, a="192.168.1.10", b="200.10.0.5", sig_src="177.10.0.5", talk=5.0, rtp_b=False,
                media_a=("177.10.0.5", 40000))


@scenario("nat05_cgnat", "nat", "Cliente em CGNAT da operadora", "O aparelho sai por um endereço 100.64.x.x (CGNAT): difícil receber chamadas.",
          expect=("DEVICE_BEHIND_NAT",))
def _():
    d = Dialog("nat05@lab", a="192.168.0.30", b="200.10.0.5", sig_src="100.72.14.9", from_user="5002")
    return register(d, T0, expires=60)


@scenario("nat06_rtp_porta_trocada", "nat", "RTP chegando de porta diferente da anunciada",
          "O NAT troca a porta de origem do RTP (40000 vira 61012). O PBX precisa responder para onde o RTP chega (comedia).",
          expect=("NAT_MEDIA_SOURCE_MISMATCH", "MEDIA_DEST_MISMATCH"), allow=("DEVICE_BEHIND_NAT", "NAT_PRIVATE_SDP"))
def _():
    return call("nat06@lab", T0, a="177.10.0.5", b="200.10.0.5", talk=4.0, media_a=("177.10.0.5", 61012))


# ---------------------------------------------------------------------------------------------------------------
# Segurança SIP
# ---------------------------------------------------------------------------------------------------------------

@scenario("seg01_scanner_sipvicious", "seguranca", "Varredura com friendly-scanner (SIPVicious)",
          "Um IP da internet manda OPTIONS com User-Agent friendly-scanner para 40 servidores da rede.",
          expect=("SEC_SCANNER", "SEC_OPTIONS_SWEEP"), allow=("SEC_SCAN", "SEC_RATE"))
def _():
    f = []
    for i in range(40):
        d = Dialog(f"seg01-{i}@lab", a="45.95.147.10", b=f"200.10.1.{i + 1}", ua_a="friendly-scanner", from_user="100")
        f += d.wire(T0 + i * 0.2, d.req("OPTIONS", 1, to_tag=False, uri_user=f"{i}"))
    return f


@scenario("seg02_forca_bruta_register", "seguranca", "Força bruta de senha em REGISTER",
          "Um atacante testa 60 senhas para o ramal 100 em 30 s; o PBX responde 403 a todas.", expect=("SEC_BRUTE_FORCE",))
def _():
    f = []
    for i in range(60):
        d = Dialog(f"seg02-{i}@lab", a="185.22.10.9", b="200.10.0.5", from_user="100", ua_a="PolycomVVX-VVX_410-UA/5.9.0")
        f += register(d, T0 + i * 0.5, final=403, challenge=False)
    return f


@scenario("seg03_enumeracao_ramais", "seguranca", "Enumeração de ramais",
          "O atacante tenta registrar os ramais 100 a 139 sem senha; os que não existem recebem 404.",
          expect=("SEC_ENUMERATION",), allow=("SEC_SCAN",))
def _():
    f = []
    for i in range(40):
        d = Dialog(f"seg03-{i}@lab", a="92.118.39.5", b="200.10.0.5", from_user=str(100 + i), ua_a="Z 5.6.1")
        f += register(d, T0 + i * 0.3, final=404, challenge=False)
    return f


@scenario("seg04_fraude_internacional", "seguranca", "Fraude internacional (IRSF)",
          "Uma conta comprometida liga para 8 destinos internacionais caros em sequência; três atendem.",
          expect=("SEC_TOLL_FRAUD",), allow=("SIP_FINAL_FAILURE", "NAT_PRIVATE_SDP"))
def _():
    f = []
    for i, num in enumerate(("0088213400", "00972592000", "00423663000", "0022470000", "0025290000", "00882160000", "0037259000", "0024510000")):
        if i < 3:
            f += call(f"seg04-{i}@lab", T0 + i * 6, a="10.0.5.5", b="187.50.0.1", to_user=num, talk=3.0, port_a=40000 + 2 * i,
                      port_b=30000 + 2 * i, seed=40 + i)
        else:
            f += failed_call(f"seg04-{i}@lab", T0 + i * 6, 480, "Temporarily Unavailable", a="10.0.5.5", b="187.50.0.1", to_user=num)
    return f


@scenario("seg05_flood_invite", "seguranca", "Flood de INVITE de uma origem",
          "Uma origem manda 300 INVITE em 10 s para números aleatórios; o PBX responde 404 a todos.",
          expect=("SEC_RATE",), allow=("SEC_SCAN", "SEC_ENUMERATION"),
          check=lambda r: [] if sum(1 for d in r.diagnostics if d.code == "SIP_FINAL_FAILURE") == 0
          else ["cada INVITE do atacante virou um diagnóstico de chamada (ruído)"])
def _():
    f = []
    for i in range(300):
        d = Dialog(f"seg05-{i}@lab", a="141.98.11.20", b="200.10.0.5", to_user=f"55119{i:06d}", ua_a="Asterisk PBX 16.2")
        f += d.wire(T0 + i / 30, d.req("INVITE", 1, body=sdp_body("141.98.11.20", 40000), to_tag=False))
        f += d.wire(T0 + i / 30 + 0.01, d.resp(404, "Not Found", 1), from_b=True)
    return f


# ---------------------------------------------------------------------------------------------------------------
# DDoS / floods
# ---------------------------------------------------------------------------------------------------------------

def _syn(src, dst, sport, dport):
    return ether(ipv4(src, dst, struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x02, 65535, 0, 0), proto=6))


@scenario("ddos01_syn_flood", "ddos", "SYN flood na porta SIP/TLS 5061", "1.200 SYN/s por 4 s contra o SBC vindos de 200 IPs forjados.",
          expect=("SYN_FLOOD",))
def _():
    f = call("ddos01@lab", T0, a="10.0.0.1", b="10.0.0.2", talk=8.0, codec="G729")
    for i in range(4800):
        f.append((T0 + 2.0 + i / 1200, _syn(f"91.{i % 200}.3.{i % 250 + 1}", "10.0.0.2", 10000 + i % 50000, 5061)))
    return f


@scenario("ddos02_udp_flood_distribuido", "ddos", "DDoS UDP distribuído com voz picotando",
          "3.000 pacotes UDP/s de 120 origens contra o PBX por 4 s; a chamada em curso perde pacotes.",
          expect=("DDOS_VOLUMETRIC",), allow=("RTP_PACKET_LOSS", "LOW_MOS", "RTP_GAP"))
def _():
    f = call("ddos02@lab", T0, talk=8.0, codec="G729", kw_a={"outage": (3.0, 0.4), "loss": 0.05}, seed=22)
    rng = random.Random(22)
    for i in range(12000):
        f.append((T0 + 3.0 + i / 3000, udp_frame(f"103.{i % 120}.{rng.randrange(256)}.7", "10.0.0.2", rng.randrange(1024, 65535), 5060 + i % 3, b"\x00" * 18)))
    return f


@scenario("ddos03_icmp_flood", "ddos", "ICMP flood", "1.000 pings/s por 4 s contra o roteador de borda.", expect=("ICMP_FLOOD",))
def _():
    f = []
    for i in range(4000):
        icmp = struct.pack("!BBHHH", 8, 0, 0, 1, i & 0xFFFF) + b"\x00" * 32
        f.append((T0 + i / 1000, ether(ipv4(f"77.{i % 60}.1.1", "200.10.0.1", icmp, proto=1))))
    return f


def _reflection(sid, port, service, size):
    @scenario(sid, "ddos", f"Reflexão/amplificação {service}",
              f"Respostas {service} (porta de origem {port}) de {size} bytes que o PBX nunca pediu chegam a 400/s: ataque de amplificação.",
              expect=("REFLECTION_AMPLIFICATION",),
              check=lambda r: [] if any(e.get("service") == service for e in r.ddos) else [f"serviço {service} não identificado"])
    def _():
        f = []
        for i in range(1600):
            f.append((T0 + i / 400, udp_frame(f"8.{i % 90}.4.{i % 200 + 1}", "200.10.0.5", port, 40000 + i % 5000, b"\xab" * size)))
        return f


_reflection("ddos04_reflexao_dns", 53, "DNS", 900)
_reflection("ddos05_reflexao_ntp", 123, "NTP", 468)


@scenario("ddos06_flood_sip_distribuido", "ddos", "Flood SIP distribuído (botnet)",
          "80 origens mandam REGISTER sem parar: 250 requisições/s por 4 s, o PBX nem consegue responder.",
          expect=("SIP_FLOOD_DISTRIBUTED",), allow=("REGISTER_FAILED", "REGISTER_NO_RESPONSE"))
def _():
    f = []
    for i in range(1000):
        d = Dialog(f"ddos06-{i}@lab", a=f"45.{i % 80}.9.9", b="200.10.0.5", from_user=str(i % 80 + 100), ua_a="Grandstream GXP1625")
        f += register(d, T0 + i / 250, final=None, challenge=False)
    return f


@scenario("ddos07_dos_uma_origem", "ddos", "Flood UDP de uma única origem", "Um único IP manda 2.500 pacotes/s por 4 s na porta 5060.",
          expect=("DOS_VOLUMETRIC",))
def _():
    f = []
    for i in range(10000):
        f.append((T0 + 1 + i / 2500, udp_frame("194.26.29.4", "200.10.0.5", 44444, 5060, b"\x00" * 10)))
    f.append((T0, udp_frame("10.0.0.1", "200.10.0.5", 5060, 5060, Dialog("ddos07-k@lab").req("OPTIONS", 1, to_tag=False))))
    f.append((T0 + 8, udp_frame("10.0.0.1", "200.10.0.5", 5060, 5060, Dialog("ddos07-k2@lab").req("OPTIONS", 1, to_tag=False))))
    return f


# ---------------------------------------------------------------------------------------------------------------
# WebRTC
# ---------------------------------------------------------------------------------------------------------------

BROWSER_PUB, BROWSER_LAN, PBX, TURN = "177.20.0.9", "192.168.0.20", "200.10.0.5", "200.10.0.50"
STUN_SRV = "74.125.250.129"
MDNS = "3f1c2a9e-5b7d-4c21-9e0a-7d3b2f6c1e44.local"


def webrtc_offer(ip, port, candidates, ufrag="brw1", video_port=None, plain=False):
    proto = "RTP/AVP" if plain else "UDP/TLS/RTP/SAVPF"
    lines = ["v=0", "o=- 4611731400430051336 2 IN IP4 127.0.0.1", "s=-", "t=0 0", "a=group:BUNDLE 0" + (" 1" if video_port else ""),
             "a=msid-semantic: WMS", f"m=audio {port} {proto} 111 0 8 126", f"c=IN IP4 {ip}", "a=rtcp:9 IN IP4 0.0.0.0"]
    lines += [f"a=candidate:{c}" for c in candidates]
    if not plain:
        lines += [f"a=ice-ufrag:{ufrag}", "a=ice-pwd:asd88fgpdd777uzjYhagZg", "a=ice-options:trickle",
                  "a=fingerprint:sha-256 7B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08",
                  "a=setup:actpass", "a=mid:0", "a=rtcp-mux"]
    lines += ["a=sendrecv", "a=rtpmap:111 opus/48000/2", "a=fmtp:111 minptime=10;useinbandfec=1", "a=rtpmap:0 PCMU/8000",
              "a=rtpmap:8 PCMA/8000", "a=rtpmap:126 telephone-event/8000"]
    if video_port:
        lines += [f"m=video {video_port} {proto} 96", f"c=IN IP4 {ip}", "a=mid:1", "a=rtcp-mux", "a=sendrecv", "a=rtpmap:96 VP8/90000"]
    return "\r\n".join(lines) + "\r\n"


def webrtc_answer(ip, port, ufrag="pbx1", plain=False, video=False, ice=True):
    proto = "RTP/AVP" if plain else "UDP/TLS/RTP/SAVPF"
    lines = ["v=0", f"o=- 1717171717 1 IN IP4 {ip}", "s=Asterisk", f"c=IN IP4 {ip}", "t=0 0", f"m=audio {port} {proto} 111 126" if not plain else f"m=audio {port} RTP/AVP 0 101"]
    if not plain:
        if ice:
            lines += [f"a=ice-ufrag:{ufrag}", "a=ice-pwd:0b3c6ed64e21a1d6aa6e5a8f", f"a=candidate:H1 1 UDP 2130706431 {ip} {port} typ host"]
        lines += ["a=fingerprint:sha-256 1D:22:0F:9A:5E:21:88:40:C2:7F:94:AE:12:0B:6C:77:35:9D:E1:0A:BF:63:28:44:9C:11:70:2E:D5:6B:A3:0E",
                  "a=setup:passive", "a=mid:0", "a=rtcp-mux", "a=rtpmap:111 opus/48000/2", "a=rtpmap:126 telephone-event/8000"]
    else:
        lines += ["a=rtpmap:0 PCMU/8000", "a=rtpmap:101 telephone-event/8000"]
    lines.append("a=sendrecv")
    if video and not plain:
        lines += [f"m=video {port} {proto} 96", "a=mid:1", "a=rtcp-mux", "a=sendrecv", "a=rtpmap:96 VP8/90000"]
    return "\r\n".join(lines) + "\r\n"


class WebRtc:
    """A browser (JsSIP-like) calling through an Asterisk-like PBX: SIP over WebSocket, ICE, DTLS-SRTP."""

    def __init__(self, cid, t0, seed=1, browser=BROWSER_PUB, ws_port=8088, b_port=50001, pbx_port=10000):
        self.cid, self.t0, self.rng = cid, t0, random.Random(seed)
        self.browser, self.ws_port, self.b_port, self.pbx_port = browser, ws_port, b_port, pbx_port
        self.frames: list = []
        self.tx = 0
        self.ws = TcpConn(browser, 52000 + seed % 1000, PBX, ws_port)
        self.relay = None  # (turn_ip, turn_port) when media goes through TURN

    # -- transport helpers --
    def _txid(self):
        self.tx += 1
        return struct.pack("!III", 0xC0FFEE, self.tx, self.rng.randrange(2 ** 32))

    def udp(self, t, from_browser, payload):
        if self.relay:
            if from_browser:
                self.frames.append((t, udp_frame(self.browser, self.relay[0], self.b_port, self.relay[1], channel_data(0x4000, payload))))
            else:
                self.frames.append((t, udp_frame(self.relay[0], self.browser, self.relay[1], self.b_port, channel_data(0x4000, payload))))
            return
        src, dst, sp, dp = (self.browser, PBX, self.b_port, self.pbx_port) if from_browser else (PBX, self.browser, self.pbx_port, self.b_port)
        self.frames.append((t, udp_frame(src, dst, sp, dp, payload)))

    def ws_open(self, t, status=101):
        self.frames += self.ws.handshake(t)
        req = (f"GET /ws HTTP/1.1\r\nHost: pbx.exemplo.com.br:{self.ws_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n"
               "Origin: https://app.exemplo.com.br\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0\r\n\r\n").encode()
        self.frames += self.ws.send(t + 0.03, "c", req)
        if status == 101:
            resp = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: sip\r\n\r\n").encode()
        else:
            resp = f"HTTP/1.1 {status} Forbidden\r\nContent-Length: 0\r\n\r\n".encode()
        self.frames += self.ws.send(t + 0.05, "s", resp)

    def sip(self, t, text: bytes, from_browser=True):
        self.frames += self.ws.send(t, "c" if from_browser else "s", ws_frame(text, 1, mask=from_browser))

    def ws_msg(self, method_or_status, cseq, cseq_method=None, body="", from_browser=True, to_tag=True, extra=()):
        via = f"SIP/2.0/WS df7jal23ls0d.invalid;branch=z9hG4bK{cseq}{self.tx}{_h(self.cid) % 1000};rport"
        if not from_browser:
            via += f";received={self.browser}"
        headers = [("Via", via), ("From", f'"Web 1001" <sip:1001@pbx.exemplo.com.br>;tag=wb{_h(self.cid) % 10**5}'),
                   ("To", "<sip:2000@pbx.exemplo.com.br>" + (";tag=as5e7c" if to_tag else "")), ("Call-ID", self.cid),
                   ("CSeq", f"{cseq} {cseq_method or method_or_status}"), *extra]
        if from_browser:
            headers += [("Contact", "<sip:k2n8s1@df7jal23ls0d.invalid;transport=ws;ob>"), ("User-Agent", "JsSIP 3.10.1")]
            start = f"{method_or_status} sip:2000@pbx.exemplo.com.br SIP/2.0" if isinstance(method_or_status, str) else ""
        else:
            code, reason = method_or_status
            start = f"SIP/2.0 {code} {reason}"
            headers += [("Server", "Asterisk PBX 20.5.0")]
            if code == 200 and (cseq_method or "INVITE") == "INVITE":
                headers.append(("Contact", "<sip:2000@200.10.0.5:8088;transport=ws>"))
        return sip_text(start, headers, body)

    # -- media plane helpers --
    def stun_check(self, t, from_browser, answer=True, error=None, use_candidate=True, answer_delay=0.02):
        tx = self._txid()
        user = b"pbx1:brw1" if from_browser else b"brw1:pbx1"
        attrs = stun_attr(0x0006, user) + stun_attr(0x0024, struct.pack("!I", 1853824767))
        attrs += stun_attr(0x802A if from_browser else 0x8029, b"\x00" * 8)
        if use_candidate and from_browser:
            attrs += stun_attr(0x0025, b"")
        attrs += stun_attr(0x0008, b"\x11" * 20) + stun_attr(0x8028, b"\x00" * 4)
        self.udp(t, from_browser, stun(1, 0, tx, attrs))
        if error:
            self.udp(t + answer_delay, not from_browser, stun(1, 3, tx, stun_error(error)))
        elif answer:
            mapped = stun_xor_addr(0x0020, self.browser if from_browser else PBX, self.b_port if from_browser else self.pbx_port)
            self.udp(t + answer_delay, not from_browser, stun(1, 2, tx, mapped + stun_attr(0x0008, b"\x22" * 20)))

    def dtls(self, t, mode="ok"):
        """Browser is the DTLS client (a=setup:actpass offer, a=setup:passive answer)."""
        ch = dtls_record(22, 0, 0, dtls_client_hello(use_srtp=(mode != "no_srtp_ext")))
        if mode == "no_answer":
            for k in range(5):
                self.udp(t + (2 ** k - 1) * 1.0, True, ch)
            return
        server_flight = (dtls_record(22, 0, 0, dtls_handshake(2, 0, b"\xfe\xfd" + b"\x33" * 32 + b"\x00\xc0\x2b\x00\x00"))
                         + dtls_record(22, 0, 1, dtls_handshake(11, 1, b"\x00" * 3 + b"\x30\x82" + b"\x44" * 420))
                         + dtls_record(22, 0, 2, dtls_handshake(14, 2, b"")))
        if mode == "incomplete":
            for k in range(4):
                self.udp(t + (2 ** k - 1) * 1.0, True, ch)
                self.udp(t + (2 ** k - 1) * 1.0 + 0.03, False, dtls_record(22, 0, k, dtls_handshake(2, 0, b"\xfe\xfd" + b"\x33" * 32 + b"\x00\xc0\x2b\x00\x00")))
            return
        self.udp(t, True, ch)
        self.udp(t + 0.03, False, server_flight)
        if mode == "alert":
            self.udp(t + 0.06, True, dtls_record(21, 0, 1, bytes([2, 42])))
            return
        client_flight = (dtls_record(22, 0, 1, dtls_handshake(11, 1, b"\x00" * 3 + b"\x55" * 300))
                         + dtls_record(22, 0, 2, dtls_handshake(16, 2, b"\x41" + b"\x04" * 65))
                         + dtls_record(20, 0, 3, b"\x01") + dtls_record(22, 1, 0, self.rng.randbytes(40)))
        self.udp(t + 0.06, True, client_flight)
        self.udp(t + 0.09, False, dtls_record(20, 0, 3, b"\x01") + dtls_record(22, 1, 0, self.rng.randbytes(40)))

    def srtp(self, t, seconds, from_browser, loss=0.0, jitter_ms=0.0, stop_at=None, video=False):
        rng = random.Random(self.rng.randrange(2 ** 30))
        ssrc = rng.randrange(1, 2 ** 32)
        seq0, ts0 = rng.randrange(1000, 30000), rng.randrange(2 ** 31)
        if video:
            frame_n = int(seconds * 30)
            seq = seq0
            for i in range(frame_n):
                ft = t + i / 30.0
                if stop_at and ft >= stop_at:
                    break
                parts = 3 + (i % 3)
                for j in range(parts):
                    hdr = struct.pack("!BBHII", 0x90, (0x80 if j == parts - 1 else 0) | 96, seq & 0xFFFF, (ts0 + i * 3000) & 0xFFFFFFFF, ssrc)
                    seq += 1
                    self.udp(ft + j * 0.0004, from_browser, hdr + b"\xbe\xde\x00\x01\x10\x00\x00\x00" + rng.randbytes(1000) + rng.randbytes(10))
            return
        for i in range(int(seconds / 0.02)):
            pt = t + i * 0.02
            if stop_at and pt >= stop_at:
                break
            if loss and rng.random() < loss:
                continue
            hdr = struct.pack("!BBHII", 0x90, 111, (seq0 + i) & 0xFFFF, (ts0 + i * 960) & 0xFFFFFFFF, ssrc)
            arrival = pt + (abs(rng.gauss(0, jitter_ms / 1000.0)) if jitter_ms else 0.0)
            self.udp(arrival, from_browser, hdr + b"\xbe\xde\x00\x01\x10" + bytes([rng.randrange(256)]) + b"\x00\x00" + rng.randbytes(70) + rng.randbytes(10))
            if i and i % 250 == 0:  # SRTCP: encrypted report blocks (must not be read as real loss)
                sr = struct.pack("!BBH", 0x81, 200, 12) + struct.pack("!I", ssrc) + rng.randbytes(44) + b"\x80\x00\x00\x01" + rng.randbytes(10)
                self.udp(arrival + 0.001, from_browser, sr)

    def turn_allocate(self, t, mode="ok"):
        """Browser allocates a relay on TURN before ICE. mode: ok, auth_fail, quota."""
        srv = (TURN, 3478)

        def send(tt, from_browser, payload):
            if from_browser:
                self.frames.append((tt, udp_frame(self.browser, srv[0], self.b_port, srv[1], payload)))
            else:
                self.frames.append((tt, udp_frame(srv[0], self.browser, srv[1], self.b_port, payload)))
        tx = self._txid()
        send(t, True, stun(3, 0, tx, stun_attr(0x0019, b"\x11\x00\x00\x00")))
        send(t + 0.02, False, stun(3, 3, tx, stun_error(401) + stun_attr(0x0014, b"exemplo.com.br") + stun_attr(0x0015, b"nonce123")))
        creds = stun_attr(0x0019, b"\x11\x00\x00\x00") + stun_attr(0x0006, b"1717171717:webuser") + stun_attr(0x0014, b"exemplo.com.br") \
            + stun_attr(0x0015, b"nonce123") + stun_attr(0x0008, b"\x33" * 20)
        attempts = 3 if mode != "ok" else 1
        for k in range(attempts):
            tx = self._txid()
            send(t + 0.05 + k * 0.5, True, stun(3, 0, tx, creds))
            if mode == "ok":
                send(t + 0.07, False, stun(3, 2, tx, stun_xor_addr(0x0016, TURN, 49152) + stun_xor_addr(0x0020, self.browser, self.b_port)
                                          + stun_attr(0x000D, struct.pack("!I", 600)) + stun_attr(0x8022, b"Coturn-4.6.2")))
            else:
                send(t + 0.07 + k * 0.5, False, stun(3, 3, tx, stun_error(401 if mode == "auth_fail" else 486)))
        if mode == "ok":
            for method in (8, 9):
                tx = self._txid()
                send(t + 0.1 + method * 0.01, True, stun(method, 0, tx, stun_xor_addr(0x0012, PBX, self.pbx_port) + stun_attr(0x0008, b"\x44" * 20)))
                send(t + 0.12 + method * 0.01, False, stun(method, 2, tx, b""))
            self.relay = srv

    def stun_gather(self, t, answered=True, count=3):
        for k in range(count):
            tx = self._txid()
            self.frames.append((t + k * 0.5, udp_frame(self.browser, STUN_SRV, self.b_port, 19302, stun(1, 0, tx))))
            if answered:
                self.frames.append((t + k * 0.5 + 0.03, udp_frame(STUN_SRV, self.browser, 19302, self.b_port, stun(1, 2, tx, stun_xor_addr(0x0020, "177.20.0.9", 50001)))))
                break


def webrtc_scenario(cid, seed=1, *, ws_status=101, register=True, answer="webrtc", ice="ok", dtls="ok", media="both", talk=6.0,
                    candidates="normal", relay=None, stun_gather=None, loss=0.0, jitter_ms=0.0, consent_break=None, ws_close=None,
                    wss=False, video=False, browser=BROWSER_PUB, capture_tail=1.0, capture_from=None):
    w = WebRtc(cid, T0, seed, browser=browser, ws_port=8089 if wss else 8088)
    t = T0
    if wss:
        tls = TcpConn(browser, 52999, PBX, 8089)
        w.frames += tls.handshake(t)
        w.frames += tls.send(t + 0.03, "c", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + w.rng.randbytes(500))
        w.frames += tls.send(t + 0.06, "s", b"\x16\x03\x03\x00\x7a\x02" + w.rng.randbytes(1200))
        for k in range(6):
            w.frames += tls.send(t + 0.2 + k * 0.4, "c" if k % 2 == 0 else "s", b"\x17\x03\x03\x01\x00" + w.rng.randbytes(256))
    else:
        w.ws_open(t, ws_status)
        if ws_status != 101:
            w.frames += w.ws.rst(t + 0.1, "s")
            return w.frames
        if register:
            w.sip(t + 0.1, w.ws_msg("REGISTER", 1, to_tag=False, extra=[("Expires", "600")]))
            w.sip(t + 0.13, w.ws_msg((401, "Unauthorized"), 1, "REGISTER", from_browser=False, extra=[("WWW-Authenticate", 'Digest realm="pbx", nonce="xyz"')]))
            w.sip(t + 0.2, w.ws_msg("REGISTER", 2, to_tag=False, extra=[("Expires", "600"), ("Authorization", 'Digest username="1001", realm="pbx", nonce="xyz", response="ok"')]))
            w.sip(t + 0.23, w.ws_msg((200, "OK"), 2, "REGISTER", from_browser=False, extra=[("Expires", "600")]))
    if stun_gather:
        w.stun_gather(t + 0.5, answered=(stun_gather == "ok"))
    if relay:
        w.turn_allocate(t + 0.8, relay)
    if candidates == "normal":
        cands = [f"1 1 udp 2122260223 {MDNS} 50000 typ host generation 0",
                 f"2 1 udp 1686052607 {BROWSER_PUB} 50001 typ srflx raddr 0.0.0.0 rport 0 generation 0"]
        if relay == "ok":
            cands.append(f"3 1 udp 41885439 {TURN} 49152 typ relay raddr {BROWSER_PUB} rport 50001 generation 0")
        c_ip, c_port = BROWSER_PUB, 50001
    elif candidates == "mdns_only":
        cands, c_ip, c_port = [f"1 1 udp 2122260223 {MDNS} 50000 typ host generation 0"], "0.0.0.0", 9
    else:  # private only
        cands, c_ip, c_port = [f"1 1 udp 2122260223 {BROWSER_LAN} 50001 typ host generation 0"], BROWSER_LAN, 50001
    if wss:
        t_ans = t + 2.0
    else:
        ti = t + 1.5
        w.sip(ti, w.ws_msg("INVITE", 3, to_tag=False, body=webrtc_offer(c_ip, c_port, cands, video_port=c_port if video else None)))
        w.sip(ti + 0.03, w.ws_msg((100, "Trying"), 3, "INVITE", from_browser=False, to_tag=False))
        w.sip(ti + 0.3, w.ws_msg((180, "Ringing"), 3, "INVITE", from_browser=False))
        t_ans = ti + 2.3
        w.sip(t_ans, w.ws_msg((200, "OK"), 3, "INVITE", from_browser=False,
                              body=webrtc_answer(PBX, w.pbx_port, plain=(answer == "plain"), video=video)))
        w.sip(t_ans + 0.05, w.ws_msg("ACK", 3, "ACK"))
    if answer == "plain":
        w.sip(t_ans + 0.4, w.ws_msg("BYE", 4, "BYE", extra=[("Reason", 'SIP;cause=488;text="Failed to set remote answer"')]))
        w.sip(t_ans + 0.45, w.ws_msg((200, "OK"), 4, "BYE", from_browser=False))
        return w.frames
    t_ice = t_ans + 0.1
    if ice in ("no_answer", "401"):
        iv = 0.05
        while t_ice < t_ans + talk:
            w.stun_check(t_ice, True, answer=False, error=401 if ice == "401" else None)
            t_ice += iv; iv = min(iv * 2, 1.6)
        end = t_ans + talk
    else:
        if ice == "slow":
            for dt in (0.0, 0.1, 0.3, 0.7, 1.5, 3.1):
                w.stun_check(t_ice + dt, True, answer=False)
            t_ice += 4.7
        if ice == "487":
            w.stun_check(t_ice - 0.02, False, error=487)
        w.stun_check(t_ice, True)
        w.stun_check(t_ice + 0.01, False)
        t_d = t_ice + 0.1
        w.dtls(t_d, dtls)
        t_m = t_d + 0.15
        end = t_m + talk
        if dtls in ("ok",) and media != "none":
            stop_b = consent_break
            w.srtp(t_m, talk, True, loss=loss, jitter_ms=jitter_ms, stop_at=(t_m + stop_b) if stop_b else None)
            if media == "both":
                w.srtp(t_m, talk, False, loss=loss, jitter_ms=jitter_ms)
            if video:
                w.srtp(t_m, talk, True, video=True)
                w.srtp(t_m, talk, False, video=True)
        if dtls in ("ok", "no_srtp_ext"):
            for k in range(1, int(talk // 2.5) + 1):
                tc = t_m + k * 2.5
                broken = consent_break is not None and tc >= t_m + consent_break
                if not broken:
                    w.stun_check(tc, True, use_candidate=False)
                w.stun_check(tc + 0.3, False, answer=not broken)
    if consent_break is None and not wss:
        w.sip(end + 0.05, w.ws_msg("BYE", 4, "BYE"))
        w.sip(end + 0.1, w.ws_msg((200, "OK"), 4, "BYE", from_browser=False))
    if ws_close:
        code, by = ws_close
        w.frames += w.ws.send(end + 0.5, "s" if by == "server" else "c",
                              ws_frame(struct.pack("!H", code) + b"Internal Error", 8, mask=(by == "client")))
    if capture_tail:
        w.frames.append((end + capture_tail, udp_frame("10.0.0.1", "10.0.0.2", 5060, 5060, Dialog("tail@lab").req("OPTIONS", 1, to_tag=False))))
    if capture_from is not None:
        return [x for x in w.frames if x[0] >= T0 + capture_from]
    return w.frames


def _wr(sid, title, what, expect=(), allow=(), check=None, **kw):
    @scenario(sid, "webrtc", title, what, expect=expect, allow=allow, check=check)
    def _():
        return webrtc_scenario(f"{sid}@lab", seed=len(sid) + sum(map(ord, sid)), **kw)


def _session_ok(r):
    s = r.webrtc.get("sessions", [])
    errs = []
    if not s:
        errs.append("nenhuma sessão WebRTC")
    elif s[0]["ice_state"] != "connected" or s[0]["dtls"]["state"] != "connected" or s[0]["media_directions"] != 2:
        errs.append(f"sessão {s[0]['ice_state']}/{s[0]['dtls']['state']}/{s[0]['media_directions']} direções")
    if not r.calls or r.calls[0].outcome != "answered":
        errs.append("chamada SIP-WebSocket não reconhecida como atendida")
    if not all(st.secure for st in r.rtp_streams):
        errs.append("fluxo SRTP não marcado como seguro")
    return errs


_wr("webrtc01_chamada_ok", "Chamada WebRTC normal (navegador ↔ PBX)",
    "Navegador registra por SIP sobre WebSocket, liga, ICE conecta, DTLS negocia e o áudio Opus (SRTP) flui nos dois sentidos.",
    check=_session_ok)
_wr("webrtc02_video_ok", "Chamada WebRTC com vídeo (BUNDLE)", "Áudio Opus e vídeo VP8 no mesmo par ICE (BUNDLE), tudo normal.",
    video=True, check=lambda r: [] if {s.media_kind for s in r.rtp_streams} == {"audio", "video"} else ["vídeo não identificado"])
_wr("webrtc03_via_turn_ok", "Chamada WebRTC passando por TURN (normal)",
    "Rede corporativa obriga relay: o navegador aloca no TURN e toda a mídia vai dentro de ChannelData. Funciona, com um aviso informativo.",
    expect=("WEBRTC_TURN_RELAY",), relay="ok",
    check=lambda r: [] if r.webrtc["sessions"] and r.webrtc["sessions"][0]["relayed"] and len(r.rtp_streams) >= 2 else ["relay TURN não analisado"])
_wr("webrtc04_ice_falhou", "ICE falhou: nenhum caminho", "As checagens ICE do navegador para o PBX nunca são respondidas (UDP bloqueado).",
    expect=("WEBRTC_ICE_FAILED",), allow=("NO_RTP_AFTER_ANSWER",), ice="no_answer")
_wr("webrtc05_ice_senha_401", "ICE recusado com 401 (SDP alterado)", "O PBX responde 401 às checagens ICE: ice-ufrag/ice-pwd não conferem.",
    expect=("WEBRTC_ICE_AUTH_FAILED",), allow=("NO_RTP_AFTER_ANSWER",), ice="401")
_wr("webrtc06_stun_bloqueado", "Servidor STUN inacessível e só IP privado",
    "Firewall bloqueia UDP: o navegador não fala com o STUN, anuncia só o IP da LAN e o ICE falha.",
    expect=("WEBRTC_STUN_UNREACHABLE", "WEBRTC_ICE_FAILED", "WEBRTC_NO_PUBLIC_CANDIDATE"), allow=("NO_RTP_AFTER_ANSWER",),
    stun_gather="blocked", candidates="private", ice="no_answer", browser=BROWSER_LAN)
_wr("webrtc07_turn_senha_errada", "Credencial TURN recusada", "O TURN recusa a credencial (401 mesmo com usuário/senha) e o caminho direto está bloqueado.",
    expect=("WEBRTC_TURN_AUTH_FAILED", "WEBRTC_ICE_FAILED"), allow=("NO_RTP_AFTER_ANSWER",), relay="auth_fail", ice="no_answer")
_wr("webrtc08_turn_cota_486", "TURN sem cota de alocação (486)", "O servidor TURN atingiu o limite de alocações do usuário: 486.",
    expect=("WEBRTC_TURN_ALLOCATE_FAILED", "WEBRTC_ICE_FAILED"), allow=("NO_RTP_AFTER_ANSWER",), relay="quota", ice="no_answer")
_wr("webrtc09_dtls_sem_resposta", "DTLS sem resposta", "ICE conecta, mas o PBX nunca responde ao ClientHello DTLS.",
    expect=("WEBRTC_DTLS_FAILED",), allow=("NO_RTP_AFTER_ANSWER",), dtls="no_answer")
_wr("webrtc10_dtls_certificado_recusado", "DTLS recusado: certificado não confere",
    "O navegador envia alerta fatal bad_certificate: a fingerprint do SDP não confere com o certificado DTLS.",
    expect=("WEBRTC_DTLS_ALERT",), allow=("NO_RTP_AFTER_ANSWER",), dtls="alert")
_wr("webrtc11_dtls_mtu", "DTLS não termina (MTU)", "O ServerHello chega, mas o datagrama grande com o certificado se perde sempre (MTU baixo na VPN).",
    expect=("WEBRTC_DTLS_FAILED",), allow=("NO_RTP_AFTER_ANSWER",), dtls="incomplete")
_wr("webrtc12_dtls_sem_srtp", "DTLS sem SRTP (use_srtp ausente)", "O DTLS fecha sem a extensão use_srtp: não há chave para áudio.",
    expect=("WEBRTC_DTLS_NO_SRTP", "WEBRTC_NO_MEDIA"), allow=("NO_RTP_AFTER_ANSWER",), dtls="no_srtp_ext")
_wr("webrtc13_sem_midia", "ICE e DTLS ok, mas sem áudio", "Tudo conecta, mas nenhum lado envia áudio (microfone negado no navegador).",
    expect=("WEBRTC_NO_MEDIA",), allow=("NO_RTP_AFTER_ANSWER",), media="none")
_wr("webrtc14_audio_unidirecional", "Áudio WebRTC em só uma direção", "Só o navegador envia SRTP; o PBX não devolve áudio.",
    expect=("WEBRTC_ONE_WAY_MEDIA", "ONE_WAY_AUDIO"), media="browser_only")
_wr("webrtc15_perda_jitter", "WebRTC com perda e jitter (4G ruim)", "Navegador em 4G ruim: 6% de perda e jitter alto medidos no cabeçalho SRTP.",
    expect=("RTP_PACKET_LOSS", "RTP_JITTER"), allow=("LOW_MOS", "RTP_REORDER"), loss=0.06, jitter_ms=70, talk=10.0)
_wr("webrtc16_caminho_caiu", "Caminho caiu no meio (troca de Wi-Fi para 4G)",
    "Depois de 4 s de conversa o navegador troca de rede: as checagens de consentimento ficam sem resposta e o áudio dele para.",
    expect=("WEBRTC_CONSENT_LOST",), allow=("WEBRTC_ONE_WAY_MEDIA", "ONE_WAY_AUDIO", "SIP_TERMINATION_NOT_SEEN"), consent_break=4.0, talk=16.0, capture_tail=0.2)
_wr("webrtc17_so_mdns", "SDP só com mDNS (.local): PBX sem áudio de volta",
    "O navegador esconde o IP com mDNS e não tem STUN; o PBX não resolve .local e não devolve áudio.",
    expect=("WEBRTC_NO_PUBLIC_CANDIDATE", "WEBRTC_ONE_WAY_MEDIA", "ONE_WAY_AUDIO"), candidates="mdns_only", media="browser_only")
_wr("webrtc18_pbx_sem_webrtc", "PBX responde com RTP comum a uma oferta WebRTC",
    "O ramal no PBX não está configurado para WebRTC: o 200 OK vem com RTP/AVP sem DTLS e o navegador desliga.",
    expect=("WEBRTC_SDP_PROFILE_MISMATCH", "NO_RTP_AFTER_ANSWER"), allow=("SIP_SHORT_CALL",), answer="plain")
_wr("webrtc19_websocket_recusado", "WebSocket recusado (HTTP 403)", "O servidor recusa o upgrade para WebSocket (Origin não permitido).",
    expect=("WEBRTC_WS_UPGRADE_FAILED",), ws_status=403)
_wr("webrtc20_websocket_caiu", "WebSocket derrubado pelo servidor (1011)",
    "Depois da chamada o servidor fecha o WebSocket com 1011 (erro interno): o ramal web fica sem registro.",
    expect=("WEBRTC_WS_CLOSED",), ws_close=(1011, "server"))
_wr("webrtc21_wss_criptografado", "Sinalização em WSS (criptografada)", "SIP vai por wss:// na porta 8089; só a mídia é analisável.",
    expect=("WEBRTC_WSS_ENCRYPTED",), wss=True)
_wr("webrtc22_conflito_papel_ice", "Conflito de papel ICE (487) resolvido", "Os dois lados começam como controlling; o ICE resolve e a chamada segue normal.",
    expect=("WEBRTC_ICE_ROLE_CONFLICT",), ice="487")
_wr("webrtc23_conexao_lenta", "Mídia WebRTC demora 5 s para começar", "As primeiras checagens ICE se perdem e o áudio só começa ~5 s depois de atender.",
    expect=("WEBRTC_SLOW_SETUP",), allow=("MEDIA_START_DELAY",), ice="slow")

_wr("webrtc24_captura_no_meio", "Captura começou com o WebSocket já aberto",
    "O técnico ligou a captura depois que o navegador já estava registrado: não há HTTP Upgrade, só quadros WebSocket. A chamada tem de ser reconhecida.",
    capture_from=1.4, check=lambda r: _session_ok(r) + ([] if r.webrtc["websocket"] and r.webrtc["websocket"][0]["started_before_capture"]
                                                       else ["WebSocket aberto antes da captura não reconhecido"]))


# ---------------------------------------------------------------------------------------------------------------
# Cenário misto (uma captura de NOC com vários problemas ao mesmo tempo)
# ---------------------------------------------------------------------------------------------------------------

@scenario("misto01_plantao_noc", "misto", "Plantão de NOC: vários problemas numa captura só",
          "Chamadas normais, uma com 503 da operadora, uma com áudio mudo por NAT, uma força bruta na internet e uma chamada WebRTC normal.",
          expect=("SIP_FINAL_FAILURE", "NAT_PRIVATE_SDP", "NAT_ONE_WAY_AUDIO", "ONE_WAY_AUDIO", "SEC_BRUTE_FORCE"),
          allow=("DEVICE_BEHIND_NAT", "NAT_MEDIA_SOURCE_MISMATCH"))
def _():
    f = []
    f += call("misto-ok1@lab", T0, talk=5.0, seed=81)
    f += call("misto-ok2@lab", T0 + 1, a="10.0.0.3", talk=5.0, port_a=40010, port_b=50010, seed=82)
    f += failed_call("misto-503@lab", T0 + 2, 503, "Service Unavailable", a="10.0.0.4", b="187.50.0.1", to_user="551130000000")
    f += call("misto-nat@lab", T0 + 3, a="192.168.1.10", b="200.10.0.5", sig_src="177.10.0.5", talk=5.0, rtp_b=False,
              media_a=("177.10.0.5", 40000), port_b=50020, seed=83)
    for i in range(20):
        d = Dialog(f"misto-bf-{i}@lab", a="185.22.10.9", b="200.10.0.5", from_user="100", ua_a="PolycomVVX-VVX_410-UA/5.9.0")
        f += register(d, T0 + 4 + i * 0.4, final=403, challenge=False)
    f += webrtc_scenario("misto-webrtc@lab", seed=84, talk=5.0, capture_tail=0)
    return f


def by_id() -> dict[str, Scenario]:
    return {s.id: s for s in SCENARIOS}


def write_all(out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for s in SCENARIOS:
        path = os.path.join(out_dir, s.filename)
        with open(path, "wb") as fh:
            fh.write(s.pcap())
        paths.append(path)
    return paths
