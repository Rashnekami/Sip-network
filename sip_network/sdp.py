from __future__ import annotations

import re
from .models import SdpCodec, SdpMedia, SdpSession

# Static RTP/AVP assignments most useful for voice troubleshooting.
STATIC_AUDIO = {
    0: ("PCMU", 8000, 1),
    3: ("GSM", 8000, 1),
    4: ("G723", 8000, 1),
    5: ("DVI4", 8000, 1),
    6: ("DVI4", 16000, 1),
    7: ("LPC", 8000, 1),
    8: ("PCMA", 8000, 1),
    9: ("G722", 8000, 1),  # RTP timestamp clock is 8 kHz by RFC profile convention.
    10: ("L16", 44100, 2),
    11: ("L16", 44100, 1),
    12: ("QCELP", 8000, 1),
    13: ("CN", 8000, 1),
    15: ("G728", 8000, 1),
    18: ("G729", 8000, 1),
}


def parse_sdp(body: str) -> SdpSession | None:
    if "m=" not in body:
        return None
    session_ip = None
    origin_ip = None
    media: list[SdpMedia] = []
    current: SdpMedia | None = None
    pending_rtpmap: dict[int, tuple[str, int, int]] = {}
    pending_fmtp: dict[int, str] = {}

    for raw in body.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line or len(line) < 2 or line[1] != "=":
            continue
        kind, value = line[0], line[2:]
        if kind == "o":
            parts = value.split()
            origin_ip = parts[5] if len(parts) >= 6 else None
            continue
        if kind == "c":
            parts = value.split()
            ip = parts[-1].split("/")[0] if parts else None
            if current is None:
                session_ip = ip
            else:
                current.connection_ip = ip
        elif kind == "m":
            parts = value.split()
            if len(parts) < 4:
                continue
            try:
                port = int(parts[1].split("/")[0])
            except ValueError:
                continue
            pts: list[int] = []
            for p in parts[3:]:
                if p.isdigit():
                    pts.append(int(p))
            current = SdpMedia(parts[0].lower(), port, parts[2], pts)
            media.append(current)
            for pt in pts:
                if pt in STATIC_AUDIO:
                    name, rate, channels = STATIC_AUDIO[pt]
                    current.codecs[pt] = SdpCodec(pt, name, rate, channels)
        elif kind == "a" and current is not None:
            m = re.match(r"rtpmap:(\d+)\s+([^/\s]+)/([0-9]+)(?:/([0-9]+))?", value, re.I)
            if m:
                pt = int(m.group(1)); name = m.group(2).upper(); rate = int(m.group(3)); channels = int(m.group(4) or 1)
                pending_rtpmap[pt] = (name, rate, channels)
                current.codecs[pt] = SdpCodec(pt, name, rate, channels, pending_fmtp.get(pt))
                continue
            m = re.match(r"fmtp:(\d+)\s+(.+)", value, re.I)
            if m:
                pt = int(m.group(1)); fmtp = m.group(2).strip(); pending_fmtp[pt] = fmtp
                if pt in current.codecs:
                    current.codecs[pt].fmtp = fmtp
                continue
            if value in ("sendrecv", "sendonly", "recvonly", "inactive"):
                current.direction = value
                continue
            m = re.match(r"ptime:([0-9.]+)", value, re.I)
            if m:
                try: current.ptime_ms = float(m.group(1))
                except ValueError: pass
                continue
            m = re.match(r"rtcp:(\d+)(?:\s+IN\s+IP[46]\s+([^\s]+))?", value, re.I)
            if m:
                current.rtcp_port = int(m.group(1)); current.rtcp_ip = m.group(2)
                continue
            if value.lower().startswith("candidate:"):
                current.ice_candidates.append(value)

    for m in media:
        if not m.connection_ip:
            m.connection_ip = session_ip
    return SdpSession(session_ip, media, origin_ip)


def codec_for_payload(session: SdpSession | None, pt: int) -> SdpCodec | None:
    if session:
        for m in session.media:
            if pt in m.codecs:
                return m.codecs[pt]
    if pt in STATIC_AUDIO:
        name, rate, channels = STATIC_AUDIO[pt]
        return SdpCodec(pt, name, rate, channels)
    return None
