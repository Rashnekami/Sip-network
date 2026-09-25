from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .models import Packet


@dataclass(slots=True)
class RtcpReport:
    packet_number: int
    timestamp: float
    reporter_ssrc: int
    source_ssrc: int
    fraction_lost: float
    cumulative_lost: int
    extended_highest_seq: int
    jitter: int
    lsr: int
    dlsr: int
    rtt_ms: Optional[float]


def looks_like_rtcp(payload: bytes) -> bool:
    if len(payload) < 4 or payload[0] >> 6 != 2:
        return False
    pt = payload[1]
    if not 192 <= pt <= 223:
        return False
    words = struct.unpack("!H", payload[2:4])[0] + 1
    return words * 4 <= len(payload)


def _ntp_middle32(unix_ts: float) -> int:
    ntp = unix_ts + 2208988800.0
    sec = int(ntp)
    frac = int((ntp - sec) * (1 << 32)) & 0xFFFFFFFF
    return ((sec & 0xFFFF) << 16) | (frac >> 16)


def parse_rtcp_reports(packets: list[Packet]) -> list[RtcpReport]:
    reports: list[RtcpReport] = []
    for p in packets:
        if p.protocol != "UDP" or not looks_like_rtcp(p.payload):
            continue
        data = p.payload; pos = 0
        while pos + 4 <= len(data):
            vpc = data[pos]; version = vpc >> 6; count = vpc & 0x1F; pt = data[pos + 1]
            words = struct.unpack("!H", data[pos + 2:pos + 4])[0] + 1
            size = words * 4
            if version != 2 or size < 4 or pos + size > len(data): break
            body = data[pos + 4:pos + size]
            reporter = None; rb_off = None
            if pt == 200 and len(body) >= 24:  # SR
                reporter = struct.unpack("!I", body[:4])[0]; rb_off = 24
            elif pt == 201 and len(body) >= 4:  # RR
                reporter = struct.unpack("!I", body[:4])[0]; rb_off = 4
            if reporter is not None and rb_off is not None:
                for i in range(count):
                    off = rb_off + i * 24
                    if off + 24 > len(body): break
                    source_ssrc = struct.unpack("!I", body[off:off + 4])[0]
                    fraction = body[off + 4] * 100.0 / 256.0
                    lost_raw = int.from_bytes(body[off + 5:off + 8], "big", signed=False)
                    if lost_raw & 0x800000: lost_raw -= 1 << 24
                    ext_high, jitter, lsr, dlsr = struct.unpack("!IIII", body[off + 8:off + 24])
                    rtt = None
                    if lsr and dlsr and p.timestamp > 0:
                        a = _ntp_middle32(p.timestamp)
                        diff = (a - lsr - dlsr) & 0xFFFFFFFF
                        sec = diff / 65536.0
                        if 0 <= sec <= 60:
                            rtt = sec * 1000.0
                    reports.append(RtcpReport(p.number, p.timestamp, reporter, source_ssrc, fraction, lost_raw, ext_high, jitter, lsr, dlsr, rtt))
            pos += size
    return reports
