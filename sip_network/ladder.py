from __future__ import annotations

from html import escape

from .models import SipCall

COLORS = {"req": "#4b8bf4", "1xx": "#8a8f98", "2xx": "#2e9d57", "3xx": "#b07cd8", "4xx": "#e6a700", "5xx": "#d33", "6xx": "#d33"}


MARKERS = list(dict.fromkeys(COLORS.values()))


def _color(start_line: str, is_request: bool, status: int | None) -> str:
    if is_request:
        return COLORS["req"]
    return COLORS.get(f"{(status or 0) // 100}xx", COLORS["1xx"])


def ladder_svg(call: SipCall, max_messages: int = 200) -> str:
    """Render a call's SIP message flow as a standalone SVG sequence diagram (sngrep-style)."""
    msgs = call.messages[:max_messages]
    hosts: list[str] = []
    for m in msgs:
        for h in (f"{m.src_ip}:{m.src_port}", f"{m.dst_ip}:{m.dst_port}"):
            if h not in hosts:
                hosts.append(h)
    col_w, row_h, top, left = 230, 30, 56, 110
    width = left + col_w * max(1, len(hosts) - 1) + 120
    height = top + row_h * (len(msgs) + 1)
    x = {h: left + i * col_w for i, h in enumerate(hosts)}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
             f'font-family="ui-monospace,Menlo,Consolas,monospace" font-size="12">',
             "<defs>" + "".join(f'<marker id="ah{i}" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
                                f'<path d="M0,0 L8,4 L0,8 z" fill="{c}"/></marker>' for i, c in enumerate(MARKERS)) + "</defs>",
             '<rect width="100%" height="100%" fill="#ffffff"/>']
    for h in hosts:
        parts.append(f'<text x="{x[h]}" y="24" text-anchor="middle" font-weight="bold" fill="#222">{escape(h)}</text>')
        parts.append(f'<line x1="{x[h]}" y1="34" x2="{x[h]}" y2="{height - 10}" stroke="#bbb" stroke-dasharray="4 4"/>')
    t0 = call.started_at
    for i, m in enumerate(msgs):
        y = top + i * row_h
        x1, x2 = x[f"{m.src_ip}:{m.src_port}"], x[f"{m.dst_ip}:{m.dst_port}"]
        color = _color(m.start_line, m.is_request, m.status_code)
        label = m.method if m.is_request else f"{m.status_code} {m.reason or ''}".strip()
        if m.sdp:
            label += " (SDP)"
        parts.append(f'<text x="8" y="{y + 4}" fill="#666">{(m.timestamp - t0):+.3f}s</text>')
        if x1 == x2:
            parts.append(f'<path d="M{x1},{y} h40 v12 h-40" fill="none" stroke="{color}" stroke-width="1.6" marker-end="url(#ah{MARKERS.index(color)})"/>')
            parts.append(f'<text x="{x1 + 46}" y="{y + 4}" fill="{color}">{escape(label)}</text>')
            continue
        parts.append(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{color}" stroke-width="1.6" marker-end="url(#ah{MARKERS.index(color)})"/>')
        parts.append(f'<text x="{(x1 + x2) / 2}" y="{y - 5}" text-anchor="middle" fill="{color}">{escape(label[:60])}</text>')
    if len(call.messages) > max_messages:
        parts.append(f'<text x="8" y="{height - 4}" fill="#999">… {len(call.messages) - max_messages} mensagens omitidas</text>')
    parts.append("</svg>")
    return "".join(parts)
