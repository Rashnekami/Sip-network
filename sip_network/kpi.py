from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

from .models import RtpStream, SipCall, SipMessage

# RFC 6076 SEER: responses that show the network delivered the session request to the user.
SEER_EFFECTIVE = {480, 486, 600, 603}


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    vs = sorted(values)
    k = max(0, min(len(vs) - 1, int(round(q * (len(vs) - 1)))))
    return round(vs[k], 1)


def _ratio(num: int, den: int) -> float | None:
    return round(num * 100.0 / den, 2) if den else None


def _call_kpis(calls: list[SipCall]) -> dict[str, Any]:
    attempts = len(calls)
    answered = [c for c in calls if c.connected]
    redirected = sum(1 for c in calls if c.final_status and 300 <= c.final_status < 400)
    effective = sum(1 for c in calls if c.connected or (c.final_status in SEER_EFFECTIVE))
    # ITU-T E.411 NER: the network worked when the call was answered or the called user caused the failure.
    ner_ok = sum(1 for c in calls if c.connected or c.outcome in ("busy", "no_answer", "rejected", "cancelled"))
    ineffective = sum(1 for c in calls if c.outcome in ("server_error", "timeout", "no_response"))
    completed_durations = [c.duration_s for c in answered if c.duration_s is not None and c.termination_observed]
    pdd = [c.pdd_ms for c in calls if c.pdd_ms is not None]
    setup = [c.setup_time_ms for c in answered if c.setup_time_ms is not None]
    return {
        "attempts": attempts,
        "answered": len(answered),
        "asr_pct": _ratio(len(answered), attempts),
        "ner_pct": _ratio(ner_ok, attempts),
        "ser_pct": _ratio(len(answered), attempts - redirected),
        "seer_pct": _ratio(effective, attempts - redirected),
        "isa_pct": _ratio(ineffective, attempts),
        "acd_s": round(statistics.mean(completed_durations), 1) if completed_durations else None,
        "total_minutes": round(sum(completed_durations) / 60.0, 2) if completed_durations else 0.0,
        "pdd_avg_ms": round(statistics.mean(pdd), 1) if pdd else None,
        "pdd_p95_ms": _pct(pdd, 0.95),
        "setup_avg_ms": round(statistics.mean(setup), 1) if setup else None,
        "outcomes": dict(Counter(c.outcome for c in calls).most_common()),
        "final_codes": dict(Counter(str(c.final_status) for c in calls if c.final_status).most_common()),
        "q850_causes": dict(Counter(f"{c.q850_cause} {c.q850_text}" for c in calls if c.q850_cause is not None).most_common()),
        "disconnect_side": dict(Counter(c.disconnect_side for c in answered if c.disconnect_side).most_common()),
        "missing_ack": sum(1 for c in calls if c.missing_ack),
        "forked": sum(1 for c in calls if c.forked),
        "with_auth_challenge": sum(1 for c in calls if c.auth_challenges),
        "short_calls_lt_3s": sum(1 for c in completed_durations if c < 3.0),
    }


def _by_peer(calls: list[SipCall]) -> list[dict[str, Any]]:
    """Per signalling peer (trunk/SBC/PBX) ASR and failures, the NOC view of 'which route is bad'."""
    groups: dict[str, list[SipCall]] = defaultdict(list)
    for c in calls:
        groups[c.callee_ip or "?"].append(c)
    rows = []
    for peer, cs in groups.items():
        k = _call_kpis(cs)
        top_fail = Counter(str(c.final_status) for c in cs if c.final_status and c.final_status >= 300).most_common(3)
        rows.append({"peer_ip": peer, "attempts": k["attempts"], "answered": k["answered"], "asr_pct": k["asr_pct"],
                     "ner_pct": k["ner_pct"], "pdd_avg_ms": k["pdd_avg_ms"], "acd_s": k["acd_s"],
                     "top_failures": ", ".join(f"{code} ({n})" for code, n in top_fail)})
    rows.sort(key=lambda r: -r["attempts"])
    return rows


def _failing_destinations(calls: list[SipCall]) -> list[dict[str, Any]]:
    groups: dict[str, list[SipCall]] = defaultdict(list)
    for c in calls:
        if not c.connected and c.outcome not in ("cancelled", "in_progress"):
            groups[c.to_uri or "?"].append(c)
    rows = [{"destination": d, "failures": len(cs),
             "codes": ", ".join(f"{k} ({v})" for k, v in Counter(str(c.final_status) for c in cs).most_common(3))}
            for d, cs in groups.items()]
    rows.sort(key=lambda r: -r["failures"])
    return rows[:20]


def _media_kpis(streams: list[RtpStream]) -> dict[str, Any]:
    mos = [s.mos for s in streams if s.mos is not None]
    bands = Counter()
    for m in mos:
        bands["boa (>=4.0)" if m >= 4.0 else "aceitável (3.6-4.0)" if m >= 3.6 else "ruim (3.1-3.6)" if m >= 3.1 else "péssima (<3.1)"] += 1
    return {
        "streams": len(streams),
        "mos_avg": round(statistics.mean(mos), 2) if mos else None,
        "mos_min": min(mos) if mos else None,
        "mos_bands": dict(bands),
        "loss_avg_pct": round(statistics.mean(s.loss_percent for s in streams), 3) if streams else None,
        "jitter_p95_ms": _pct([s.jitter_ms for s in streams], 0.95),
        "codecs": dict(Counter(s.codec for s in streams).most_common()),
        "dscp": dict(Counter(str(s.dscp) for s in streams).most_common()),
    }


def _method_counts(messages: list[SipMessage]) -> dict[str, int]:
    return dict(Counter(m.method for m in messages if m.is_request).most_common())


def compute_kpis(calls: list[SipCall], streams: list[RtpStream], messages: list[SipMessage],
                 registrations: list[dict[str, Any]]) -> dict[str, Any]:
    reg_delays = [r["avg_register_delay_ms"] for r in registrations if r["avg_register_delay_ms"] is not None]
    return {
        "calls": _call_kpis(calls),
        "by_peer": _by_peer(calls),
        "failing_destinations": _failing_destinations(calls),
        "media": _media_kpis(streams),
        "sip_methods": _method_counts(messages),
        "registrations": {
            "aors": len(registrations),
            "registered": sum(1 for r in registrations if r["state"] == "registered"),
            "failed": sum(1 for r in registrations if r["state"] == "failed"),
            "no_response": sum(1 for r in registrations if r["state"] == "no_response"),
            "rrd_avg_ms": round(statistics.mean(reg_delays), 1) if reg_delays else None,
        },
    }
