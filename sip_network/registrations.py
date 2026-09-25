from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .models import SipMessage


def _auth_username(m: SipMessage) -> str | None:
    for name in ("authorization", "proxy-authorization"):
        v = m.header(name)
        if v:
            mm = re.search(r'username\s*=\s*"?([^",]+)"?', v, re.I)
            if mm:
                return mm.group(1)
    return None


def _expires(m: SipMessage) -> int | None:
    contact = m.header("contact") or ""
    mm = re.search(r";\s*expires\s*=\s*(\d+)", contact, re.I)
    if mm:
        return int(mm.group(1))
    v = m.header("expires")
    if v and v.strip().isdigit():
        return int(v.strip())
    return None


def request_transactions(messages: list[SipMessage], methods: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    """Pair every request (first copy, retransmissions folded) with its final response."""
    txs: dict[tuple, dict[str, Any]] = {}
    for m in messages:
        if m.is_request:
            if m.method == "ACK" or (methods and m.method not in methods):
                continue
            key = (m.call_id, m.cseq_number, m.method, m.via_branch)
            tx = txs.get(key)
            if tx is None:
                txs[key] = {
                    "method": m.method, "call_id": m.call_id, "cseq": m.cseq_number, "branch": m.via_branch,
                    "at": m.timestamp, "src_ip": m.src_ip, "dst_ip": m.dst_ip, "src_port": m.src_port,
                    "from_uri": m.from_uri, "to_uri": m.to_uri, "user_agent": m.user_agent,
                    "auth_username": _auth_username(m), "has_credentials": _auth_username(m) is not None,
                    "expires": _expires(m) if m.method == "REGISTER" else None,
                    "copies": 1, "provisional": None, "final_status": None, "final_reason": None,
                    "response_ms": None, "server": None,
                }
            else:
                tx["copies"] += 1
    by_cseq: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for tx in txs.values():
        by_cseq[(tx["call_id"], tx["cseq"], tx["method"])].append(tx)
    for m in messages:
        if m.is_request or m.status_code is None:
            continue
        cands = by_cseq.get((m.call_id, m.cseq_number, m.cseq_method))
        if not cands:
            continue
        tx = next((t for t in cands if t["branch"] == m.via_branch), cands[0])
        if m.status_code < 200:
            tx["provisional"] = tx["provisional"] or m.status_code
        elif tx["final_status"] is None:
            tx["final_status"] = m.status_code
            tx["final_reason"] = m.reason
            tx["response_ms"] = round((m.timestamp - tx["at"]) * 1000.0, 1)
            tx["server"] = m.server or m.user_agent
    return sorted(txs.values(), key=lambda t: t["at"])


def analyze_registrations(messages: list[SipMessage]) -> list[dict[str, Any]]:
    """Summarise REGISTER activity per AOR (address of record) and source."""
    txs = request_transactions(messages, ("REGISTER",))
    groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for tx in txs:
        groups[(tx["to_uri"], tx["src_ip"])].append(tx)
    out = []
    for (aor, src), items in groups.items():
        finals = [t for t in items if t["final_status"] is not None]
        ok = [t for t in finals if 200 <= t["final_status"] < 300]
        challenges = [t for t in finals if t["final_status"] in (401, 407)]
        failures = [t for t in finals if t["final_status"] >= 300 and t["final_status"] not in (401, 407)]
        # A challenge answered with credentials that is challenged again means the password was refused.
        cred_rejected = [t for t in finals if t["has_credentials"] and t["final_status"] in (401, 403, 407)]
        rrd = [t["response_ms"] for t in ok if t["response_ms"] is not None]
        last = finals[-1] if finals else None
        if ok and last and 200 <= last["final_status"] < 300:
            state = "registered" if (last["expires"] is None or last["expires"] > 0) else "unregistered"
        elif not finals:
            state = "no_response"
        else:
            state = "failed"
        out.append({
            "aor": aor, "source_ip": src, "state": state,
            "attempts": len(items), "successes": len(ok), "challenges": len(challenges),
            "credential_rejections": len(cred_rejected), "failures": len(failures),
            "no_response": sum(1 for t in items if t["final_status"] is None),
            "last_status": last["final_status"] if last else None,
            "last_reason": last["final_reason"] if last else None,
            "expires": next((t["expires"] for t in reversed(items) if t["expires"] is not None), None),
            "avg_register_delay_ms": round(sum(rrd) / len(rrd), 1) if rrd else None,
            "user_agent": next((t["user_agent"] for t in items if t["user_agent"]), None),
            "registrar": next((t["server"] for t in items if t["server"]), None),
            "first_at": items[0]["at"], "last_at": items[-1]["at"],
        })
    out.sort(key=lambda r: (r["state"] == "registered", r["aor"] or ""))
    return out
