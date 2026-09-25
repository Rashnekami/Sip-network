from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .config import DEFAULT_THRESHOLDS, Thresholds
from .models import SipCall, SipMessage

# User-Agent strings of well known SIP scanners / attack tools.
SCANNER_AGENTS = (
    "friendly-scanner", "sipvicious", "sipcli", "sip-scan", "sipscan", "vaxsipuseragent", "pplsip",
    "iwar", "sundayddr", "smap", "svcrack", "svwar", "sipptk", "voipbuster", "cantabile", "gulp",
    "sipsak", "nmap", "zoiper rv2.8",
)


def _user(uri: str | None) -> str | None:
    if not uri:
        return None
    m = re.match(r"(?:sips?|tel):([^@;>]+)", uri, re.I)
    return m.group(1) if m else None


def is_international(number: str | None, home_country_code: str = "55") -> bool:
    if not number:
        return False
    digits = re.sub(r"[^\d+]", "", number)
    if digits.startswith("+"):
        return not digits.startswith("+" + home_country_code) and len(digits) >= 9
    # NANP dials 011 for international; most other plans (Brazil included: 00 + CSP + country) use 00.
    prefix = "011" if home_country_code == "1" else "00"
    return digits.startswith(prefix) and len(digits) >= 10


def analyze_sip_security(messages: list[SipMessage], transactions: list[dict[str, Any]], calls: list[SipCall],
                         th: Thresholds = DEFAULT_THRESHOLDS) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    # 1. Request rate per source and method.
    by_ip_method: dict[tuple, list[float]] = defaultdict(list)
    targets: dict[str, set[str]] = defaultdict(set)
    options_hosts: dict[str, set[str]] = defaultdict(set)
    agents: dict[str, set[str]] = defaultdict(set)
    for m in messages:
        if not m.is_request or not m.src_ip or not m.method:
            continue
        by_ip_method[(m.src_ip, m.method)].append(m.timestamp)
        if m.to_uri and m.method in ("INVITE", "REGISTER", "OPTIONS"):
            targets[m.src_ip].add(m.to_uri)
        if m.method == "OPTIONS" and m.dst_ip:
            options_hosts[m.src_ip].add(m.dst_ip)
        ua = (m.user_agent or "").lower()
        if ua and any(sig in ua for sig in SCANNER_AGENTS):
            agents[m.src_ip].add(m.user_agent)
    for (ip, method), times in by_ip_method.items():
        if len(times) < 10:
            continue
        duration = max(times) - min(times)
        rate = len(times) / duration if duration > 0 else float(len(times))
        threshold = th.method_rate_per_s if method in ("INVITE", "REGISTER", "OPTIONS") else th.other_method_rate_per_s
        if rate >= threshold:
            alerts.append({"severity": "warning", "type": "rate", "source_ip": ip, "method": method, "rate_per_s": round(rate, 2),
                           "count": len(times), "detail": f"{len(times)} {method} a {rate:.1f}/s. Validar flood ou teste de carga."})
    for ip, uas in agents.items():
        alerts.append({"severity": "critical", "type": "scanner", "source_ip": ip, "user_agents": sorted(uas),
                       "detail": f"User-Agent de ferramenta de ataque/scanner SIP: {', '.join(sorted(uas))}. Bloquear a origem no SBC/firewall."})
    for ip, unique in targets.items():
        if len(unique) >= th.scan_distinct_targets:
            alerts.append({"severity": "warning", "type": "scan", "source_ip": ip, "targets": len(unique),
                           "detail": f"{len(unique)} destinos SIP distintos a partir da mesma origem; possível varredura/enumeração."})
    for ip, hosts in options_hosts.items():
        if len(hosts) >= th.options_sweep_hosts:
            alerts.append({"severity": "warning", "type": "options_sweep", "source_ip": ip, "hosts": len(hosts),
                           "detail": f"OPTIONS enviados para {len(hosts)} hosts diferentes: varredura de servidores SIP."})

    # 2. Credential attacks: failed authentications per source.
    failed_auth: dict[str, list[dict]] = defaultdict(list)
    not_found_users: dict[str, set[str]] = defaultdict(set)
    for tx in transactions:
        st = tx["final_status"]
        if st is None or tx["method"] not in ("REGISTER", "INVITE"):
            continue
        if tx["has_credentials"] and st in (401, 403, 407):
            failed_auth[tx["src_ip"]].append(tx)
        elif st == 403 and tx["method"] == "REGISTER":
            failed_auth[tx["src_ip"]].append(tx)
        if st in (404, 403, 604):
            u = _user(tx["to_uri"])  # INVITE target, or the AOR being registered
            if u:
                not_found_users[tx["src_ip"]].add(u)
    for ip, txs in failed_auth.items():
        if len(txs) < th.brute_force_failures:
            continue
        users = sorted({t["auth_username"] or _user(t["from_uri"]) or "?" for t in txs})
        alerts.append({"severity": "critical", "type": "brute_force", "source_ip": ip, "failures": len(txs),
                       "usernames": users[:20], "distinct_usernames": len(users),
                       "detail": f"{len(txs)} autenticações recusadas para {len(users)} usuário(s): tentativa de força bruta de senha."})
    for ip, users in not_found_users.items():
        if len(users) >= th.enumeration_distinct_users:
            alerts.append({"severity": "warning", "type": "enumeration", "source_ip": ip, "distinct_users": len(users),
                           "sample": sorted(users)[:10],
                           "detail": f"{len(users)} ramais/usuários distintos testados com resposta 403/404: enumeração de ramais."})

    # 3. Toll fraud indicators: many international destinations from one origin.
    intl: dict[str, list[SipCall]] = defaultdict(list)
    for c in calls:
        if is_international(_user(c.to_uri), th.home_country_code):
            intl[c.caller_ip or "?"].append(c)
    for ip, cs in intl.items():
        dests = {_user(c.to_uri) for c in cs}
        if len(dests) >= th.toll_fraud_destinations:
            answered = [c for c in cs if c.connected]
            alerts.append({"severity": "critical" if answered else "warning", "type": "toll_fraud", "source_ip": ip,
                           "international_destinations": len(dests), "answered": len(answered),
                           "sample": sorted(d for d in dests if d)[:10],
                           "detail": f"{len(cs)} chamadas para {len(dests)} destinos internacionais distintos ({len(answered)} atendidas). "
                                     "Padrão típico de fraude de tarifação (IRSF); validar conta/credencial de origem."})
    order = {"critical": 0, "warning": 1, "info": 2}
    alerts.sort(key=lambda a: order.get(a["severity"], 9))
    return alerts
