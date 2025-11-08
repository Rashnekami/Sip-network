"""
Analysis Routines for Network and VoIP Traffic
=============================================

This module contains functions that operate on lists of packets produced by
``voip_analyzer.parser``.  The goal of these routines is to extract high
level metrics that help understand the behaviour of a network capture.  Two
main analysis functions are provided:

* :func:`analyze_network` – examines all packets regardless of port and
  computes per‑flow metrics such as latency, jitter, packet counts and
  simple storm detection.  Flows are grouped by (source_ip, dest_ip,
  protocol).
* :func:`analyze_voip` – focuses on packets that look like SIP signalling
  or RTP media streams and aggregates metrics per call.  A call is defined
  by the 4‑tuple (source_ip, dest_ip, source_port, dest_port) for UDP
  traffic.  Jitter and a rough MOS estimate are calculated.

These functions mirror the behaviour of the original TypeScript
implementation in the PCAP Analyzer project but avoid dependencies on
external packet parsing libraries.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import List, Dict, Tuple, Optional

from .parser import Packet


def _is_private_ip(ip: str) -> bool:
    """Determine whether an IPv4 address is from a private range.

    Args:
        ip: Dotted decimal IPv4 address.

    Returns:
        True if the address is private; False otherwise.
    """
    try:
        octets = list(map(int, ip.split(".")))
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
    except Exception:
        # Non‑IPv4 addresses are treated as non‑private
        pass
    return False


def _same_subnet(ip1: str, ip2: str) -> bool:
    """Check whether two IPv4 addresses reside in the same /24 subnet.

    Args:
        ip1: First IPv4 address.
        ip2: Second IPv4 address.

    Returns:
        True if the first three octets match; False otherwise.
    """
    try:
        o1 = list(map(int, ip1.split(".")))
        o2 = list(map(int, ip2.split(".")))
        return o1[:3] == o2[:3]
    except Exception:
        return False


def analyze_network(packets: List[Packet]) -> List[Dict[str, Optional[float]]]:
    """Aggregate basic network metrics per flow.

    A network flow is identified by the combination of source IP, destination
    IP and protocol.  For each flow the following statistics are computed:

    * Average, minimum and maximum inter‑packet latency in milliseconds.
    * Jitter (standard deviation of inter‑packet latency).
    * Packet count and total bytes.
    * Flags for broadcast/multicast/ARP/DHCP storms.
    * A flag indicating a potential NAT or routing misconfiguration if two
      private addresses belong to different subnets.

    Args:
        packets: Sequence of Packet instances to analyse.

    Returns:
        A list of dictionaries, one per flow, containing the computed metrics.
    """
    from collections import defaultdict

    flow_map: Dict[str, Dict[str, any]] = {}

    for pkt in packets:
        if pkt.protocol == "ARP" or pkt.source_ip == "Unknown":
            # Skip ARP frames and unknown sources when computing latencies
            continue
        flow_key = f"{pkt.source_ip}-{pkt.dest_ip}-{pkt.protocol}"
        if flow_key not in flow_map:
            flow_map[flow_key] = {
                "source_ip": pkt.source_ip,
                "dest_ip": pkt.dest_ip,
                "protocol": pkt.protocol,
                "packets": [],
                "timestamps": [],
                "packet_count": 0,
                "total_bytes": 0,
            }
        flow = flow_map[flow_key]
        flow["packets"].append(pkt)
        flow["timestamps"].append(pkt.timestamp)
        flow["packet_count"] += 1
        flow["total_bytes"] += pkt.length

    results: List[Dict[str, Optional[float]]] = []
    for flow in flow_map.values():
        ts_sorted = sorted(flow["timestamps"])
        avg_latency = min_latency = max_latency = jitter = 0.0
        if len(ts_sorted) > 1:
            diffs = [ts_sorted[i] - ts_sorted[i - 1] for i in range(1, len(ts_sorted))]
            avg_latency = sum(diffs) / len(diffs)
            min_latency = min(diffs)
            max_latency = max(diffs)
            # Standard deviation
            mean = avg_latency
            variance = sum((d - mean) ** 2 for d in diffs) / len(diffs)
            jitter = variance ** 0.5
        # Detect storms
        broadcast_storm = flow["packet_count"] > 100
        # Simple multicast detection based on destination first octet (224-239)
        dest_octet0 = 0
        try:
            dest_octet0 = int(flow["dest_ip"].split(".")[0])
        except Exception:
            pass
        multicast_storm = 224 <= dest_octet0 <= 239 and flow["packet_count"] > 50
        arp_storm = flow["protocol"] == "ARP" and flow["packet_count"] > 50
        # DHCP uses UDP ports 67/68; check first packet ports
        dhcp_storm = False
        if flow["packets"]:
            first_pkt: Packet = flow["packets"][0]
            if first_pkt.protocol == "UDP":
                if first_pkt.source_port in (67, 68) or first_pkt.dest_port in (67, 68):
                    dhcp_storm = flow["packet_count"] > 30
        # NAT error detection
        nat_error = False
        nat_error_reason: Optional[str] = None
        src_ip = flow["source_ip"]
        dst_ip = flow["dest_ip"]
        if _is_private_ip(src_ip) and _is_private_ip(dst_ip) and not _same_subnet(src_ip, dst_ip):
            nat_error = True
            nat_error_reason = (
                "Comunicação entre sub-redes privadas diferentes (possível erro de roteamento)"
            )

        results.append({
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": flow["protocol"],
            "source_port": flow["packets"][0].source_port if flow["packets"] else None,
            "dest_port": flow["packets"][0].dest_port if flow["packets"] else None,
            "avg_latency_ms": round(avg_latency, 2) if avg_latency else 0.0,
            "min_latency_ms": round(min_latency, 2) if min_latency else 0.0,
            "max_latency_ms": round(max_latency, 2) if max_latency else 0.0,
            "jitter_ms": round(jitter, 2) if jitter else 0.0,
            "packet_count": flow["packet_count"],
            "total_bytes": flow["total_bytes"],
            "nat_error": nat_error,
            "nat_error_reason": nat_error_reason,
            "broadcast_storm": broadcast_storm,
            "multicast_storm": multicast_storm,
            "arp_storm": arp_storm,
            "dhcp_storm": dhcp_storm,
        })
    return results


def analyze_voip(packets: List[Packet]) -> List[Dict[str, Optional[float]]]:
    """Compute VoIP metrics for UDP flows.

    A VoIP flow is detected when the source or destination port falls into the
    SIP (5060/5061) or RTP (10000–20000) ranges.  For each matching flow, a
    jitter metric and a rough MOS estimate are calculated using the same
    simple heuristics employed in the original PCAP Analyzer.  Packet loss
    and detailed SIP message analysis are not implemented here but could be
    added in the future.

    Args:
        packets: Collection of parsed packets.

    Returns:
        A list of dictionaries containing metrics per UDP call.
    """
    sip_ports = {5060, 5061}
    rtp_min = 10000
    rtp_max = 20000
    calls: Dict[str, Dict[str, any]] = {}

    for pkt in packets:
        if pkt.protocol != "UDP":
            continue
        sp = pkt.source_port or 0
        dp = pkt.dest_port or 0
        is_sip = sp in sip_ports or dp in sip_ports
        is_rtp = (rtp_min <= sp <= rtp_max) or (rtp_min <= dp <= rtp_max)
        if not (is_sip or is_rtp):
            continue
        call_key = f"{pkt.source_ip}-{pkt.dest_ip}-{sp}-{dp}"
        if call_key not in calls:
            calls[call_key] = {
                "source_ip": pkt.source_ip,
                "dest_ip": pkt.dest_ip,
                "source_port": sp,
                "dest_port": dp,
                "protocol": "SIP" if is_sip else "RTP",
                "timestamps": [],
                "packet_count": 0,
            }
        call = calls[call_key]
        call["timestamps"].append(pkt.timestamp)
        call["packet_count"] += 1

    results: List[Dict[str, Optional[float]]] = []
    for call in calls.values():
        ts_sorted = sorted(call["timestamps"])
        jitter = 0.0
        if len(ts_sorted) > 1:
            diffs = [ts_sorted[i] - ts_sorted[i - 1] for i in range(1, len(ts_sorted))]
            mean = sum(diffs) / len(diffs)
            variance = sum((d - mean) ** 2 for d in diffs) / len(diffs)
            jitter = variance ** 0.5
        # Rough MOS estimation based on jitter thresholds (ms)
        mos = 4.5
        if jitter > 300:
            mos = 1.5
        elif jitter > 200:
            mos = 2.5
        elif jitter > 100:
            mos = 3.5
        result = {
            "source_ip": call["source_ip"],
            "dest_ip": call["dest_ip"],
            "source_port": call["source_port"],
            "dest_port": call["dest_port"],
            "protocol": call["protocol"],
            "jitter_ms": round(jitter, 2) if jitter else 0.0,
            "mos": round(mos, 2),
            "packet_count": call["packet_count"],
            "call_duration": call["packet_count"],
            "sip_failures": 0,
            "sip_errors": [],
            "nat_error": False,
            "firewall_blocked": False,
        }
        results.append(result)
    return results


def analyze_sip_calls(packets: List[Packet]) -> List[Dict[str, Optional[str]]]:
    """Reconstruct SIP call flows and detect missing messages.

    This function parses SIP signalling carried over UDP (ports 5060/5061) and
    attempts to group messages by Call‑ID.  It records the sequence of
    requests/responses per call and flags when important messages are
    missing (e.g. ACK after a 200 OK response, or BYE/CANCEL to terminate
    the call).  Only basic parsing is performed to avoid heavy
    dependencies; headers are extracted using simple string searches.

    Args:
        packets: List of parsed Packet objects.

    Returns:
        A list of dictionaries summarising each SIP call with flags for
        missing ACK/BYE.
    """
    from collections import defaultdict
    import re

    calls: Dict[str, Dict[str, any]] = {}

    for pkt in packets:
        if pkt.protocol != "UDP":
            continue
        if (pkt.source_port not in (5060, 5061)) and (pkt.dest_port not in (5060, 5061)):
            continue
        if not pkt.payload:
            continue
        try:
            text = pkt.payload.decode("latin-1", errors="ignore")
        except Exception:
            continue
        # Extract Call‑ID
        call_id_match = re.search(r"Call-ID:\s*([^\r\n]+)", text, re.IGNORECASE)
        if not call_id_match:
            continue
        call_id = call_id_match.group(1).strip()
        # Identify method or status code
        first_line = text.split("\r\n", 1)[0]
        method = first_line.split()[0] if first_line else "UNKNOWN"
        # Normalise responses
        if method[0].isdigit():
            method = method  # keep status code, e.g. 200
        else:
            method = method.upper()
        # Extract From/To URIs
        from_match = re.search(r"From:\s*([^;>\r\n]+)", text, re.IGNORECASE)
        to_match = re.search(r"To:\s*([^;>\r\n]+)", text, re.IGNORECASE)
        from_uri = from_match.group(1).strip() if from_match else None
        to_uri = to_match.group(1).strip() if to_match else None
        # Initialise call structure
        if call_id not in calls:
            calls[call_id] = {
                "call_id": call_id,
                "from": from_uri,
                "to": to_uri,
                "messages": [],
                "start_time": pkt.timestamp,
                "end_time": pkt.timestamp,
            }
        c = calls[call_id]
        c["messages"].append(method)
        c["end_time"] = pkt.timestamp
        # Update from/to if not already set
        if not c.get("from") and from_uri:
            c["from"] = from_uri
        if not c.get("to") and to_uri:
            c["to"] = to_uri

    results: List[Dict[str, any]] = []
    for call in calls.values():
        msgs = call["messages"]
        # Determine missing ACK/BYE
        # Expect ACK following a 200 response to INVITE
        missing_ack = False
        missing_bye = False
        if any(m.startswith("200") for m in msgs) and "ACK" not in msgs:
            missing_ack = True
        if not any(m == "BYE" or m == "CANCEL" for m in msgs):
            missing_bye = True
        results.append({
            "call_id": call["call_id"],
            "from": call.get("from"),
            "to": call.get("to"),
            "start_time_ms": round(call["start_time"], 2),
            "end_time_ms": round(call["end_time"], 2),
            "message_count": len(msgs),
            "methods": ",".join(msgs[:10]) + ("..." if len(msgs) > 10 else ""),
            "missing_ack": missing_ack,
            "missing_bye": missing_bye,
        })
    return results


def analyze_rtp_streams(packets: List[Packet]) -> List[Dict[str, any]]:
    """Analyse RTP streams for jitter and packet loss.

    This function inspects UDP packets in the RTP port range (10000–20000) and
    computes jitter and packet loss statistics per stream.  The stream key is
    defined by (source_ip, dest_ip, source_port, dest_port).  Sequence numbers
    are extracted from the first two bytes of the RTP payload (after the
    standard 12‑byte header).  Packet loss is computed by comparing the
    difference between the observed sequence numbers and the expected range.

    Args:
        packets: List of packets parsed from a PCAP file.

    Returns:
        A list of dictionaries summarising each RTP stream.
    """
    streams: Dict[str, Dict[str, any]] = {}
    rtp_min = 10000
    rtp_max = 20000
    for pkt in packets:
        if pkt.protocol != "UDP":
            continue
        sp = pkt.source_port or 0
        dp = pkt.dest_port or 0
        if not ((rtp_min <= sp <= rtp_max) or (rtp_min <= dp <= rtp_max)):
            continue
        if not pkt.payload or len(pkt.payload) < 12 + 2:
            continue
        # Determine stream key
        key = f"{pkt.source_ip}-{pkt.dest_ip}-{sp}-{dp}"
        if key not in streams:
            streams[key] = {
                "source_ip": pkt.source_ip,
                "dest_ip": pkt.dest_ip,
                "source_port": sp,
                "dest_port": dp,
                "timestamps": [],
                "seq_nums": [],
            }
        s = streams[key]
        # Extract RTP sequence number (2 bytes after first 2 bytes header)
        # RTP header: 0-1: flags/version, 2-3: sequence number
        seq_bytes = pkt.payload[2:4]
        seq_num = int.from_bytes(seq_bytes, byteorder="big")
        s["timestamps"].append(pkt.timestamp)
        s["seq_nums"].append(seq_num)

    results: List[Dict[str, any]] = []
    for s in streams.values():
        ts_sorted = sorted(s["timestamps"])
        jitter = 0.0
        if len(ts_sorted) > 1:
            diffs = [ts_sorted[i] - ts_sorted[i - 1] for i in range(1, len(ts_sorted))]
            mean = sum(diffs) / len(diffs)
            var = sum((d - mean) ** 2 for d in diffs) / len(diffs)
            jitter = var ** 0.5
        seqs = s["seq_nums"]
        lost = 0
        expected = len(seqs)
        if seqs:
            min_seq = min(seqs)
            max_seq = max(seqs)
            expected = max_seq - min_seq + 1
            lost = expected - len(seqs)
        loss_percent = (lost / expected * 100.0) if expected > 0 else 0.0
        results.append({
            "source_ip": s["source_ip"],
            "dest_ip": s["dest_ip"],
            "source_port": s["source_port"],
            "dest_port": s["dest_port"],
            "jitter_ms": round(jitter, 2),
            "packet_loss_pct": round(loss_percent, 2),
            "total_packets": len(seqs),
        })
    return results


def detect_floods(packets: List[Packet], threshold: int = 500) -> List[Dict[str, any]]:
    """Detect high‑rate traffic bursts that may indicate flood or storm attacks.

    The detection is performed per source IP and protocol by counting how many
    packets arrive within each one‑second interval.  If the count exceeds
    ``threshold``, a flood event is recorded.  This method can be used to
    flag SIP floods, ICMP storms or other volumetric attacks.

    Args:
        packets: List of Packet objects.
        threshold: Packet count per second above which a flood is reported.

    Returns:
        List of dictionaries describing detected flood events.
    """
    from collections import defaultdict
    events: List[Dict[str, any]] = []
    counters: Dict[Tuple[str, str, int], int] = defaultdict(int)
    for pkt in packets:
        # Bin timestamp to seconds
        sec = int(pkt.timestamp // 1000)
        key = (pkt.source_ip, pkt.protocol, sec)
        counters[key] += 1
    for (ip, proto, sec), count in counters.items():
        if count > threshold:
            events.append({
                "source_ip": ip,
                "protocol": proto,
                "timestamp_sec": sec,
                "packet_count": count,
            })
    return events


def detect_port_scans(
    packets: List[Packet],
    port_threshold: int = 50,
    ip_threshold: int = 50,
    time_window_ms: int = 60_000
) -> List[Dict[str, any]]:
    """Detect potential port and host scan activities.

    A port scan typically consists of a single source IP attempting to
    contact many different destination ports (vertical scan) or many
    destination hosts on the same or different ports (horizontal scan).
    This heuristic counts the number of unique destination ports and
    destination IPs contacted by each source within the entire capture
    window.  If the counts exceed configurable thresholds, an alert is
    raised.  A time window can optionally be specified to restrict
    counting to packets occurring within a certain time span (default
    60 seconds) relative to the first packet from that source.

    Args:
        packets: Parsed packet list from the PCAP.
        port_threshold: Number of unique destination ports that triggers
            a vertical scan alert.
        ip_threshold: Number of unique destination IPs that triggers a
            horizontal scan alert.
        time_window_ms: Maximum time span (in milliseconds) between the
            first and last observed packet from a source IP for counting.
            If set to 0, the entire capture duration is considered.

    Returns:
        A list of dictionaries describing detected scan events.  Each
        record contains the source IP, counts of unique ports and hosts
        contacted, and the type of scan detected (vertical, horizontal or
        both).
    """
    from collections import defaultdict

    # Track per source IP: first timestamp, set of dest ports and dest ips
    src_stats: Dict[str, Dict[str, any]] = {}

    for pkt in packets:
        if pkt.protocol != "TCP":
            # Scans typically leverage TCP SYN packets; UDP scans exist but
            # are harder to detect without payload inspection.  Focus on TCP.
            continue
        if pkt.source_ip == "Unknown" or pkt.dest_ip == "Unknown":
            continue
        src = pkt.source_ip
        if src not in src_stats:
            src_stats[src] = {
                "start_ts": pkt.timestamp,
                "end_ts": pkt.timestamp,
                "dest_ports": set(),
                "dest_ips": set(),
            }
        s = src_stats[src]
        s["end_ts"] = max(s["end_ts"], pkt.timestamp)
        # Only count within time window
        if time_window_ms > 0 and (pkt.timestamp - s["start_ts"]) > time_window_ms:
            # Reset counts for new window
            s["start_ts"] = pkt.timestamp
            s["dest_ports"] = set()
            s["dest_ips"] = set()
        if pkt.dest_port is not None:
            s["dest_ports"].add(pkt.dest_port)
        s["dest_ips"].add(pkt.dest_ip)

    scan_events: List[Dict[str, any]] = []
    for src, stats in src_stats.items():
        port_count = len(stats["dest_ports"])
        ip_count = len(stats["dest_ips"])
        scan_type = []
        if port_count >= port_threshold:
            scan_type.append("vertical")
        if ip_count >= ip_threshold:
            scan_type.append("horizontal")
        if scan_type:
            scan_events.append({
                "source_ip": src,
                "unique_dest_ports": port_count,
                "unique_dest_ips": ip_count,
                "scan_type": "+".join(scan_type),
            })
    return scan_events


def audit_firewall(packets: List[Packet]) -> List[Dict[str, any]]:
    """Perform a basic firewall audit based on observed traffic patterns.

    Because the parser does not decode TCP flags, this audit makes a
    simplified assumption: flows consisting of a single outgoing packet
    with no return traffic (i.e. only one packet observed for the
    source→destination pair) may indicate that the destination port is
    unreachable (blocked or filtered).  Similarly, flows with very few
    packets (<3) may indicate partially blocked connections or resets.

    The function groups packets by (source_ip, dest_ip, dest_port, protocol)
    and counts the number of packets observed for each grouping.  Flows
    meeting the above criteria are flagged and returned for further
    investigation.

    Args:
        packets: List of Packet objects.

    Returns:
        List of dictionaries describing potential firewall‑related issues.
        Each record contains the source IP, destination IP, destination
        port, protocol and packet count, along with a boolean indicating
        whether the connection is likely blocked.
    """
    from collections import defaultdict

    flow_counts: Dict[str, Dict[str, any]] = {}
    for pkt in packets:
        if pkt.protocol not in ("TCP", "UDP"):
            continue
        if pkt.source_ip == "Unknown" or pkt.dest_ip == "Unknown":
            continue
        key = f"{pkt.source_ip}-{pkt.dest_ip}-{pkt.dest_port}-{pkt.protocol}"
        if key not in flow_counts:
            flow_counts[key] = {
                "source_ip": pkt.source_ip,
                "dest_ip": pkt.dest_ip,
                "dest_port": pkt.dest_port,
                "protocol": pkt.protocol,
                "packet_count": 0,
            }
        flow_counts[key]["packet_count"] += 1

    results: List[Dict[str, any]] = []
    for flow in flow_counts.values():
        count = flow["packet_count"]
        # Heuristic: 1 packet means likely blocked (no reply); 2-3 packets mean possibly reset
        likely_blocked = count <= 1
        possibly_reset = 2 <= count <= 3
        results.append({
            "source_ip": flow["source_ip"],
            "dest_ip": flow["dest_ip"],
            "dest_port": flow["dest_port"],
            "protocol": flow["protocol"],
            "packet_count": count,
            "likely_blocked": likely_blocked,
            "possibly_reset": possibly_reset,
        })
    return [r for r in results if r["likely_blocked"] or r["possibly_reset"]]


def search_payload(packets: List[Packet], pattern: str) -> List[Dict[str, any]]:
    """Search for a string pattern in packet payloads.

    This helper allows quick grepping of PCAP data for indicators of
    compromise, sensitive information or protocol diagnostics.  The search is
    case-insensitive and performed on the decoded ASCII representation of
    each payload.  Non‑printable characters are ignored.

    Args:
        packets: List of Packet objects.
        pattern: Substring to search for.

    Returns:
        A list of dictionaries summarising packets where the pattern was
        found.  The payload snippet shows up to 40 characters around the
        first match.
    """
    pattern_lower = pattern.lower()
    results: List[Dict[str, any]] = []
    for pkt in packets:
        if not pkt.payload:
            continue
        try:
            text = pkt.payload.decode("latin-1", errors="ignore")
        except Exception:
            continue
        idx = text.lower().find(pattern_lower)
        if idx != -1:
            start = max(0, idx - 20)
            end = min(len(text), idx + len(pattern) + 20)
            snippet = text[start:end].replace("\r", " ").replace("\n", " ")
            results.append({
                "timestamp_ms": round(pkt.timestamp, 2),
                "source_ip": pkt.source_ip,
                "dest_ip": pkt.dest_ip,
                "protocol": pkt.protocol,
                "payload_snippet": snippet,
            })
    return results
