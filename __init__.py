"""
VoIP and Network PCAP Analyzer
==============================

This package provides a simple toolkit for reading packet capture (PCAP) files
and computing basic network and VoIP metrics.  It is designed to be used
within a Streamlit application, but the core functions can also be consumed
directly from other Python scripts.

The high‑level workflow is:

* Use :func:`voip_analyzer.parser.read_pcap` to parse a PCAP file into a
  list of packet dictionaries.  Each dictionary contains the timestamp
  (milliseconds since epoch), source and destination IP addresses, protocol
  name and optional source/destination ports.
* Use :func:`voip_analyzer.analysis.analyze_network` to compute per‑flow
  network metrics such as average latency, jitter, packet counts and
  detection of broadcast/multicast storms or possible NAT configuration
  issues.
* Use :func:`voip_analyzer.analysis.analyze_voip` to compute per‑call VoIP
  metrics.  Flows are identified by the 4‑tuple of source/destination IP
  addresses and ports.  Jitter is calculated from inter‑packet arrival
  variation and a rough Mean Opinion Score (MOS) is estimated based on
  jitter.

Note that this project intentionally avoids dependencies outside of the
Python standard library so that it can run in minimal environments without
package managers.  The parsing logic covers IPv4 traffic and basic
Ethernet, TCP and UDP parsing.  Other protocols (IPv6, VLAN tags, etc.)
are ignored.
"""