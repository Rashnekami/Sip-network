from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass(slots=True)
class Packet:
    number: int
    timestamp: float  # unix seconds
    captured_len: int
    original_len: int
    link_type: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: str = "UNKNOWN"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    payload: bytes = b""
    vlan_ids: tuple[int, ...] = ()
    ip_version: Optional[int] = None
    fragmented: bool = False
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    dscp: Optional[int] = None
    # (key, byte_offset, more_fragments, l4_bytes, l4_proto) while an IP fragment is pending reassembly.
    frag_info: Optional[tuple[Any, int, bool, bytes, int]] = None
    parse_notes: tuple[str, ...] = ()

    def flow4(self) -> tuple[Any, ...]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)


@dataclass(slots=True)
class SdpCodec:
    payload_type: int
    name: str
    clock_rate: int
    channels: int = 1
    fmtp: Optional[str] = None


@dataclass(slots=True)
class SdpMedia:
    media: str
    port: int
    proto: str
    payload_types: list[int]
    connection_ip: Optional[str] = None
    codecs: dict[int, SdpCodec] = field(default_factory=dict)
    direction: str = "sendrecv"
    ptime_ms: Optional[float] = None
    rtcp_port: Optional[int] = None
    rtcp_ip: Optional[str] = None
    ice_candidates: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SdpSession:
    connection_ip: Optional[str]
    media: list[SdpMedia] = field(default_factory=list)
    origin_ip: Optional[str] = None


@dataclass(slots=True)
class SipMessage:
    packet_number: int
    timestamp: float
    transport: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    start_line: str
    is_request: bool
    method: Optional[str]
    status_code: Optional[int]
    reason: Optional[str]
    call_id: Optional[str]
    cseq_number: Optional[int]
    cseq_method: Optional[str]
    from_uri: Optional[str]
    to_uri: Optional[str]
    from_tag: Optional[str]
    to_tag: Optional[str]
    via_branch: Optional[str]
    via_sent_by: Optional[str]
    via_received: Optional[str]
    via_rport: Optional[str]
    contact_uri: Optional[str]
    contact_host: Optional[str]
    user_agent: Optional[str]
    server: Optional[str]
    content_type: Optional[str]
    body: str = ""
    sdp: Optional[SdpSession] = None
    raw_headers: dict[str, list[str]] = field(default_factory=dict)
    dscp: Optional[int] = None
    # Declared Content-Length vs bytes really carried (UDP, one message per datagram). A mismatch is a SIP ALG signature.
    content_length_declared: Optional[int] = None
    body_bytes_actual: Optional[int] = None

    def header(self, name: str) -> Optional[str]:
        vals = self.raw_headers.get(name.lower())
        return vals[0] if vals else None


@dataclass(slots=True)
class SipCall:
    call_id: str
    from_uri: Optional[str]
    to_uri: Optional[str]
    messages: list[SipMessage]
    invite_cseq: Optional[int]
    started_at: float
    ended_at: float
    connected_at: Optional[float]
    terminated_at: Optional[float]
    first_provisional_at: Optional[float]
    ringing_at: Optional[float]
    early_media_at: Optional[float]
    final_status: Optional[int]
    final_reason: Optional[str]
    missing_ack: bool
    termination_observed: bool
    retransmissions: int
    media_endpoints: list[dict[str, Any]] = field(default_factory=list)
    # Outcome and NOC timings.
    outcome: str = "unknown"
    caller_ip: Optional[str] = None
    callee_ip: Optional[str] = None
    pdd_ms: Optional[float] = None
    setup_time_ms: Optional[float] = None
    ring_time_ms: Optional[float] = None
    trying_ms: Optional[float] = None
    duration_s: Optional[float] = None
    disconnect_side: Optional[str] = None
    disconnect_method: Optional[str] = None
    q850_cause: Optional[int] = None
    q850_text: Optional[str] = None
    reason_header: Optional[str] = None
    auth_challenges: int = 0
    invite_attempts: int = 0
    no_response: bool = False
    # Dialog model (RFC 3261 sec. 12): one entry per remote tag that answered.
    dialogs: list[dict[str, Any]] = field(default_factory=list)
    forked: bool = False
    early_dialogs: int = 0
    reinvites: int = 0
    hold_events: list[dict[str, Any]] = field(default_factory=list)
    transfers: list[dict[str, Any]] = field(default_factory=list)
    caller_user_agent: Optional[str] = None
    callee_user_agent: Optional[str] = None
    p_asserted_identity: Optional[str] = None
    diversion: Optional[str] = None
    negotiated_codecs: list[str] = field(default_factory=list)
    unanswered_ack_dialogs: list[str] = field(default_factory=list)
    session_expires: Optional[int] = None

    @property
    def connected(self) -> bool:
        return self.connected_at is not None


@dataclass(slots=True)
class RtpPacket:
    packet_number: int
    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    marker: int
    payload_type: int
    sequence: int
    rtp_timestamp: int
    ssrc: int
    payload_len: int
    header_len: int
    padding_len: int = 0


@dataclass(slots=True)
class RtpStream:
    stream_id: str
    call_id: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    ssrc: int
    payload_type: int
    codec: str
    clock_rate: int
    packets: int
    unique_packets: int
    expected_packets: int
    lost_packets: int
    loss_percent: float
    duplicates: int
    out_of_order: int
    jitter_ms: float
    max_interarrival_gap_ms: float
    duration_s: float
    bitrate_kbps: float
    ptime_ms: Optional[float]
    burst_ratio: float
    dtmf_events: list[int] = field(default_factory=list)
    dtmf_digits: str = ""
    rtt_ms: Optional[float] = None
    mos: Optional[float] = None
    r_factor: Optional[float] = None
    mos_note: Optional[str] = None
    dscp: Optional[int] = None
    dscp_values: dict[int, int] = field(default_factory=dict)
    first_packet_at: Optional[float] = None
    last_packet_at: Optional[float] = None
    gaps_over_threshold: int = 0
    comfort_noise_packets: int = 0
    unexpected_payload_types: list[int] = field(default_factory=list)
    ssrc_changes_on_flow: int = 0
    rtcp_remote_loss_pct: Optional[float] = None
    rtcp_remote_cumulative_lost: Optional[int] = None
    rtcp_remote_jitter_ms: Optional[float] = None
    sdp_destination_match: Optional[bool] = None


@dataclass(slots=True)
class Diagnostic:
    severity: str
    code: str
    title: str
    detail: str
    confidence: str
    call_id: Optional[str] = None
    stream_id: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    category: str = ""


@dataclass(slots=True)
class AnalysisResult:
    capture: dict[str, Any]
    calls: list[SipCall]
    rtp_streams: list[RtpStream]
    diagnostics: list[Diagnostic]
    network_flows: list[dict[str, Any]]
    security: list[dict[str, Any]]
    kpis: dict[str, Any] = field(default_factory=dict)
    registrations: list[dict[str, Any]] = field(default_factory=list)
    nat: list[dict[str, Any]] = field(default_factory=list)
    ddos: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = "2.2"

    def to_dict(self, include_messages: bool = True) -> dict[str, Any]:
        calls = [asdict(x) for x in self.calls]
        if not include_messages:
            for c in calls:
                c["messages"] = [{k: m[k] for k in ("packet_number", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "start_line", "cseq_number", "cseq_method")} for m in c["messages"]]
        return {
            "schema_version": self.schema_version,
            "capture": self.capture,
            "kpis": self.kpis,
            "registrations": self.registrations,
            "calls": calls,
            "rtp_streams": [asdict(x) for x in self.rtp_streams],
            "diagnostics": [asdict(x) for x in self.diagnostics],
            "network_flows": self.network_flows,
            "security": self.security,
            "nat": self.nat,
            "ddos": self.ddos,
        }
