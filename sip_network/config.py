from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Thresholds:
    """Limits used by the diagnostic rules. NOC teams can tune these per customer/trunk."""

    # Signalling
    pdd_warning_ms: float = 5000.0
    pdd_critical_ms: float = 10000.0
    retransmissions_warning: int = 3
    short_call_s: float = 3.0
    auth_challenge_loop: int = 2
    # Media
    loss_info_pct: float = 1.0
    loss_warning_pct: float = 2.0
    loss_critical_pct: float = 5.0
    jitter_info_ms: float = 20.0
    jitter_warning_ms: float = 30.0
    jitter_critical_ms: float = 50.0
    mos_warning: float = 3.6
    mos_critical: float = 3.1
    rtp_gap_ms: float = 500.0
    media_start_delay_s: float = 1.5
    rtp_after_bye_s: float = 2.0
    expected_rtp_dscp: int = 46  # EF
    expected_sip_dscp: tuple[int, ...] = (24, 26, 40, 46)  # CS3, AF31, CS5, EF
    # Security
    method_rate_per_s: float = 20.0
    other_method_rate_per_s: float = 50.0
    scan_distinct_targets: int = 30
    brute_force_failures: int = 10
    enumeration_distinct_users: int = 10
    options_sweep_hosts: int = 10
    toll_fraud_destinations: int = 5
    home_country_code: str = "55"
    # NAT
    nat_register_expires_s: int = 120
    # DDoS / floods (per destination, per second)
    ddos_min_pps: float = 2000.0
    ddos_min_seconds: int = 3
    ddos_baseline_factor: float = 10.0
    ddos_distributed_sources: int = 50
    syn_flood_min_pps: float = 200.0
    sip_flood_min_rps: float = 100.0
    icmp_flood_min_pps: float = 500.0
    reflection_min_pps: float = 200.0
    # WebRTC
    webrtc_setup_warning_ms: float = 3000.0
    webrtc_consent_lost_checks: int = 3
    # Network
    fragments_lost_warning: int = 1


DEFAULT_THRESHOLDS = Thresholds()
