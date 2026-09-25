from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CodecImpairment:
    ie: float
    bpl: float
    confidence: str


# Operational codec profiles. PCMU/PCMA/G729/G723 values follow commonly used
# narrowband E-model planning profiles. Other codecs use conservative fallback
# values and are explicitly labelled approximate rather than standards-conformant.
CODEC_PROFILES = {
    "PCMU": CodecImpairment(0.0, 25.1, "high"),
    "PCMA": CodecImpairment(0.0, 25.1, "high"),
    "G729": CodecImpairment(11.0, 19.0, "high"),
    "G723": CodecImpairment(15.0, 16.1, "medium"),
    "G728": CodecImpairment(7.0, 18.0, "medium"),
    "GSM": CodecImpairment(20.0, 10.0, "medium"),
    "G726": CodecImpairment(7.0, 18.0, "low"),
    "ILBC": CodecImpairment(10.0, 20.0, "low"),
    "G722": CodecImpairment(4.0, 25.0, "low"),
    "OPUS": CodecImpairment(5.0, 25.0, "low"),
}
DEFAULT_PROFILE = CodecImpairment(10.0, 20.0, "low")


def delay_impairment(one_way_ms: float) -> float:
    d = max(0.0, one_way_ms)
    return 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)


def equipment_impairment(codec: str, loss_percent: float, burst_ratio: float) -> tuple[float, CodecImpairment]:
    profile = CODEC_PROFILES.get(codec.upper(), DEFAULT_PROFILE)
    ppl = max(0.0, loss_percent)
    br = max(1.0, burst_ratio)
    if ppl <= 0:
        return profile.ie, profile
    denom = (ppl / br) + profile.bpl
    ie_eff = profile.ie + (95.0 - profile.ie) * ppl / denom
    return ie_eff, profile


def r_to_mos(r: float) -> float:
    if r <= 0: return 1.0
    if r >= 100: return 4.5
    mos = 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
    return min(4.5, max(1.0, mos))


def estimate_mos(codec: str, loss_percent: float, burst_ratio: float = 1.0, one_way_delay_ms: float | None = None) -> tuple[float, float, str]:
    ie_eff, profile = equipment_impairment(codec, loss_percent, burst_ratio)
    id_factor = delay_impairment(one_way_delay_ms or 0.0) if one_way_delay_ms is not None else 0.0
    r = max(0.0, min(100.0, 93.2 - id_factor - ie_eff))
    mos = r_to_mos(r)
    if one_way_delay_ms is None:
        note = f"E-model operacional sem atraso boca-ouvido; perfil de codec {profile.confidence}."
    else:
        note = f"E-model operacional usando atraso estimado de RTT/2; perfil de codec {profile.confidence}."
    return round(mos, 2), round(r, 1), note
