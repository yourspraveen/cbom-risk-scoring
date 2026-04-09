"""Weighted risk scoring for CBOM assets.

Formula:
    R = 0.35·V + 0.20·E + 0.25·S + 0.10·L + 0.10·(6 − Rep)

Where:
    V   = Quantum vulnerability score (Broken=5, Weakened=3, Safe=1, Unknown=4)
    E   = Exposure (1–5, internet-facing = 5)
    S   = Data sensitivity/classification (Public=1 → Top Secret=5)
    L   = Longevity mapped to 1–5 (<1yr=1, 1-3=2, 3-7=3, 7-15=4, 15+=5)
    Rep = Replaceability (1=very hard, 5=trivially easy)

Priority tiers:
    Critical: R >= 4.0
    High:     R >= 3.0
    Medium:   R >= 2.0
    Low:      R <  2.0
"""

from dataclasses import dataclass

from utils.schema import CryptoAsset, PriorityTier

# Weight constants
W_V = 0.35
W_E = 0.20
W_S = 0.25
W_L = 0.10
W_R = 0.10


def _longevity_score(years: int) -> float:
    """Map longevity (years) to a 1–5 score."""
    if years < 1:
        return 1.0
    if years < 3:
        return 2.0
    if years < 7:
        return 3.0
    if years < 15:
        return 4.0
    return 5.0


@dataclass
class RiskResult:
    asset_id: str
    score: float
    priority: PriorityTier
    v: float
    e: float
    s: float
    longevity: float
    rep_term: float


def score_asset(asset: CryptoAsset) -> RiskResult:
    """Compute weighted risk score for a single CryptoAsset."""
    v = float(asset.quantum_vulnerability.value)
    e = float(asset.exposure)
    s = float(asset.data_classification.value)
    longevity = _longevity_score(asset.longevity_years)
    rep_term = 6.0 - float(asset.replaceability)

    score = W_V * v + W_E * e + W_S * s + W_L * longevity + W_R * rep_term

    if score >= 4.0:
        priority = PriorityTier.CRITICAL
    elif score >= 3.0:
        priority = PriorityTier.HIGH
    elif score >= 2.0:
        priority = PriorityTier.MEDIUM
    else:
        priority = PriorityTier.LOW

    return RiskResult(
        asset_id=asset.asset_id,
        score=round(score, 3),
        priority=priority,
        v=v,
        e=e,
        s=s,
        longevity=longevity,
        rep_term=rep_term,
    )
