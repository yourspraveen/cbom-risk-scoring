"""Weight sensitivity analysis for the CBOM risk-scoring model.

Perturbs each of the five weights by ±0.10 (redistributing the delta
proportionally across the remaining weights) and reports how many of
the 30 synthetic TLS assets change priority tier.

Run from the repository root:
    python3 research/src/experiments/weight_sensitivity.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collections import Counter

from analysis.risk_scorer import W_E, W_L, W_R, W_S, W_V, _longevity_score
from experiments.tls_inventory import build_inventory
from utils.schema import PriorityTier

BASE_WEIGHTS = (W_V, W_E, W_S, W_L, W_R)
WEIGHT_LABELS = ("V", "E", "S", "L", "Rep")
DELTA = 0.10


def _tier(score: float) -> PriorityTier:
    if score >= 4.0:
        return PriorityTier.CRITICAL
    if score >= 3.0:
        return PriorityTier.HIGH
    if score >= 2.0:
        return PriorityTier.MEDIUM
    return PriorityTier.LOW


def score_with_weights(asset, wv: float, we: float, ws: float, wl: float, wr: float) -> PriorityTier:
    v = float(asset.quantum_vulnerability.value)
    e = float(asset.exposure)
    s = float(asset.data_classification.value)
    longevity = _longevity_score(asset.longevity_years)
    rep = 6.0 - float(asset.replaceability)
    return _tier(wv * v + we * e + ws * s + wl * longevity + wr * rep)


def perturb(base: tuple, idx: int, delta: float) -> tuple:
    """Shift weight[idx] by delta, redistribute proportionally to others."""
    weights = list(base)
    weights[idx] += delta
    others = [j for j in range(len(base)) if j != idx]
    other_sum = sum(base[j] for j in others)
    for j in others:
        weights[j] -= delta * (base[j] / other_sum)
    weights = [max(0.01, w) for w in weights]
    total = sum(weights)
    return tuple(w / total for w in weights)


def run() -> None:
    assets = build_inventory()
    base_tiers = {a.asset_id: score_with_weights(a, *BASE_WEIGHTS) for a in assets}

    def counts(tiers: dict) -> tuple:
        c = Counter(tiers.values())
        return (c[PriorityTier.CRITICAL], c[PriorityTier.HIGH],
                c[PriorityTier.MEDIUM], c[PriorityTier.LOW])

    print(f"{'Perturbation':<18} {'V':>5} {'E':>5} {'S':>5} {'L':>5} {'Rep':>5} "
          f"{'Crit':>6} {'High':>6} {'Med':>6} {'Low':>6} {'Changes':>8}")
    print("-" * 80)

    crit, high, med, low = counts(base_tiers)
    wv, we, ws, wl, wr = BASE_WEIGHTS
    print(f"{'Baseline':<18} {wv:>5.2f} {we:>5.2f} {ws:>5.2f} {wl:>5.2f} {wr:>5.2f} "
          f"{crit:>6} {high:>6} {med:>6} {low:>6} {'—':>8}")

    for i, lbl in enumerate(WEIGHT_LABELS):
        for sign, sym in ((-1, "-"), (+1, "+")):
            new_w = perturb(BASE_WEIGHTS, i, sign * DELTA)
            new_tiers = {a.asset_id: score_with_weights(a, *new_w) for a in assets}
            changes = sum(1 for aid in base_tiers if base_tiers[aid] != new_tiers[aid])
            crit, high, med, low = counts(new_tiers)
            label = f"w_{lbl} {sym}0.10"
            print(f"{label:<18} {new_w[0]:>5.2f} {new_w[1]:>5.2f} {new_w[2]:>5.2f} "
                  f"{new_w[3]:>5.2f} {new_w[4]:>5.2f} "
                  f"{crit:>6} {high:>6} {med:>6} {low:>6} {changes:>8}")


if __name__ == "__main__":
    run()
