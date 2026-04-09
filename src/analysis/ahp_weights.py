"""AHP pairwise weight elicitation for the CBOM risk-scoring model.

Constructs a 5×5 pairwise comparison matrix using the Saaty 1–9 scale,
derives priority weights via the geometric-mean method, and reports the
Consistency Ratio (CR).

Run from the repository root:
    python3 research/src/analysis/ahp_weights.py
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Saaty random-index table (n = 1..10)
# ---------------------------------------------------------------------------
_RI: dict[int, float] = {
    1: 0.00, 2: 0.00, 3: 0.58, 4: 0.90, 5: 1.12,
    6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45, 10: 1.49,
}

# ---------------------------------------------------------------------------
# Factor labels
# ---------------------------------------------------------------------------
LABELS = [
    "V  (Quantum Vulnerability)",
    "E  (Exposure)",
    "S  (Data Sensitivity)",
    "L  (Longevity)",
    "Rep(Replaceability)",
]
SHORT = ["V", "E", "S", "L", "Rep"]

# ---------------------------------------------------------------------------
# Expert-assigned baseline weights (Eq. 1 in the paper)
# ---------------------------------------------------------------------------
EXPERT = [0.35, 0.20, 0.25, 0.10, 0.10]

# ---------------------------------------------------------------------------
# Pairwise comparison matrix  A[i][j] = importance of factor i over factor j
#
# Saaty scale: 1 = equal, 2 = equal-to-moderate, 3 = moderate,
#              4 = moderate-to-strong, 5 = strong, …  (reciprocals for j>i)
#
# Justifications
#   V vs E (2): Shor-vulnerable assets remain at risk even when air-gapped
#               (harvest-now-decrypt-later on stored ciphertext); exposure
#               governs attack-surface reach but cannot override algorithmic
#               quantum-safety.
#   V vs S (2): Vulnerability class is the primary binary qualifier;
#               data sensitivity amplifies urgency but does not change
#               quantum-resistance status.
#   V vs L (4): Longevity and replaceability are secondary ordering factors
#               within a tier; V and S jointly determine tier membership.
#   V vs Rep(4): Same reasoning as V vs L.
#   S vs E (2): Data classification has clear regulatory anchors (HIPAA,
#               GLBA, FISMA); network exposure is a softer operational
#               indicator.
#   S vs L (3): Sensitivity has stronger regulatory support as an
#               independent factor; longevity is an organizational estimate
#               with higher uncertainty.
#   S vs Rep(3): Same reasoning as S vs L.
#   E vs L (2): Exposure is directly observable and binarily verifiable
#               (internet-facing vs. not); longevity requires subjective
#               assessment.
#   E vs Rep(2): Same reasoning as E vs L.
#   L vs Rep(1): Both are secondary tie-breaker factors of equal weight;
#               longevity captures the HNDL window, replaceability captures
#               architectural friction, neither dominating the other.
# ---------------------------------------------------------------------------
MATRIX: list[list[float]] = [
    # V       E      S      L      Rep
    [1,       2,     2,     4,     4    ],  # V
    [1/2,     1,     1/2,   2,     2    ],  # E
    [1/2,     2,     1,     3,     3    ],  # S
    [1/4,     1/2,   1/3,   1,     1    ],  # L
    [1/4,     1/2,   1/3,   1,     1    ],  # Rep
]


# ---------------------------------------------------------------------------
# AHP computation helpers
# ---------------------------------------------------------------------------

def _geometric_mean_weights(matrix: list[list[float]]) -> list[float]:
    """Derive priority weights via the geometric-mean (row-product) method."""
    n = len(matrix)
    geo = []
    for row in matrix:
        product = 1.0
        for v in row:
            product *= v
        geo.append(product ** (1.0 / n))
    total = sum(geo)
    return [g / total for g in geo]


def _lambda_max(matrix: list[list[float]], weights: list[float]) -> float:
    """Compute the principal eigenvalue λ_max = mean(Aw_i / w_i)."""
    n = len(matrix)
    ratios = []
    for i in range(n):
        aw_i = sum(matrix[i][j] * weights[j] for j in range(n))
        ratios.append(aw_i / weights[i])
    return sum(ratios) / n


def _consistency(matrix: list[list[float]], weights: list[float]) -> tuple[float, float, float]:
    """Return (λ_max, CI, CR)."""
    n = len(matrix)
    lmax = _lambda_max(matrix, weights)
    ci = (lmax - n) / (n - 1)
    ri = _RI[n]
    cr = ci / ri if ri > 0 else 0.0
    return lmax, ci, cr


def _fmt(v: float) -> str:
    """Format a matrix cell as a short fraction string."""
    if v == 1:
        return "1"
    if v > 1:
        return str(int(v)) if v == int(v) else f"{v:.2f}"
    # reciprocal
    denom = round(1.0 / v)
    return f"1/{denom}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute(
    matrix: list[list[float]] | None = None,
    expert: list[float] | None = None,
) -> dict:
    """Run AHP on *matrix* and return a results dict.

    Defaults to the CBOM pairwise matrix and expert weights defined in
    this module.
    """
    if matrix is None:
        matrix = MATRIX
    if expert is None:
        expert = EXPERT

    weights = _geometric_mean_weights(matrix)
    lmax, ci, cr = _consistency(matrix, weights)
    max_delta = max(abs(w - e) for w, e in zip(weights, expert))

    return {
        "weights":   weights,
        "lambda_max": lmax,
        "ci":        ci,
        "cr":        cr,
        "max_delta": max_delta,
        "consistent": cr < 0.10,
    }


def run() -> dict:
    """Print full AHP report and return results dict."""
    n = len(MATRIX)
    res = compute()
    weights = res["weights"]

    print("=" * 65)
    print("AHP Weight Elicitation — CBOM Risk-Scoring Model")
    print("=" * 65)

    # --- Pairwise comparison matrix ---
    col_w = 7
    header = f"{'Factor':<26}" + "".join(f"{s:>{col_w}}" for s in SHORT)
    print("\nPairwise Comparison Matrix (Saaty 1–9 scale):")
    print(header)
    print("-" * (26 + col_w * n))
    for i in range(n):
        row = f"{SHORT[i]:<26}"
        for j in range(n):
            row += f"{_fmt(MATRIX[i][j]):>{col_w}}"
        print(row)

    # --- Priority weights ---
    print(f"\n{'Factor':<26} {'AHP weight':>12} {'Expert weight':>14} {'Δ':>8}")
    print("-" * 62)
    for i in range(n):
        delta = weights[i] - EXPERT[i]
        print(
            f"{LABELS[i]:<26} {weights[i]:>12.4f}"
            f" {EXPERT[i]:>14.4f} {delta:>+8.4f}"
        )
    print(f"\n  Max |Δ| = {res['max_delta']:.4f}  "
          f"(well within the ±0.10 sensitivity bound, Section IV.D)")

    # --- Consistency ---
    print("\nConsistency Check:")
    print(f"  λ_max = {res['lambda_max']:.4f}")
    print(f"  CI    = {res['ci']:.4f}  [ (λ_max − n) / (n − 1) ]")
    print(f"  RI    = {_RI[n]:.2f}   (Saaty random index, n = {n})")
    print(f"  CR    = {res['cr']:.4f}  "
          f"{'✓ CONSISTENT (CR < 0.10)' if res['consistent'] else '✗ INCONSISTENT'}")

    return res


if __name__ == "__main__":
    run()
