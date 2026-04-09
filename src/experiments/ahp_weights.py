"""AHP weight elicitation for CBOM risk-scoring model.

Reproduces the AHP computation reported in Section IV-C of the paper:
  - 5x5 pairwise comparison matrix (Saaty 1--9 scale)
  - Geometric-mean (row-product) weight derivation
  - lambda_max approximation and Consistency Ratio (CR) computation

Reference: Saaty, T.L. (1980). The Analytic Hierarchy Process.
           McGraw-Hill, New York. doi:10.1007/978-3-642-50244-6

Expected output:
  AHP-derived weights : [0.389, 0.169, 0.263, 0.090, 0.090]
  lambda_max          : 5.039
  CI                  : 0.0098
  CR                  : 0.009 (< 0.10  =>  matrix is acceptably consistent)
  Max |Delta| vs expert weights: 0.039
"""

# ---------------------------------------------------------------------------
# Pairwise comparison matrix  (factors: V, E, S, L, Rep)
# A[i][j] = importance of factor i relative to factor j (Saaty 1-9 scale)
# ---------------------------------------------------------------------------
A = [
    #  V      E      S      L      Rep
    [1.0,    2.0,   2.0,   4.0,   4.0],   # V
    [1/2,    1.0,   1/2,   2.0,   2.0],   # E
    [1/2,    2.0,   1.0,   3.0,   3.0],   # S
    [1/4,    1/2,   1/3,   1.0,   1.0],   # L
    [1/4,    1/2,   1/3,   1.0,   1.0],   # Rep
]
FACTORS = ["V (Quantum Vuln)", "E (Exposure)", "S (Sensitivity)",
           "L (Longevity)", "Rep (Replaceability)"]
EXPERT_WEIGHTS = [0.35, 0.20, 0.25, 0.10, 0.10]

# Saaty Random Index for n=5, from Saaty (1980) Table 3
RI_5 = 1.12

n = len(A)


def geometric_mean_weights(matrix: list[list[float]]) -> list[float]:
    """Derive weights by the row-product (geometric-mean) method."""
    raw = []
    for row in matrix:
        product = 1.0
        for val in row:
            product *= val
        raw.append(product ** (1.0 / n))
    total = sum(raw)
    return [r / total for r in raw]


def lambda_max(matrix: list[list[float]], weights: list[float]) -> float:
    """Approximate lambda_max as (1/n) * sum_i (Aw)_i / w_i."""
    total = 0.0
    for i in range(n):
        aw_i = sum(matrix[i][j] * weights[j] for j in range(n))
        total += aw_i / weights[i]
    return total / n


def consistency_ratio(lmax: float) -> tuple[float, float]:
    """Return (CI, CR) where CI = (lambda_max - n)/(n-1), CR = CI/RI."""
    ci = (lmax - n) / (n - 1)
    cr = ci / RI_5
    return ci, cr


def main() -> None:
    weights = geometric_mean_weights(A)
    lmax = lambda_max(A, weights)
    ci, cr = consistency_ratio(lmax)

    print("=" * 55)
    print("AHP Weight Elicitation — CBOM Risk Scoring Model")
    print("=" * 55)
    print(f"\n{'Factor':<25} {'AHP w':>8} {'Expert w':>10} {'Delta':>8}")
    print("-" * 55)
    for i, factor in enumerate(FACTORS):
        delta = weights[i] - EXPERT_WEIGHTS[i]
        print(f"{factor:<25} {weights[i]:>8.3f} {EXPERT_WEIGHTS[i]:>10.3f} "
              f"{delta:>+8.3f}")
    print("-" * 55)
    max_delta = max(abs(weights[i] - EXPERT_WEIGHTS[i]) for i in range(n))
    print(f"\nlambda_max : {lmax:.3f}")
    print(f"CI         : {ci:.4f}")
    print(f"CR         : {cr:.4f}  ({'OK < 0.10' if cr < 0.10 else 'FAIL >= 0.10'})")
    print(f"RI_5       : {RI_5} (Saaty 1980)")
    print(f"Max |Delta|: {max_delta:.3f}")


if __name__ == "__main__":
    main()
