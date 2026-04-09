"""Generate figures/score_scatter.pdf for paper02.

Strip/scatter plot of risk scores grouped by quantum vulnerability class,
colour-coded by priority tier, with tier-boundary lines.  Shows that
vulnerability class alone does not determine tier: exposure, data
sensitivity, and longevity differentiate assets within the same class.

Run from the repository root:
    python3 research/src/experiments/plot_score_scatter.py

Output: papers/paper02/figures/score_scatter.pdf
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from analysis.risk_scorer import score_asset
from experiments.tls_inventory import build_inventory
from utils.schema import PriorityTier, QuantumVulnerability

OUT = Path(__file__).resolve().parents[3] / "papers" / "paper02" / "figures" / "score_scatter.pdf"

# Display order and labels for vulnerability classes
VULN_ORDER = [
    QuantumVulnerability.BROKEN,
    QuantumVulnerability.UNKNOWN,
    QuantumVulnerability.WEAKENED,
    QuantumVulnerability.SAFE,
]
VULN_LABELS = ["Broken\n(Shor)", "Unknown", "Weakened\n(Grover)", "Safe\n(PQC)"]

TIER_COLORS = {
    PriorityTier.CRITICAL: "#c0392b",
    PriorityTier.HIGH:     "#e67e22",
    PriorityTier.MEDIUM:   "#2980b9",
    PriorityTier.LOW:      "#27ae60",
}
TIER_BOUNDARIES = [4.0, 3.0, 2.0]
TIER_LABELS     = ["Critical", "High", "Medium", "Low"]


def make_figure() -> None:
    assets  = build_inventory()
    results = [score_asset(a) for a in assets]
    asset_map = {a.asset_id: a for a in assets}

    # Group scores by vulnerability class
    groups: dict[QuantumVulnerability, list[float]] = {v: [] for v in VULN_ORDER}
    colors_by_group: dict[QuantumVulnerability, list[str]] = {v: [] for v in VULN_ORDER}
    for r in results:
        vuln = asset_map[r.asset_id].quantum_vulnerability
        groups[vuln].append(r.score)
        colors_by_group[vuln].append(TIER_COLORS[r.priority])

    fig, ax = plt.subplots(figsize=(3.5, 3.0))

    rng = np.random.default_rng(42)
    for x_idx, vuln in enumerate(VULN_ORDER):
        scores = groups[vuln]
        colors = colors_by_group[vuln]
        # Jitter x positions to avoid overplotting
        jitter = rng.uniform(-0.18, 0.18, size=len(scores))
        ax.scatter(
            [x_idx + j for j in jitter],
            scores,
            c=colors,
            s=36,
            edgecolors="white",
            linewidths=0.4,
            zorder=3,
        )

    # Tier boundary lines
    boundary_styles = dict(linestyle="--", linewidth=0.8, color="#555555", zorder=2)
    for boundary in TIER_BOUNDARIES:
        ax.axhline(boundary, **boundary_styles)

    # Tier labels on the right margin
    tier_mid_y = [4.5, 3.5, 2.5, 1.4]
    for label, y in zip(TIER_LABELS, tier_mid_y):
        ax.text(3.62, y, label, va="center", ha="left", fontsize=6.5, color="#333333")

    ax.set_xticks(range(len(VULN_ORDER)))
    ax.set_xticklabels(VULN_LABELS, fontsize=7.5)
    ax.set_ylabel("Risk Score $R$", fontsize=8)
    ax.set_xlabel("Quantum Vulnerability Class", fontsize=8)
    ax.set_ylim(1.0, 5.4)
    ax.set_xlim(-0.5, 4.1)
    ax.tick_params(labelsize=7.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # Legend for tiers
    legend_patches = [
        mpatches.Patch(color=TIER_COLORS[t], label=t.value)
        for t in PriorityTier
    ]
    ax.legend(
        handles=legend_patches,
        fontsize=6.5,
        loc="lower left",
        framealpha=0.85,
        edgecolor="#cccccc",
        handlelength=1.0,
    )

    plt.tight_layout(pad=0.4)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUT, format="pdf", bbox_inches="tight")
    print(f"Saved {OUT}")


if __name__ == "__main__":
    make_figure()
