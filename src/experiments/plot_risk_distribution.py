"""Generate figures/risk_distribution.pdf for paper02.

Run from the repository root:
    python3 research/src/experiments/plot_risk_distribution.py

Output: papers/paper02/figures/risk_distribution.pdf
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from analysis.risk_scorer import score_asset
from experiments.tls_inventory import build_inventory
from utils.schema import PriorityTier

TIERS  = [PriorityTier.CRITICAL, PriorityTier.HIGH, PriorityTier.MEDIUM, PriorityTier.LOW]
LABELS = ["Critical", "High", "Medium", "Low"]
COLORS = ["#c0392b", "#e67e22", "#2980b9", "#27ae60"]

OUT = Path(__file__).resolve().parents[3] / "papers" / "paper02" / "figures" / "risk_distribution.pdf"


def make_figure() -> None:
    assets  = build_inventory()
    results = [score_asset(a) for a in assets]
    total   = len(results)
    counts  = [sum(1 for r in results if r.priority == t) for t in TIERS]

    fig, ax = plt.subplots(figsize=(3.5, 2.4))
    bars = ax.bar(LABELS, counts, color=COLORS, width=0.55, edgecolor="black", linewidth=0.6)

    for bar, count in zip(bars, counts):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.25,
            f"{count}\n({100 * count / total:.0f}%)",
            ha="center", va="bottom", fontsize=7.5, linespacing=1.3,
        )

    ax.set_ylabel("Number of Assets", fontsize=8)
    ax.set_xlabel("Remediation Priority Tier", fontsize=8)
    ax.set_ylim(0, max(counts) + 3)
    ax.tick_params(labelsize=8)
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout(pad=0.4)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUT, format="pdf", bbox_inches="tight")
    print(f"Saved {OUT}")


if __name__ == "__main__":
    make_figure()
