"""Generate figures/real_tier_distribution.pdf for paper02.

Stacked bar chart: X = sector (21), bars stacked by remediation tier
(Critical at bottom, then High, Medium, Low).  Reads the committed
JSON so no network access is required.

Run from the repository root:
    python3 research/src/experiments/plot_real_results.py

Output: papers/paper02/figures/real_tier_distribution.pdf
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from analysis.risk_scorer import score_asset
from experiments.real_inventory import _SECTOR_KEYS, build_inventory
from utils.schema import PriorityTier

_REPO_ROOT = Path(__file__).resolve().parents[3]
OUT = _REPO_ROOT / "papers" / "paper02" / "figures" / "real_tier_distribution.pdf"

# Abbreviated labels in the same order as _SECTOR_KEYS
SECTOR_LABELS = [
    "Govt.",
    "Finance",
    "Health.",
    "Energy",
    "Legal",
    "Telecom.",
    "Transport.",
    "Prof. Svcs.",
    "Tech.",
    "Educ.",
    "Retail",
    "Mfg.",
    "Media",
    "Travel",
    "Real Est.",
    "Social",
    "Science",
    "Nonprofit",
    "Sports",
    "Gaming",
    "Agri.",
]

TIERS       = [PriorityTier.CRITICAL, PriorityTier.HIGH,
               PriorityTier.MEDIUM,   PriorityTier.LOW]
TIER_LABELS = ["Critical", "High", "Medium", "Low"]
TIER_COLORS = ["#c0392b", "#e67e22", "#2980b9", "#27ae60"]


def _sector_of(asset) -> str:
    return asset.notes.split(";")[0].replace("sector=", "").strip()


def make_figure() -> None:
    assets, _ = build_inventory()
    results   = [score_asset(a) for a in assets]
    amap      = {a.asset_id: a for a in assets}

    counts: dict[str, dict[PriorityTier, int]] = {
        sk: {t: 0 for t in TIERS} for sk in _SECTOR_KEYS
    }
    for r in results:
        counts[_sector_of(amap[r.asset_id])][r.priority] += 1

    fig, ax = plt.subplots(figsize=(7.0, 2.8))
    x        = list(range(len(_SECTOR_KEYS)))
    bottoms  = [0] * len(_SECTOR_KEYS)

    for tier, color, label in zip(TIERS, TIER_COLORS, TIER_LABELS):
        heights = [counts[sk][tier] for sk in _SECTOR_KEYS]
        bars = ax.bar(
            x, heights, bottom=bottoms,
            color=color, width=0.65,
            edgecolor="black", linewidth=0.4,
            label=label,
        )
        for bar, h, bot in zip(bars, heights, bottoms):
            if h > 2:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bot + h / 2,
                    str(h),
                    ha="center", va="center",
                    fontsize=5.5, color="white", fontweight="bold",
                )
        bottoms = [b + h for b, h in zip(bottoms, heights)]

    ax.set_xticks(x)
    ax.set_xticklabels(SECTOR_LABELS, fontsize=6.0, rotation=45, ha="right")
    ax.set_ylabel("Endpoints", fontsize=7.5)
    ax.set_ylim(0, max(bottoms) + 5)
    ax.tick_params(axis="y", labelsize=7.0)
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    patches = [mpatches.Patch(color=c, label=lbl)
               for c, lbl in zip(TIER_COLORS, TIER_LABELS)]
    ax.legend(handles=patches, fontsize=6.0, loc="upper right",
              framealpha=0.85, edgecolor="#cccccc", handlelength=1.0,
              ncol=2)

    plt.tight_layout(pad=0.5)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUT, format="pdf", bbox_inches="tight")
    print(f"Saved {OUT}")


if __name__ == "__main__":
    make_figure()
