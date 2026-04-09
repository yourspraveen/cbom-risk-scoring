"""Real-world CBOM inventory from passive TLS scan results.

Reads research/data/real_tls_scan_sectors.json (committed; no network access),
maps each record to a CryptoAsset using sector-based heuristics, scores
every asset with the existing risk scorer, and prints:
  - A prioritised remediation table (sorted by score descending)
  - A tier summary (overall and by sector)

Sector heuristics (all endpoints have V=5, Broken):
  Government          : E=4, S=SECRET(4),       longevity=15 yr, rep=2  → R=4.45 Critical
  Finance             : E=5, S=CONFIDENTIAL(3), longevity=10 yr, rep=2  → R=4.30 Critical
  Healthcare          : E=4, S=CONFIDENTIAL(3), longevity=10 yr, rep=2  → R=4.10 Critical
  Energy/Utilities    : E=4, S=SECRET(4),       longevity=15 yr, rep=2  → R=4.45 Critical
  Legal               : E=4, S=CONFIDENTIAL(3), longevity=10 yr, rep=2  → R=4.10 Critical
  Telecommunications  : E=5, S=CONFIDENTIAL(3), longevity=5 yr,  rep=3  → R=4.10 Critical
  Transportation      : E=4, S=CONFIDENTIAL(3), longevity=7 yr,  rep=3  → R=4.00 Critical
  Professional Svc    : E=4, S=CONFIDENTIAL(3), longevity=7 yr,  rep=3  → R=4.00 Critical
  Technology          : E=5, S=INTERNAL(2),     longevity=5 yr,  rep=4  → R=3.75 High
  Education           : E=4, S=INTERNAL(2),     longevity=5 yr,  rep=3  → R=3.65 High
  Retail/Ecommerce    : E=5, S=INTERNAL(2),     longevity=5 yr,  rep=3  → R=3.85 High
  Manufacturing       : E=4, S=INTERNAL(2),     longevity=10 yr, rep=3  → R=3.75 High
  Media/News          : E=5, S=PUBLIC(1),        longevity=3 yr,  rep=5  → R=3.30 High
  Travel/Hospitality  : E=5, S=INTERNAL(2),     longevity=5 yr,  rep=4  → R=3.75 High
  Real Estate         : E=4, S=INTERNAL(2),     longevity=5 yr,  rep=3  → R=3.65 High
  Social Media        : E=5, S=INTERNAL(2),     longevity=3 yr,  rep=4  → R=3.65 High
  Science/Research    : E=4, S=INTERNAL(2),     longevity=7 yr,  rep=4  → R=3.65 High
  Nonprofit           : E=3, S=INTERNAL(2),     longevity=5 yr,  rep=4  → R=3.35 High
  Sports              : E=5, S=PUBLIC(1),        longevity=3 yr,  rep=5  → R=3.30 High
  Gaming              : E=5, S=PUBLIC(1),        longevity=3 yr,  rep=5  → R=3.30 High
  Agriculture/Food    : E=3, S=INTERNAL(2),     longevity=5 yr,  rep=4  → R=3.35 High

Run from the repository root:
    python3 research/src/experiments/real_inventory.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.risk_scorer import RiskResult, score_asset
from utils.schema import (
    AssetType,
    CryptoAsset,
    DataClassification,
    PriorityTier,
    QuantumVulnerability,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_JSON_PATH = _REPO_ROOT / "research" / "data" / "real_tls_scan_sectors.json"

# ---------------------------------------------------------------------------
# Sector heuristics — 21 sectors, keys match JSON sector field values
# ---------------------------------------------------------------------------
_SECTOR: dict[str, dict] = {
    "Government": dict(
        exposure=4,
        data_classification=DataClassification.SECRET,
        longevity_years=15,
        replaceability=2,
    ),
    "Finance": dict(
        exposure=5,
        data_classification=DataClassification.CONFIDENTIAL,
        longevity_years=10,
        replaceability=2,
    ),
    "Healthcare": dict(
        exposure=4,
        data_classification=DataClassification.CONFIDENTIAL,
        longevity_years=10,
        replaceability=2,
    ),
    "Energy/Utilities": dict(
        exposure=4,
        data_classification=DataClassification.SECRET,
        longevity_years=15,
        replaceability=2,
    ),
    "Legal": dict(
        exposure=4,
        data_classification=DataClassification.CONFIDENTIAL,
        longevity_years=10,
        replaceability=2,
    ),
    "Telecommunications": dict(
        exposure=5,
        data_classification=DataClassification.CONFIDENTIAL,
        longevity_years=5,
        replaceability=3,
    ),
    "Transportation": dict(
        exposure=4,
        data_classification=DataClassification.CONFIDENTIAL,
        longevity_years=7,
        replaceability=3,
    ),
    "Professional Services": dict(
        exposure=4,
        data_classification=DataClassification.CONFIDENTIAL,
        longevity_years=7,
        replaceability=3,
    ),
    "Technology": dict(
        exposure=5,
        data_classification=DataClassification.INTERNAL,
        longevity_years=5,
        replaceability=4,
    ),
    "Education": dict(
        exposure=4,
        data_classification=DataClassification.INTERNAL,
        longevity_years=5,
        replaceability=3,
    ),
    "Retail/Ecommerce": dict(
        exposure=5,
        data_classification=DataClassification.INTERNAL,
        longevity_years=5,
        replaceability=3,
    ),
    "Manufacturing": dict(
        exposure=4,
        data_classification=DataClassification.INTERNAL,
        longevity_years=10,
        replaceability=3,
    ),
    "Media/News": dict(
        exposure=5,
        data_classification=DataClassification.PUBLIC,
        longevity_years=3,
        replaceability=5,
    ),
    "Travel/Hospitality": dict(
        exposure=5,
        data_classification=DataClassification.INTERNAL,
        longevity_years=5,
        replaceability=4,
    ),
    "Real Estate": dict(
        exposure=4,
        data_classification=DataClassification.INTERNAL,
        longevity_years=5,
        replaceability=3,
    ),
    "Social Media": dict(
        exposure=5,
        data_classification=DataClassification.INTERNAL,
        longevity_years=3,
        replaceability=4,
    ),
    "Science/Research": dict(
        exposure=4,
        data_classification=DataClassification.INTERNAL,
        longevity_years=7,
        replaceability=4,
    ),
    "Nonprofit": dict(
        exposure=3,
        data_classification=DataClassification.INTERNAL,
        longevity_years=5,
        replaceability=4,
    ),
    "Sports": dict(
        exposure=5,
        data_classification=DataClassification.PUBLIC,
        longevity_years=3,
        replaceability=5,
    ),
    "Gaming": dict(
        exposure=5,
        data_classification=DataClassification.PUBLIC,
        longevity_years=3,
        replaceability=5,
    ),
    "Agriculture/Food": dict(
        exposure=3,
        data_classification=DataClassification.INTERNAL,
        longevity_years=5,
        replaceability=4,
    ),
}

# cert_algo string → QuantumVulnerability (all Shor-vulnerable today)
_VULN: dict[str | None, QuantumVulnerability] = {
    "RSA":        QuantumVulnerability.BROKEN,
    "ECDSA-P256": QuantumVulnerability.BROKEN,
    "ECDSA-P384": QuantumVulnerability.BROKEN,
    "ECDSA-P521": QuantumVulnerability.BROKEN,
    "Ed25519":    QuantumVulnerability.BROKEN,
    "Ed448":      QuantumVulnerability.BROKEN,
    None:         QuantumVulnerability.UNKNOWN,
}

_SECTOR_KEYS = list(_SECTOR.keys())


def build_inventory(
    json_path: Path = _JSON_PATH,
) -> tuple[list[CryptoAsset], list[dict]]:
    """Return (assets, raw_records) from the scan JSON.

    Records with *error != None* are skipped.
    The sector is embedded in each asset's *notes* field for downstream use.
    """
    data = json.loads(json_path.read_text())
    raw_records: list[dict] = data["results"]

    assets: list[CryptoAsset] = []
    idx = 1
    for rec in raw_records:
        if rec.get("error") is not None:
            continue
        sector = rec["sector"]
        p = _SECTOR[sector]
        algo = rec.get("cert_algo")
        asset = CryptoAsset(
            asset_id=f"R{idx:04d}",
            name=f"{rec['host']} TLS",
            asset_type=AssetType.CERTIFICATE,
            algorithm=algo or "UNKNOWN",
            key_size=rec.get("cert_key_bits") or 0,
            quantum_vulnerability=_VULN.get(algo, QuantumVulnerability.UNKNOWN),
            exposure=p["exposure"],
            data_classification=p["data_classification"],
            longevity_years=p["longevity_years"],
            replaceability=p["replaceability"],
            endpoints=[rec["host"]],
            notes=(
                f"sector={sector};"
                f"tls={rec.get('tls_version')};"
                f"cipher={rec.get('cipher_suite')}"
            ),
        )
        assets.append(asset)
        idx += 1
    return assets, raw_records


def _sector_of(asset: CryptoAsset) -> str:
    return asset.notes.split(";")[0].replace("sector=", "").strip()


def run(json_path: Path = _JSON_PATH) -> list[RiskResult]:
    """Score all assets and print tables."""
    assets, raw = build_inventory(json_path)
    results = [score_asset(a) for a in assets]
    results.sort(key=lambda r: r.score, reverse=True)
    asset_map = {a.asset_id: a for a in assets}

    # Metadata from raw records
    raw_map = {r["host"]: r for r in raw if r.get("error") is None}

    print(f"\n{'ID':<6} {'Host':<35} {'Sector':<22} {'Algo':<12}"
          f" {'TLS':>8} {'Score':>6} {'Tier'}")
    print("-" * 100)
    for r in results:
        a = asset_map[r.asset_id]
        host = a.endpoints[0]
        raw_rec = raw_map.get(host, {})
        tls = raw_rec.get("tls_version") or "?"
        print(
            f"{r.asset_id:<6} {host:<35} {_sector_of(a):<22} {a.algorithm:<12}"
            f" {tls:>8} {r.score:>6.3f} {r.priority.value}"
        )

    print("\nOverall tier distribution:")
    total = len(results)
    for tier in PriorityTier:
        count = sum(1 for r in results if r.priority == tier)
        print(f"  {tier.value:<10}: {count:>4}  ({100 * count / total:.0f}%)")

    print("\nTier distribution by sector:")
    print(f"  {'Sector':<22} {'N':>4}  {'Crit':>5} {'High':>5} {'Med':>5} {'Low':>5} {'Score':>7}")
    print("  " + "-" * 56)
    for sk in _SECTOR_KEYS:
        sr = [r for r in results if _sector_of(asset_map[r.asset_id]) == sk]
        n    = len(sr)
        if n == 0:
            continue
        crit = sum(1 for r in sr if r.priority == PriorityTier.CRITICAL)
        high = sum(1 for r in sr if r.priority == PriorityTier.HIGH)
        med  = sum(1 for r in sr if r.priority == PriorityTier.MEDIUM)
        low  = sum(1 for r in sr if r.priority == PriorityTier.LOW)
        avg  = sum(r.score for r in sr) / n
        print(f"  {sk:<22} {n:>4}  {crit:>5} {high:>5} {med:>5} {low:>5} {avg:>7.3f}")

    return results


if __name__ == "__main__":
    run()
