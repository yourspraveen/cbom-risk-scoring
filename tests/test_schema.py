"""Tests for CBOM schema and risk scorer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from utils.schema import (
    AssetType,
    CryptoAsset,
    DataClassification,
    PriorityTier,
    QuantumVulnerability,
)
from analysis.risk_scorer import RiskResult, _longevity_score, score_asset


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

def test_crypto_asset_instantiation():
    asset = CryptoAsset(
        asset_id="T01",
        name="test-asset",
        asset_type=AssetType.ALGORITHM,
        algorithm="RSA-2048",
        key_size=2048,
        quantum_vulnerability=QuantumVulnerability.BROKEN,
        exposure=3,
        data_classification=DataClassification.INTERNAL,
        longevity_years=5,
        replaceability=3,
    )
    assert asset.asset_id == "T01"
    assert asset.quantum_vulnerability == QuantumVulnerability.BROKEN
    assert asset.endpoints == []


def test_enum_values():
    assert QuantumVulnerability.BROKEN.value == 5
    assert QuantumVulnerability.WEAKENED.value == 3
    assert QuantumVulnerability.SAFE.value == 1
    assert QuantumVulnerability.UNKNOWN.value == 4

    assert DataClassification.PUBLIC.value == 1
    assert DataClassification.TOP_SECRET.value == 5


# ---------------------------------------------------------------------------
# Risk scorer tests
# ---------------------------------------------------------------------------

def _make_asset(**kwargs) -> CryptoAsset:
    defaults = dict(
        asset_id="X00",
        name="test",
        asset_type=AssetType.ALGORITHM,
        algorithm="RSA-2048",
        key_size=2048,
        quantum_vulnerability=QuantumVulnerability.BROKEN,
        exposure=3,
        data_classification=DataClassification.INTERNAL,
        longevity_years=5,
        replaceability=3,
    )
    defaults.update(kwargs)
    return CryptoAsset(**defaults)


def test_score_in_range():
    """Risk score must always be in [0, 5]."""
    # Minimum possible score: V=1, E=1, S=1, L=1, Rep=5 → (6-5)=1
    # R = 0.35*1 + 0.20*1 + 0.25*1 + 0.10*1 + 0.10*1 = 1.0
    min_asset = _make_asset(
        quantum_vulnerability=QuantumVulnerability.SAFE,
        exposure=1,
        data_classification=DataClassification.PUBLIC,
        longevity_years=0,
        replaceability=5,
    )
    result = score_asset(min_asset)
    assert 0.0 <= result.score <= 5.0

    # Maximum possible score: V=5, E=5, S=5, L=5, Rep=1 → (6-1)=5
    # R = 0.35*5 + 0.20*5 + 0.25*5 + 0.10*5 + 0.10*5 = 5.0
    max_asset = _make_asset(
        quantum_vulnerability=QuantumVulnerability.BROKEN,
        exposure=5,
        data_classification=DataClassification.TOP_SECRET,
        longevity_years=20,
        replaceability=1,
    )
    result = score_asset(max_asset)
    assert 0.0 <= result.score <= 5.0


def test_priority_critical():
    asset = _make_asset(
        quantum_vulnerability=QuantumVulnerability.BROKEN,  # V=5
        exposure=5,                                          # E=5
        data_classification=DataClassification.TOP_SECRET,  # S=5
        longevity_years=20,                                  # L=5
        replaceability=1,                                    # Rep=1 → 6-1=5
    )
    result = score_asset(asset)
    assert result.priority == PriorityTier.CRITICAL
    assert result.score >= 4.0


def test_priority_low():
    asset = _make_asset(
        quantum_vulnerability=QuantumVulnerability.SAFE,     # V=1
        exposure=1,                                          # E=1
        data_classification=DataClassification.PUBLIC,       # S=1
        longevity_years=0,                                   # L=1
        replaceability=5,                                    # Rep=5 → 6-5=1
    )
    result = score_asset(asset)
    assert result.priority == PriorityTier.LOW
    assert result.score < 2.0


def test_priority_high():
    # Tune parameters to land in [3.0, 4.0)
    # R = 0.35*5 + 0.20*3 + 0.25*2 + 0.10*2 + 0.10*(6-3)
    #   = 1.75 + 0.60 + 0.50 + 0.20 + 0.30 = 3.35
    asset = _make_asset(
        quantum_vulnerability=QuantumVulnerability.BROKEN,   # V=5
        exposure=3,                                          # E=3
        data_classification=DataClassification.INTERNAL,    # S=2
        longevity_years=3,                                   # L=2 (3–7 range)
        replaceability=3,                                    # Rep=3
    )
    result = score_asset(asset)
    assert result.priority == PriorityTier.HIGH
    assert 3.0 <= result.score < 4.0


def test_score_result_type():
    asset = _make_asset()
    result = score_asset(asset)
    assert isinstance(result, RiskResult)
    assert isinstance(result.score, float)
    assert isinstance(result.priority, PriorityTier)


def test_longevity_score_boundaries():
    assert _longevity_score(0) == 1.0
    assert _longevity_score(1) == 2.0
    assert _longevity_score(3) == 3.0
    assert _longevity_score(7) == 4.0
    assert _longevity_score(15) == 5.0
    assert _longevity_score(100) == 5.0


def test_inventory_runs():
    """Smoke-test: inventory generates 30 assets and all score."""
    from experiments.tls_inventory import build_inventory, run
    assets = build_inventory()
    assert len(assets) == 30
    results = run()
    assert len(results) == 30
