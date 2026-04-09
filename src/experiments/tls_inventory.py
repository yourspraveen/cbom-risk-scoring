"""Simulated enterprise TLS endpoint inventory for CBOM evaluation.

Generates 30 synthetic CryptoAssets spanning RSA-2048, ECDHE-P256, AES-128,
AES-256, and NIST PQC algorithms.  Runs risk scoring and prints a prioritized
remediation table.
"""

import sys
from pathlib import Path

# Allow running directly: python tls_inventory.py
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.risk_scorer import RiskResult, score_asset
from utils.schema import (
    AssetType,
    CryptoAsset,
    DataClassification,
    PriorityTier,
    QuantumVulnerability,
)

# ---------------------------------------------------------------------------
# Synthetic inventory definition
# ---------------------------------------------------------------------------

_RAW: list[tuple] = [
    # (id, name, type, algorithm, key_size, vuln, exposure, classification,
    #  longevity_years, replaceability, endpoints)

    # ---- RSA-based (Broken) ------------------------------------------------
    ("A01", "api-gateway TLS", AssetType.PROTOCOL, "RSA-2048", 2048,
     QuantumVulnerability.BROKEN, 5, DataClassification.CONFIDENTIAL, 10, 2,
     ["api.corp.example"]),
    ("A02", "legacy-erp cert", AssetType.CERTIFICATE, "RSA-2048", 2048,
     QuantumVulnerability.BROKEN, 3, DataClassification.SECRET, 15, 1,
     ["erp.internal"]),
    ("A03", "web-dmz TLS", AssetType.PROTOCOL, "RSA-4096", 4096,
     QuantumVulnerability.BROKEN, 5, DataClassification.PUBLIC, 5, 3,
     ["www.corp.example"]),
    ("A04", "vpn-server cert", AssetType.CERTIFICATE, "RSA-2048", 2048,
     QuantumVulnerability.BROKEN, 4, DataClassification.CONFIDENTIAL, 10, 2,
     ["vpn.corp.example"]),
    ("A05", "mail-gateway TLS", AssetType.PROTOCOL, "RSA-2048", 2048,
     QuantumVulnerability.BROKEN, 4, DataClassification.INTERNAL, 7, 3,
     ["mail.corp.example"]),
    ("A06", "db-proxy cert", AssetType.CERTIFICATE, "RSA-2048", 2048,
     QuantumVulnerability.BROKEN, 2, DataClassification.SECRET, 20, 1,
     ["db-proxy.internal"]),
    ("A07", "hr-portal TLS", AssetType.PROTOCOL, "RSA-2048", 2048,
     QuantumVulnerability.BROKEN, 3, DataClassification.CONFIDENTIAL, 10, 3,
     ["hr.internal"]),
    ("A08", "fin-api cert", AssetType.CERTIFICATE, "RSA-4096", 4096,
     QuantumVulnerability.BROKEN, 5, DataClassification.TOP_SECRET, 25, 1,
     ["fin.api.corp.example"]),

    # ---- ECDHE-P256 (Broken by Shor) ---------------------------------------
    ("A09", "cdn-edge TLS", AssetType.PROTOCOL, "ECDHE-P256", 256,
     QuantumVulnerability.BROKEN, 5, DataClassification.PUBLIC, 3, 4,
     ["cdn.corp.example"]),
    ("A10", "iot-mgmt TLS", AssetType.PROTOCOL, "ECDHE-P256", 256,
     QuantumVulnerability.BROKEN, 3, DataClassification.CONFIDENTIAL, 10, 2,
     ["iot-mgmt.internal"]),
    ("A11", "k8s-apiserver cert", AssetType.CERTIFICATE, "ECDHE-P384", 384,
     QuantumVulnerability.BROKEN, 2, DataClassification.SECRET, 7, 2,
     ["k8s.internal"]),
    ("A12", "sso-provider TLS", AssetType.PROTOCOL, "ECDHE-P256", 256,
     QuantumVulnerability.BROKEN, 4, DataClassification.CONFIDENTIAL, 10, 3,
     ["sso.corp.example"]),
    ("A13", "partner-api TLS", AssetType.PROTOCOL, "ECDHE-P256", 256,
     QuantumVulnerability.BROKEN, 5, DataClassification.INTERNAL, 5, 3,
     ["partner-api.corp.example"]),
    ("A14", "backup-sync cert", AssetType.CERTIFICATE, "ECDHE-P256", 256,
     QuantumVulnerability.BROKEN, 1, DataClassification.CONFIDENTIAL, 15, 2,
     ["backup.internal"]),

    # ---- AES-128 (Weakened by Grover — effective 64-bit) -------------------
    ("A15", "disk-encrypt AES-128", AssetType.ALGORITHM, "AES-128-GCM", 128,
     QuantumVulnerability.WEAKENED, 1, DataClassification.SECRET, 15, 3,
     []),
    ("A16", "session-token AES-128", AssetType.ALGORITHM, "AES-128-CBC", 128,
     QuantumVulnerability.WEAKENED, 3, DataClassification.CONFIDENTIAL, 5, 4,
     ["api.corp.example"]),
    ("A17", "log-archive AES-128", AssetType.ALGORITHM, "AES-128-GCM", 128,
     QuantumVulnerability.WEAKENED, 1, DataClassification.INTERNAL, 10, 4,
     []),
    ("A18", "vpn-data AES-128", AssetType.ALGORITHM, "AES-128-CBC", 128,
     QuantumVulnerability.WEAKENED, 4, DataClassification.CONFIDENTIAL, 10, 3,
     ["vpn.corp.example"]),

    # ---- AES-256 (Still safe — Grover halves key space to 128 bits) --------
    ("A19", "disk-encrypt AES-256", AssetType.ALGORITHM, "AES-256-GCM", 256,
     QuantumVulnerability.SAFE, 1, DataClassification.SECRET, 15, 5,
     []),
    ("A20", "backup AES-256", AssetType.ALGORITHM, "AES-256-GCM", 256,
     QuantumVulnerability.SAFE, 1, DataClassification.CONFIDENTIAL, 10, 5,
     []),
    ("A21", "db-tde AES-256", AssetType.ALGORITHM, "AES-256-CBC", 256,
     QuantumVulnerability.SAFE, 2, DataClassification.TOP_SECRET, 20, 4,
     ["db.internal"]),

    # ---- SHA-256/384 (Weakened by Grover) ----------------------------------
    ("A22", "code-signing SHA-256", AssetType.ALGORITHM, "SHA-256", 256,
     QuantumVulnerability.WEAKENED, 2, DataClassification.INTERNAL, 5, 4,
     []),
    ("A23", "TLS-HMAC SHA-384", AssetType.ALGORITHM, "HMAC-SHA384", 384,
     QuantumVulnerability.WEAKENED, 5, DataClassification.CONFIDENTIAL, 5, 4,
     ["api.corp.example"]),

    # ---- NIST PQC (Safe) ---------------------------------------------------
    ("A24", "pqc-pilot Kyber768", AssetType.ALGORITHM, "ML-KEM-768", 0,
     QuantumVulnerability.SAFE, 3, DataClassification.CONFIDENTIAL, 15, 5,
     ["pqc-pilot.internal"]),
    ("A25", "pqc-pilot Dilithium3", AssetType.ALGORITHM, "ML-DSA-65", 0,
     QuantumVulnerability.SAFE, 3, DataClassification.CONFIDENTIAL, 15, 5,
     ["pqc-pilot.internal"]),
    ("A26", "hybrid TLS SPHINCS+", AssetType.PROTOCOL, "SLH-DSA-128s", 0,
     QuantumVulnerability.SAFE, 3, DataClassification.INTERNAL, 10, 4,
     ["hybrid-tls.internal"]),

    # ---- Legacy/Unknown ----------------------------------------------------
    ("A27", "legacy-mainframe cipher", AssetType.ALGORITHM, "3DES-112", 112,
     QuantumVulnerability.UNKNOWN, 2, DataClassification.CONFIDENTIAL, 10, 1,
     ["mainframe.internal"]),
    ("A28", "scada-comms RC4", AssetType.PROTOCOL, "RC4-128", 128,
     QuantumVulnerability.UNKNOWN, 3, DataClassification.SECRET, 10, 1,
     ["scada.ot"]),
    ("A29", "iot-sensor DES", AssetType.ALGORITHM, "DES-56", 56,
     QuantumVulnerability.UNKNOWN, 2, DataClassification.INTERNAL, 5, 1,
     ["iot-sensor.ot"]),
    ("A30", "old-vpn PPTP-MPPE", AssetType.PROTOCOL, "MPPE-128", 128,
     QuantumVulnerability.UNKNOWN, 4, DataClassification.CONFIDENTIAL, 5, 2,
     ["old-vpn.internal"]),
]


def build_inventory() -> list[CryptoAsset]:
    assets = []
    for row in _RAW:
        (aid, name, atype, algo, ksize, vuln, exp, cls_, lon, rep, eps) = row
        assets.append(CryptoAsset(
            asset_id=aid,
            name=name,
            asset_type=atype,
            algorithm=algo,
            key_size=ksize,
            quantum_vulnerability=vuln,
            exposure=exp,
            data_classification=cls_,
            longevity_years=lon,
            replaceability=rep,
            endpoints=eps,
        ))
    return assets


def run() -> list[RiskResult]:
    assets = build_inventory()
    results = [score_asset(a) for a in assets]
    results.sort(key=lambda r: r.score, reverse=True)

    # Print table
    print(f"{'ID':<5} {'Asset':<35} {'Score':>6} {'Priority':<10}")
    print("-" * 60)
    for r in results:
        asset = next(a for a in assets if a.asset_id == r.asset_id)
        print(f"{r.asset_id:<5} {asset.name:<35} {r.score:>6.3f} {r.priority.value:<10}")

    # Summary by tier
    print("\nPriority distribution:")
    for tier in PriorityTier:
        count = sum(1 for r in results if r.priority == tier)
        print(f"  {tier.value:<10}: {count:>2} assets")

    return results


if __name__ == "__main__":
    run()
