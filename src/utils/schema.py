"""CBOM data models: CryptoAsset, AssetType, QuantumVulnerability, etc."""

from dataclasses import dataclass, field
from enum import Enum


class AssetType(Enum):
    ALGORITHM = "algorithm"
    PROTOCOL = "protocol"
    CERTIFICATE = "certificate"
    KEY = "key"
    LIBRARY = "library"


class QuantumVulnerability(Enum):
    """Quantum vulnerability classification with numeric score."""
    BROKEN = 5      # Broken by Shor's algorithm (RSA, ECC, DH)
    WEAKENED = 3    # Weakened by Grover's algorithm (symmetric, hash)
    SAFE = 1        # Post-quantum safe (NIST PQC standards)
    UNKNOWN = 4     # Unknown/unclassified


class DataClassification(Enum):
    """Data sensitivity level."""
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    SECRET = 4
    TOP_SECRET = 5


class PriorityTier(Enum):
    """Remediation priority tiers based on risk score."""
    CRITICAL = "Critical"   # R >= 4.0
    HIGH = "High"           # R >= 3.0
    MEDIUM = "Medium"       # R >= 2.0
    LOW = "Low"             # R < 2.0


@dataclass
class CryptoAsset:
    """A cryptographic asset in the enterprise CBOM."""
    asset_id: str
    name: str
    asset_type: AssetType
    algorithm: str
    key_size: int                              # bits; 0 if not applicable
    quantum_vulnerability: QuantumVulnerability
    exposure: int                              # 1–5 (5 = internet-facing)
    data_classification: DataClassification
    longevity_years: int                       # years data must stay confidential
    replaceability: int                        # 1–5 (5 = trivially replaceable)
    endpoints: list[str] = field(default_factory=list)
    notes: str = ""
