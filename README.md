# CBOM Risk-Scoring Prototype

Companion code and data for the paper:

> **CBOM-Based Risk Scoring for Post-Quantum Cryptographic Migration**
> Praveen Kumar Palaniswamy and Muthukumar Kubendran

## Repository Structure

```
src/
  utils/schema.py              CryptoAsset dataclass and enumerations
  analysis/risk_scorer.py      Multi-factor risk scoring (Eq. 1 in paper)
  analysis/ahp_weights.py      AHP weight derivation (Section IV-B)
  experiments/
    tls_inventory.py            30-asset synthetic benchmark (Section VII-B)
    tls_scanner.py              Live TLS endpoint scanner
    tls_scanner_sectors.py      Sector-stratified live scan (Section VII-D)
    real_inventory.py           Real scan result processing
    weight_sensitivity.py       Weight sensitivity analysis (Section VII-C)
    ahp_weights.py              AHP consistency verification
    plot_risk_distribution.py   Figure generation: risk distribution
    plot_score_scatter.py       Figure generation: score scatter
    plot_real_results.py        Figure generation: real scan results
    tranco_sector_sample.py     Tranco list sector sampling utility
tests/
  test_schema.py               Unit tests for schema module
data/
  real_tls_scan.json            Live TLS scan results (50 endpoints)
  real_tls_scan_sectors.json    Sector-stratified scan results
pyproject.toml                 Project metadata (Python >= 3.11, stdlib only)
```

## Quick Start

```bash
# No external dependencies required (stdlib only)
python3 -m pytest tests/ -q

# Run synthetic benchmark (Table III in paper)
python3 src/experiments/tls_inventory.py

# Run weight sensitivity analysis (Table V in paper)
python3 src/experiments/weight_sensitivity.py

# Run AHP consistency check
python3 src/experiments/ahp_weights.py
```

## Requirements

- Python >= 3.11
- No external packages (stdlib only)

## License

See the accompanying paper for terms of use.
