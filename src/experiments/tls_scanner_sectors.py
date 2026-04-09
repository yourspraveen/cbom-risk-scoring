"""Threaded TLS scanner for the 21-sector real-world case study.

Reads the Tranco-sampled endpoint list from
  tranco_vq3pn_sector_sample.json
and probes each domain with a TLS handshake only (no HTTP content
exchanged beyond ClientHello/ServerHello).

Run once locally; commit the output JSON so CI can reproduce
downstream analysis without network access:

    python3 research/src/experiments/tls_scanner_sectors.py

Output: research/data/real_tls_scan_sectors.json
"""

from __future__ import annotations

import datetime
import json
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
INPUT  = _REPO_ROOT / "papers" / "paper02" / "tranco_vq3pn_sector_sample.json"
OUT    = _REPO_ROOT / "research" / "data" / "real_tls_scan_sectors.json"

TIMEOUT  = 6   # seconds per host
WORKERS  = 30  # concurrent TLS connections

# ---------------------------------------------------------------------------
# Signature-algorithm OID → canonical name  (same as tls_scanner.py)
# ---------------------------------------------------------------------------
_SIG_OID_MAP: dict[str, str] = {
    "1.2.840.113549.1.1.1":  "RSA",
    "1.2.840.113549.1.1.5":  "RSA",
    "1.2.840.113549.1.1.10": "RSA",
    "1.2.840.113549.1.1.11": "RSA",
    "1.2.840.113549.1.1.12": "RSA",
    "1.2.840.113549.1.1.13": "RSA",
    "1.2.840.10045.4.3.1":   "ECDSA-P256",
    "1.2.840.10045.4.3.2":   "ECDSA-P256",
    "1.2.840.10045.4.3.3":   "ECDSA-P384",
    "1.2.840.10045.4.3.4":   "ECDSA-P521",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

_CURVE_BITS: dict[str, int] = {
    "1.2.840.10045.3.1.7": 256,
    "1.3.132.0.34":        384,
    "1.3.132.0.35":        521,
    "1.3.101.112":         255,
    "1.3.101.113":         448,
}

_RSA_SPKI = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])

# Known PQC / hybrid key-exchange cipher suite name substrings
_PQC_MARKERS = ("MLKEM", "ML_KEM", "KYBER", "X25519MLKEM", "P256MLKEM",
                "X25519Kyber", "P384MLKEM")


# ---------------------------------------------------------------------------
# DER helpers (stdlib only)
# ---------------------------------------------------------------------------
def _der_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    n = first & 0x7F
    return int.from_bytes(data[offset + 1: offset + 1 + n], "big"), offset + 1 + n


def _all_oids(der: bytes) -> list[str]:
    oids: list[str] = []
    i = 0
    while i < len(der) - 2:
        if der[i] != 0x06:
            i += 1
            continue
        lb = der[i + 1]
        if lb == 0 or lb >= 0x80:
            i += 1
            continue
        start = i + 2
        if start + lb > len(der):
            i += 1
            continue
        try:
            raw = der[start: start + lb]
            components = [raw[0] // 40, raw[0] % 40]
            acc = 0
            for b in raw[1:]:
                acc = (acc << 7) | (b & 0x7F)
                if not (b & 0x80):
                    components.append(acc)
                    acc = 0
            oids.append(".".join(str(c) for c in components))
            i = start + lb
        except Exception:
            i += 1
    return oids


def _cert_algo(der: bytes) -> tuple[str | None, int]:
    oids = _all_oids(der)
    algo: str | None = None
    for oid in oids:
        if oid in _SIG_OID_MAP:
            algo = _SIG_OID_MAP[oid]
            break
    if algo is None:
        return None, 0

    key_bits = 0
    if algo == "RSA":
        idx = der.find(_RSA_SPKI)
        if idx >= 0:
            i = idx + len(_RSA_SPKI)
            limit = min(i + 64, len(der))
            while i < limit:
                if der[i] == 0x03:
                    try:
                        bs_len, bs_start = _der_length(der, i + 1)
                        inner = der[bs_start + 1: bs_start + bs_len]
                        if inner and inner[0] == 0x30:
                            _, seq_start = _der_length(inner, 1)
                            if inner[seq_start] == 0x02:
                                mod_len, _ = _der_length(inner, seq_start + 1)
                                if mod_len > 0 and inner[seq_start + 2] == 0x00:
                                    mod_len -= 1
                                key_bits = mod_len * 8
                    except Exception:
                        pass
                    break
                i += 1
    elif algo in ("Ed25519", "Ed448"):
        key_bits = _CURVE_BITS.get(
            "1.3.101.112" if algo == "Ed25519" else "1.3.101.113", 255
        )
    else:
        for oid in oids:
            if oid in _CURVE_BITS:
                key_bits = _CURVE_BITS[oid]
                break
        if key_bits == 0:
            key_bits = 384 if "P384" in algo else 521 if "P521" in algo else 256

    return algo, key_bits


# ---------------------------------------------------------------------------
# Key-exchange group detection via openssl CLI
# ---------------------------------------------------------------------------
def _get_negotiated_group(host: str, port: int = 443) -> str | None:
    """Return the negotiated TLS key-exchange group via openssl s_client.

    Python's ssl module does not expose the TLS 1.3 named group (key_share
    extension) through its public API—conn.cipher() returns the symmetric
    cipher suite only.  We shell out to ``openssl s_client -brief`` to
    capture the negotiated group from stderr.

    Returns e.g. ``"X25519MLKEM768"`` (PQC hybrid) or
    ``"X25519, 253 bits"`` (classical), or *None* on failure.
    """
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host, "-brief"],
            input=b"",
            capture_output=True,
            timeout=TIMEOUT + 4,
        )
        for line in proc.stderr.decode("utf-8", errors="replace").splitlines():
            # TLS 1.3 PQC hybrid: "Negotiated TLS1.3 group: X25519MLKEM768"
            if "Negotiated" in line and "group" in line and ":" in line:
                return line.split(":", 1)[1].strip()
            # TLS 1.3/1.2 classical: "Peer Temp Key: X25519, 253 bits"
            if "Peer Temp Key" in line and ":" in line:
                return line.split(":", 1)[1].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# Per-host probe
# ---------------------------------------------------------------------------
def _probe(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result: dict = {
        "tls_version":   None,
        "cipher_suite":  None,
        "cert_algo":     None,
        "cert_key_bits": 0,
        "cert_sig_oid":  None,
        "negotiated_group": None,
        "pqc_hybrid":    False,
        "error":         None,
    }
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                result["tls_version"]  = conn.version()
                info = conn.cipher()
                result["cipher_suite"] = info[0] if info else None
                der = conn.getpeercert(binary_form=True)
                if der:
                    oids = _all_oids(der)
                    for oid in oids:
                        if oid in _SIG_OID_MAP:
                            result["cert_sig_oid"] = oid
                            break
                    name, bits = _cert_algo(der)
                    result["cert_algo"]     = name
                    result["cert_key_bits"] = bits
    except socket.timeout:
        result["error"] = "timeout"
    except ssl.SSLError as exc:
        result["error"] = f"ssl:{exc.reason}"
    except socket.gaierror:
        result["error"] = "dns_failed"
    except OSError as exc:
        result["error"] = f"os_error:{exc}"

    # Detect the negotiated key-exchange group via openssl s_client.
    # Python's ssl.SSLSocket.cipher() only returns the symmetric cipher
    # suite name (e.g. TLS_AES_256_GCM_SHA384); the TLS 1.3 key_share
    # group is not exposed.  openssl s_client reports it explicitly.
    if result["error"] is None:
        group = _get_negotiated_group(host, port)
        result["negotiated_group"] = group
        result["pqc_hybrid"] = bool(
            group and any(m.upper() in group.upper() for m in _PQC_MARKERS)
        )

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run_scan() -> None:
    sample = json.loads(INPUT.read_text())
    hosts: list[tuple[str, str]] = []  # (domain, sector)
    for sector, entries in sample["sectors"].items():
        for entry in entries:
            hosts.append((entry["domain"], sector))

    total = len(hosts)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"Scanning {total} hosts across {len(sample['sectors'])} sectors "
          f"({WORKERS} workers, {TIMEOUT}s timeout) …\n")

    records: list[dict] = [None] * total  # type: ignore[list-item]
    completed = 0

    def _task(idx: int, host: str, sector: str) -> tuple[int, dict]:
        info = _probe(host)
        return idx, {"host": host, "port": 443, "sector": sector, **info}

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {
            pool.submit(_task, i, host, sector): i
            for i, (host, sector) in enumerate(hosts)
        }
        for fut in as_completed(futures):
            idx, rec = fut.result()
            records[idx] = rec
            completed += 1
            status = rec["error"] or f"{rec['tls_version']} / {rec['cert_algo']}"
            group = rec.get("negotiated_group") or ""
            pqc_flag = " [PQC]" if rec.get("pqc_hybrid") else ""
            print(f"[{completed:4d}/{total}] {rec['host']:<45} {status:<30} "
                  f"{group}{pqc_flag}", flush=True)

    success = sum(1 for r in records if r["error"] is None)
    pqc_count = sum(1 for r in records if r.get("pqc_hybrid"))

    payload = {
        "scan_timestamp":         ts,
        "scanner_version":        "3.0",
        "openssl_version":        ssl.OPENSSL_VERSION,
        "tranco_list_id":         sample["metadata"]["tranco_list_id"],
        "tranco_date":            sample["metadata"]["tranco_date"],
        "total_hosts":            total,
        "success_count":          success,
        "failure_count":          total - success,
        "pqc_hybrid_count":       pqc_count,
        "results":                records,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2))
    print(f"\nSaved → {OUT.relative_to(_REPO_ROOT)}")
    print(f"  Succeeded : {success}/{total}  ({100*success/total:.1f}%)")
    print(f"  Failed    : {total-success}/{total}")
    print(f"  PQC hybrid: {pqc_count}/{success} reachable endpoints")


if __name__ == "__main__":
    run_scan()
