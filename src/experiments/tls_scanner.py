"""Passive TLS scanner for CBOM real-world case study.

Probes 50 well-known HTTPS endpoints using a TLS handshake only — no HTTP
request is sent.  Extracts TLS version, cipher suite, and certificate
signature algorithm from each endpoint.

Run locally once; commit the output JSON so CI can reproduce results
without network access:

    python3 research/src/experiments/tls_scanner.py

Output: research/data/real_tls_scan.json
"""

from __future__ import annotations

import datetime
import json
import socket
import ssl
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
OUT = _REPO_ROOT / "research" / "data" / "real_tls_scan.json"

TIMEOUT = 8  # seconds per host

# ---------------------------------------------------------------------------
# Host list: (hostname, port, sector)
# ---------------------------------------------------------------------------
HOSTS: list[tuple[str, int, str]] = [
    # --- Government (10) ---
    ("usa.gov",         443, "government"),
    ("irs.gov",         443, "government"),
    ("cdc.gov",         443, "government"),
    ("fbi.gov",         443, "government"),
    ("dhs.gov",         443, "government"),
    ("nasa.gov",        443, "government"),
    ("state.gov",       443, "government"),
    ("treasury.gov",    443, "government"),
    ("ftc.gov",         443, "government"),
    ("nist.gov",        443, "government"),
    # --- Finance (10) ---
    ("chase.com",           443, "finance"),
    ("bankofamerica.com",   443, "finance"),
    ("wellsfargo.com",      443, "finance"),
    ("paypal.com",          443, "finance"),
    ("visa.com",            443, "finance"),
    ("mastercard.com",      443, "finance"),
    ("stripe.com",          443, "finance"),
    ("fidelity.com",        443, "finance"),
    ("schwab.com",          443, "finance"),
    ("americanexpress.com", 443, "finance"),
    # --- Healthcare (5) ---
    ("cms.hhs.gov",         443, "healthcare"),
    ("myhealth.va.gov",     443, "healthcare"),
    ("cvs.com",             443, "healthcare"),
    ("mayoclinic.org",      443, "healthcare"),
    ("webmd.com",           443, "healthcare"),
    # --- Technology (15) ---
    ("google.com",      443, "technology"),
    ("apple.com",       443, "technology"),
    ("microsoft.com",   443, "technology"),
    ("amazon.com",      443, "technology"),
    ("meta.com",        443, "technology"),
    ("linkedin.com",    443, "technology"),
    ("cloudflare.com",  443, "technology"),
    ("github.com",      443, "technology"),
    ("netflix.com",     443, "technology"),
    ("adobe.com",       443, "technology"),
    ("salesforce.com",  443, "technology"),
    ("slack.com",       443, "technology"),
    ("zoom.us",         443, "technology"),
    ("dropbox.com",     443, "technology"),
    ("twilio.com",      443, "technology"),
    # --- Education (10) ---
    ("mit.edu",         443, "education"),
    ("stanford.edu",    443, "education"),
    ("harvard.edu",     443, "education"),
    ("berkeley.edu",    443, "education"),
    ("cmu.edu",         443, "education"),
    ("cornell.edu",     443, "education"),
    ("caltech.edu",     443, "education"),
    ("uchicago.edu",    443, "education"),
    ("columbia.edu",    443, "education"),
    ("yale.edu",        443, "education"),
]

# ---------------------------------------------------------------------------
# Signature-algorithm OID → canonical name
# ---------------------------------------------------------------------------
_SIG_OID_MAP: dict[str, str] = {
    # RSA / RSA-PSS
    "1.2.840.113549.1.1.1":  "RSA",   # rsaEncryption (SPKI)
    "1.2.840.113549.1.1.5":  "RSA",   # sha1WithRSAEncryption
    "1.2.840.113549.1.1.10": "RSA",   # id-RSASSA-PSS
    "1.2.840.113549.1.1.11": "RSA",   # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": "RSA",   # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": "RSA",   # sha512WithRSAEncryption
    # ECDSA
    "1.2.840.10045.4.3.1":   "ECDSA-P256",  # ecdsa-with-SHA224
    "1.2.840.10045.4.3.2":   "ECDSA-P256",  # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3":   "ECDSA-P384",  # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4":   "ECDSA-P521",  # ecdsa-with-SHA512
    # Edwards-curve
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

# Curve OID → key bits
_CURVE_BITS: dict[str, int] = {
    "1.2.840.10045.3.1.7": 256,   # prime256v1 (P-256)
    "1.3.132.0.34":        384,   # secp384r1
    "1.3.132.0.35":        521,   # secp521r1
    "1.3.101.112":         255,   # Ed25519
    "1.3.101.113":         448,   # Ed448
}

# RSA SPKI OID bytes used to locate the modulus
_RSA_SPKI = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])


# ---------------------------------------------------------------------------
# Minimal DER helpers (no external packages)
# ---------------------------------------------------------------------------

def _der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Return (length, next_offset) for a DER length field."""
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    n = first & 0x7F
    length = int.from_bytes(data[offset + 1 : offset + 1 + n], "big")
    return length, offset + 1 + n


def _all_oids(der: bytes) -> list[str]:
    """Return every OID value found in *der* (linear scan for tag 0x06).

    Only short-form DER lengths (< 0x80) are considered for OIDs.
    This rejects bytes that happen to equal 0x06 inside length fields
    (long-form lengths start with a byte ≥ 0x80, which never occurs for
    standard X.509 algorithm OIDs).
    """
    oids: list[str] = []
    i = 0
    while i < len(der) - 2:
        if der[i] != 0x06:
            i += 1
            continue
        length_byte = der[i + 1]
        # Skip false positives: long-form length byte or zero-length OID
        if length_byte == 0 or length_byte >= 0x80:
            i += 1
            continue
        length = length_byte
        start = i + 2
        if start + length > len(der):
            i += 1
            continue
        try:
            raw = der[start : start + length]
            first, second = raw[0] // 40, raw[0] % 40
            components: list[int] = [first, second]
            acc = 0
            for b in raw[1:]:
                acc = (acc << 7) | (b & 0x7F)
                if not (b & 0x80):
                    components.append(acc)
                    acc = 0
            oids.append(".".join(str(c) for c in components))
            i = start + length
        except Exception:
            i += 1
    return oids


def _cert_algo(der: bytes) -> tuple[str | None, int]:
    """Return (algorithm_name, key_bits) from DER certificate bytes."""
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
            # Walk forward to the BIT STRING (0x03) that wraps the RSA key
            i = idx + len(_RSA_SPKI)
            limit = min(i + 64, len(der))
            while i < limit:
                if der[i] == 0x03:
                    try:
                        bs_len, bs_start = _der_length(der, i + 1)
                        # BIT STRING: 1 unused-bits byte, then SEQUENCE
                        inner = der[bs_start + 1 : bs_start + bs_len]
                        if inner and inner[0] == 0x30:
                            _, seq_start = _der_length(inner, 1)
                            if inner[seq_start] == 0x02:   # INTEGER = modulus
                                mod_len, _ = _der_length(inner, seq_start + 1)
                                # Strip leading 0x00 sign byte if present
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

    else:  # ECDSA-*
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
    """Return the negotiated TLS key-exchange group via openssl s_client."""
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host, "-brief"],
            input=b"",
            capture_output=True,
            timeout=TIMEOUT + 4,
        )
        for line in proc.stderr.decode("utf-8", errors="replace").splitlines():
            if "Negotiated" in line and "group" in line and ":" in line:
                return line.split(":", 1)[1].strip()
            if "Peer Temp Key" in line and ":" in line:
                return line.split(":", 1)[1].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


# Known PQC / hybrid key-exchange group name substrings
_PQC_MARKERS = ("MLKEM", "ML_KEM", "KYBER", "X25519MLKEM", "P256MLKEM",
                "X25519Kyber", "P384MLKEM")


# ---------------------------------------------------------------------------
# Per-host probe
# ---------------------------------------------------------------------------

def _probe(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result: dict = {
        "tls_version": None,
        "cipher_suite": None,
        "cert_algo": None,
        "cert_key_bits": 0,
        "cert_sig_oid": None,
        "negotiated_group": None,
        "pqc_hybrid": False,
        "error": None,
    }
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                result["tls_version"] = conn.version()
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
                    result["cert_algo"] = name
                    result["cert_key_bits"] = bits
    except socket.timeout:
        result["error"] = "timeout"
    except ssl.SSLError as exc:
        result["error"] = f"ssl:{exc.reason}"
    except socket.gaierror:
        result["error"] = "dns_failed"
    except OSError as exc:
        result["error"] = f"os_error:{exc}"

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
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    records: list[dict] = []

    for idx, (host, port, sector) in enumerate(HOSTS, 1):
        print(f"[{idx:02d}/{len(HOSTS)}] {host:<35}", end=" ", flush=True)
        info = _probe(host, port)
        records.append({"host": host, "port": port, "sector": sector, **info})
        status = info["error"] or f"{info['tls_version']} / {info['cert_algo']}"
        print(status)

    success = sum(1 for r in records if r["error"] is None)
    payload = {
        "scan_timestamp": ts,
        "scanner_version": "1.0",
        "total_hosts": len(HOSTS),
        "success_count": success,
        "results": records,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2))
    print(f"\nSaved {OUT}  ({success}/{len(HOSTS)} succeeded)")


if __name__ == "__main__":
    run_scan()
