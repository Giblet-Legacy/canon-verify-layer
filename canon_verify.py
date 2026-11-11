"""
canon_verify.py — P6 Canon Verify primitive layer

Function:
    Independent zero-trust ledger verifier. Reimplements
    canonicalisation, SHA-256, did:key decoding, and Ed25519
    verification from scratch. Does NOT import any other Forge Stack
    layer.

Public API:
    1. verify_ledger — Verifies a .jsonl ledger file.

Layer:    P6 — Canon Verify
Depends:  (nothing — standalone)
Consumed: Auditing, external verification
Version:  1.0.0 (on freeze; 0.0.0-dev until then)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ALPHABET_INDEX = {c: i for i, c in enumerate(_ALPHABET)}

# ---------------------------------------------------------------------------
# Independent implementations (not imported from P1)
# ---------------------------------------------------------------------------
def _b58decode(s):
    z = 0
    for c in s:
        if c == "1":
            z += 1
        else:
            break
    n = 0
    for c in s[z:]:
        if c not in _ALPHABET_INDEX:
            raise ValueError("invalid base58btc character")
        n = n * 58 + _ALPHABET_INDEX[c]
    body_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return (b"\x00" * z) + body_bytes

def _decode_did_key(did):
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key")
    raw = _b58decode(did[9:])
    if not raw.startswith(b"\xed\x01"):
        raise ValueError("not Ed25519 multicodec")
    raw_key = raw[2:]
    if len(raw_key) != 32:
        raise ValueError("not a 32-byte key")
    return Ed25519PublicKey.from_public_bytes(raw_key)

def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()

def _sha256_digest(data):
    return hashlib.sha256(data).digest()

# ---------------------------------------------------------------------------
# 1. verify_ledger
#    Reads a .jsonl ledger and verifies the chain and signatures.
# ---------------------------------------------------------------------------
def verify_ledger(filepath, did_key):
    try:
        public_key = _decode_did_key(did_key)
    except ValueError:
        return False

    expected_seq = 0
    expected_prev = "0" * 64

    if not __import__('os').path.exists(filepath):
        return False

    with open(filepath, "r") as f:
        for line in f:
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
                seq = entry["seq"]
                prev = entry["prev"]
                record = entry["record"]
                signer = entry["signer"]
                claimed_hash = entry["hash"]
                sig_hex = entry["signature"]
            except (json.JSONDecodeError, KeyError):
                return False

            # 1. Verify chain structure
            if seq != expected_seq or prev != expected_prev:
                return False

            # 2. Reconstruct unsigned entry
            unsigned = {
                "seq": seq,
                "prev": prev,
                "record": record,
                "signer": signer
            }

            # 3. Verify hash
            canonical = _canonical_bytes(unsigned)
            actual_hash = _sha256_hex(canonical)
            if actual_hash != claimed_hash:
                return False

            # 4. Verify signature (over the raw 32-byte digest)
            try:
                sig_bytes = bytes.fromhex(sig_hex)
                digest = _sha256_digest(canonical)
                public_key.verify(sig_bytes, digest)
            except (ValueError, InvalidSignature):
                return False

            # 5. Advance chain
            expected_seq += 1
            expected_prev = claimed_hash

    return True
