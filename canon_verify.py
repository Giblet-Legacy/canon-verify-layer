"""
canon_verify.py — P6 Canon Verify primitive layer

Function:
    Independent zero-trust ledger verifier. Reimplements
    canonicalisation, SHA-256, did:key decoding, and Ed25519
    verification from scratch. Does NOT import any other Forge Stack
    layer. Any malformed input, tampered entry, broken chain link or
    foreign signer causes verification to return False — it never
    raises on bad ledger data.

Public API:
    6. verify_ledger — Verifies a .jsonl ledger file.

Layer:    P6 — Canon Verify
Depends:  (nothing — standalone; stdlib + cryptography only)
Consumed: Auditing, external verification
Version:  1.0.1
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ALPHABET_INDEX = {c: i for i, c in enumerate(_ALPHABET)}
_GENESIS_PREV = "0" * 64
_ED25519_MULTICODEC = b"\xed\x01"
_DID_KEY_PREFIX = "did:key:z"


# ---------------------------------------------------------------------------
# Independent implementations (not imported from P1)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 1. _b58decode
#    Decodes a base58btc (Bitcoin alphabet) string to bytes. Leading '1'
#    characters map to leading zero bytes.
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


# ---------------------------------------------------------------------------
# 2. _decode_did_key
#    Decodes a did:key (multibase 'z' + 0xed01 multicodec + 32-byte key)
#    into an Ed25519PublicKey. Raises ValueError on any malformation.
# ---------------------------------------------------------------------------
def _decode_did_key(did):
    if not isinstance(did, str) or not did.startswith(_DID_KEY_PREFIX):
        raise ValueError("not a did:key")
    raw = _b58decode(did[len(_DID_KEY_PREFIX):])
    if not raw.startswith(_ED25519_MULTICODEC):
        raise ValueError("not Ed25519 multicodec")
    raw_key = raw[len(_ED25519_MULTICODEC):]
    if len(raw_key) != 32:
        raise ValueError("not a 32-byte key")
    return Ed25519PublicKey.from_public_bytes(raw_key)


# ---------------------------------------------------------------------------
# 3. _canonical_bytes
#    Canonical JSON: sorted keys, no whitespace, ASCII-only, UTF-8 bytes.
# ---------------------------------------------------------------------------
def _canonical_bytes(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# 4. _sha256_hex
#    SHA-256 of data as a lowercase hex string.
# ---------------------------------------------------------------------------
def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 5. _sha256_digest
#    SHA-256 of data as the raw 32-byte digest (the signed message).
# ---------------------------------------------------------------------------
def _sha256_digest(data):
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# 6. verify_ledger
#    Reads a .jsonl ledger and verifies the chain and signatures.
#    Returns True only if every entry passes; False on any failure.
# ---------------------------------------------------------------------------
def verify_ledger(filepath, did_key):
    try:
        public_key = _decode_did_key(did_key)
    except ValueError:
        return False

    if not os.path.isfile(filepath):
        return False

    expected_seq = 0
    expected_prev = _GENESIS_PREV

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue

                # 6a. Parse and extract fields
                try:
                    entry = json.loads(line)
                    seq = entry["seq"]
                    prev = entry["prev"]
                    record = entry["record"]
                    signer = entry["signer"]
                    claimed_hash = entry["hash"]
                    sig_hex = entry["signature"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    return False

                # 6b. Verify chain structure (bool is not a valid seq)
                if type(seq) is not int or seq != expected_seq:
                    return False
                if prev != expected_prev:
                    return False

                # 6c. Signer must be the identity being verified against
                if signer != did_key:
                    return False

                # 6d. Reconstruct unsigned entry and verify hash
                unsigned = {
                    "seq": seq,
                    "prev": prev,
                    "record": record,
                    "signer": signer,
                }
                canonical = _canonical_bytes(unsigned)
                if _sha256_hex(canonical) != claimed_hash:
                    return False

                # 6e. Verify signature over the raw 32-byte digest
                try:
                    sig_bytes = bytes.fromhex(sig_hex)
                    public_key.verify(sig_bytes, _sha256_digest(canonical))
                except (ValueError, TypeError, InvalidSignature):
                    return False

                # 6f. Advance chain
                expected_seq += 1
                expected_prev = claimed_hash
    except (OSError, UnicodeDecodeError):
        return False

    return True
