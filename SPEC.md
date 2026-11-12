# SPEC — canon-verify-layer (P6 Canon Verify)

SPEC.md — the complete layer specification for P6 Canon Verify.

Function:
    This document is the authoritative specification for primitive
    layer P6. It defines the zero-trust, standalone verifier.

Layer:     P6 — Canon Verify
Depends:   (nothing — standalone)
Consumed:  Auditing, external verification
Version:   SPEC 1.0.1
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

## 1. Zero-Trust Isolation Rule
P6 MUST NOT import `envelope`, `ledger`, or any other Forge Stack layer.
It must reimplement:
- Canonical JSON (sort_keys=True, separators=(',', ':'), ensure_ascii=True)
- SHA-256 hashing
- did:key base58btc decoding
- Ed25519 signature verification

## 2. Verification Rules
### verify_ledger(filepath: str, did_key: str) -> bool
1. Decode the did:key to extract the raw Ed25519 public key.
2. Read the file line by line.
3. For each entry, reconstruct the unsigned dict: `{"seq": entry["seq"], "prev": entry["prev"], "record": entry["record"], "signer": entry["signer"]}`.
4. Canonicalise the unsigned dict and hash it (SHA-256 hex).
5. Verify that the hash matches `entry["hash"]`.
6. Verify that the Ed25519 signature (hex decoded) is valid over the raw 32-byte digest.
7. Verify the chain: `entry["seq"] == expected_seq` (an integer, not a bool) and `entry["prev"] == expected_prev`. Genesis: `expected_seq = 0`, `expected_prev = "0" * 64`.
8. Verify the signer: `entry["signer"] == did_key` (matches P4 `verify_ledger`). *(Added in 1.0.1.)*
9. If all pass, return True. Return False on any failure — malformed JSON, non-object lines, missing fields, wrong types, unreadable or missing file, or an invalid did:key. The verifier MUST NOT raise on bad ledger data.

An empty ledger (no entries) verifies as True.
