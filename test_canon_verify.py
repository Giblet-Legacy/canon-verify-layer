"""
test_canon_verify.py — P6 Canon Verify test suite

Function:
    Generates ledgers with P4 (ledger-layer) and P1 (envelope-layer),
    then verifies them with P6's isolated code. Only the tests import
    other layers; canon_verify.py itself imports nothing from the stack.
    Sibling repos are located relative to this file, so the suite runs
    from any working directory.

Layer:    P6 — Canon Verify
Spec:     SPEC.md v1.0.1
Licence:  MSL-1.0
"""

import os
import sys
import json
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Path setup: allow the test to use P4 to generate a ledger,
# and P1 to generate the did:key string.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "envelope-layer"))
sys.path.insert(0, os.path.join(_HERE, "..", "ledger-layer"))

import ledger
import envelope_v2 as envelope

# Import P6
import canon_verify


# ---------------------------------------------------------------------------
# 1. key — fixture: fresh Ed25519 private key
# ---------------------------------------------------------------------------
@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


# ---------------------------------------------------------------------------
# 2. temp_ledger — fixture: empty temporary .jsonl path, removed afterwards
# ---------------------------------------------------------------------------
@pytest.fixture
def temp_ledger():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)


# ---------------------------------------------------------------------------
# 3. _read_entries / _write_entries — helpers for tampering
# ---------------------------------------------------------------------------
def _read_entries(path):
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _write_entries(path, entries):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for e in entries:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# 4. test_verify_valid_ledger
# ---------------------------------------------------------------------------
def test_verify_valid_ledger(temp_ledger, key):
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    ledger.append_entry(temp_ledger, {"data": "two"}, key)
    ledger.append_entry(temp_ledger, {"data": "three"}, key)

    did_key = envelope.did_key_encode(key.public_key())
    assert canon_verify.verify_ledger(temp_ledger, did_key) is True


# ---------------------------------------------------------------------------
# 5. test_verify_tampered_record
# ---------------------------------------------------------------------------
def test_verify_tampered_record(temp_ledger, key):
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    entries = _read_entries(temp_ledger)
    entries[0]["record"]["data"] = "tampered"
    _write_entries(temp_ledger, entries)

    did_key = envelope.did_key_encode(key.public_key())
    assert canon_verify.verify_ledger(temp_ledger, did_key) is False


# ---------------------------------------------------------------------------
# 6. test_verify_broken_chain
# ---------------------------------------------------------------------------
def test_verify_broken_chain(temp_ledger, key):
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    ledger.append_entry(temp_ledger, {"data": "two"}, key)
    entries = _read_entries(temp_ledger)
    entries[1]["prev"] = "badhash" * 8
    _write_entries(temp_ledger, entries)

    did_key = envelope.did_key_encode(key.public_key())
    assert canon_verify.verify_ledger(temp_ledger, did_key) is False


# ---------------------------------------------------------------------------
# 7. test_verify_wrong_key
#    A valid ledger checked against a different did:key must fail.
# ---------------------------------------------------------------------------
def test_verify_wrong_key(temp_ledger, key):
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    other = envelope.did_key_encode(Ed25519PrivateKey.generate().public_key())
    assert canon_verify.verify_ledger(temp_ledger, other) is False


# ---------------------------------------------------------------------------
# 8. test_verify_bad_signature
# ---------------------------------------------------------------------------
def test_verify_bad_signature(temp_ledger, key):
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    entries = _read_entries(temp_ledger)
    sig = bytearray(bytes.fromhex(entries[0]["signature"]))
    sig[0] ^= 0x01
    entries[0]["signature"] = sig.hex()
    _write_entries(temp_ledger, entries)

    did_key = envelope.did_key_encode(key.public_key())
    assert canon_verify.verify_ledger(temp_ledger, did_key) is False


# ---------------------------------------------------------------------------
# 9. test_verify_malformed_inputs
#    Malformed data must return False, never raise.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("line", [
    "not json",
    "[1, 2, 3]",
    '{"seq": 0}',
    '"a string"',
])
def test_verify_malformed_inputs(temp_ledger, key, line):
    with open(temp_ledger, "w", encoding="utf-8") as f:
        f.write(line + "\n")
    did_key = envelope.did_key_encode(key.public_key())
    assert canon_verify.verify_ledger(temp_ledger, did_key) is False


# ---------------------------------------------------------------------------
# 10. test_verify_non_hex_signature
# ---------------------------------------------------------------------------
def test_verify_non_hex_signature(temp_ledger, key):
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    entries = _read_entries(temp_ledger)
    entries[0]["signature"] = 12345
    _write_entries(temp_ledger, entries)

    did_key = envelope.did_key_encode(key.public_key())
    assert canon_verify.verify_ledger(temp_ledger, did_key) is False


# ---------------------------------------------------------------------------
# 11. test_verify_bad_did_and_missing_file
# ---------------------------------------------------------------------------
def test_verify_bad_did_and_missing_file(temp_ledger, key):
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    assert canon_verify.verify_ledger(temp_ledger, "did:web:example") is False
    assert canon_verify.verify_ledger(temp_ledger, "did:key:z0OIl") is False
    assert canon_verify.verify_ledger(temp_ledger, None) is False

    did_key = envelope.did_key_encode(key.public_key())
    missing = temp_ledger + ".missing"
    assert canon_verify.verify_ledger(missing, did_key) is False


# ---------------------------------------------------------------------------
# 12. test_did_key_decode_matches_p1
#    P6's independent did:key decoder must agree with P1's encoder.
# ---------------------------------------------------------------------------
def test_did_key_decode_matches_p1(key):
    from cryptography.hazmat.primitives import serialization
    raw = serialization.Encoding.Raw
    fmt = serialization.PublicFormat.Raw
    did_key = envelope.did_key_encode(key.public_key())
    decoded = canon_verify._decode_did_key(did_key)
    assert decoded.public_bytes(raw, fmt) == key.public_key().public_bytes(raw, fmt)
