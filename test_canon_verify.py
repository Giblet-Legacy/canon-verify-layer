"""
test_canon_verify.py — P6 Canon Verify test suite

Function:
    Generates a ledger with P4, then verifies it with P6's isolated code.

Layer:    P6 — Canon Verify
Spec:     SPEC.md v1.0.0
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
sys.path.insert(0, os.path.abspath('../envelope-layer'))
sys.path.insert(0, os.path.abspath('../ledger-layer'))

import ledger
import envelope_v2 as envelope

# Import P6
import canon_verify

@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()

@pytest.fixture
def temp_ledger():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    open(path, 'w').close()  # empty the file
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_verify_valid_ledger(temp_ledger, key):
    # Generate a ledger with P4
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    ledger.append_entry(temp_ledger, {"data": "two"}, key)
    ledger.append_entry(temp_ledger, {"data": "three"}, key)
    
    did_key = envelope.did_key_encode(key.public_key())
    
    # Verify with P6 (isolated)
    assert canon_verify.verify_ledger(temp_ledger, did_key) is True

def test_verify_tampered_record(temp_ledger, key):
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    
    # Tamper
    with open(temp_ledger, "r") as f:
        lines = f.readlines()
    
    entry = json.loads(lines[0])
    entry["record"]["data"] = "tampered"
    
    with open(temp_ledger, "w") as f:
        f.write(json.dumps(entry, separators=(',', ':')) + "\n")
        
    did_key = envelope.did_key_encode(key.public_key())
    assert canon_verify.verify_ledger(temp_ledger, did_key) is False

def test_verify_broken_chain(temp_ledger, key):
    ledger.append_entry(temp_ledger, {"data": "one"}, key)
    ledger.append_entry(temp_ledger, {"data": "two"}, key)
    
    # Break chain
    with open(temp_ledger, "r") as f:
        lines = f.readlines()
        
    entry = json.loads(lines[1])
    entry["prev"] = "badhash" * 8
    
    with open(temp_ledger, "w") as f:
        f.write(lines[0])
        f.write(json.dumps(entry, separators=(',', ':')) + "\n")
        
    did_key = envelope.did_key_encode(key.public_key())
    assert canon_verify.verify_ledger(temp_ledger, did_key) is False
