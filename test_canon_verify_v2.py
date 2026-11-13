"""
test_canon_verify_v2.py — P6 Canon Verify v2 (strict layer) test suite

Function:
    Executable expression of SPEC_V2.md. Written before
    canon_verify_v2.py and run red first. Uses P4 ledger_v2 only to
    write real ledgers and to check that P6 v2 and P4 v2 agree;
    canon_verify_v2.py itself imports nothing from the stack.

Functions in this file (pytest-collected):
    1. test_valid_ledger
    2. test_empty_and_missing
    3. test_bad_line_forms
    4. test_deep_nesting
    5. test_tamper_and_wrong_key
    6. test_agrees_with_p4_v2
    7. test_isolation

Helpers:
    8. _write_ledger — a three-entry ledger_v2 ledger, returns (path, did, pub)
    9. _variants     — (name, bytes) cases built from a good ledger

Layer:    P6 — Canon Verify, v2 (strict)
Spec:     SPEC_V2.md 2.0.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import ast
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in ("envelope-layer", "ledger-layer"):
    _full = os.path.join(_HERE, "..", _p)
    if _full not in sys.path:
        sys.path.insert(0, _full)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import envelope_v2  # noqa: E402
import ledger_v2  # noqa: E402
import canon_verify  # noqa: E402
import canon_verify_v2  # noqa: E402


# 8. _write_ledger
def _write_ledger(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = str(tmp_path / "ledger.jsonl")
    for n in range(3):
        ledger_v2.append_entry(path, {"n": n, "text": "entry"}, key)
    return path, envelope_v2.did_key_encode(key.public_key()), key.public_key()


# 9. _variants
def _variants(good):
    lines = good.split(b"\n")
    first = lines[0]
    return [
        ("crlf", good.replace(b"\n", b"\r\n")),
        ("trailing_blank", good + b"\n"),
        ("no_final_lf", good.rstrip(b"\n")),
        ("whitespace", good.replace(b'"seq":', b'"seq": ', 1)),
        ("extra_key", good.replace(b'{"seq"', b'{"x":1,"seq"', 1)),
        ("duplicate_key", good.replace(b'{"seq":0,', b'{"seq":0,"seq":0,', 1)),
        ("non_ascii", good.replace(b"entry", "entré".encode("utf-8"), 1)),
        ("nan", good.replace(b'"n":0', b'"n":NaN', 1)),
        ("tampered", good.replace(b'"n":1', b'"n":9', 1)),
        ("empty", b""),
        ("first_only_ok", first + b"\n"),
    ]


# 1. test_valid_ledger
def test_valid_ledger(tmp_path):
    path, did, _ = _write_ledger(tmp_path)
    assert canon_verify_v2.verify_ledger(path, did) is True
    assert canon_verify.verify_ledger(path, did) is True


# 2. test_empty_and_missing
def test_empty_and_missing(tmp_path):
    key = Ed25519PrivateKey.generate()
    did = envelope_v2.did_key_encode(key.public_key())
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    assert canon_verify.verify_ledger(str(empty), did) is True  # the v1 behaviour v2 closes
    assert canon_verify_v2.verify_ledger(str(empty), did) is False
    assert canon_verify_v2.verify_ledger(str(tmp_path / "absent.jsonl"), did) is False


# 3. test_bad_line_forms
def test_bad_line_forms(tmp_path):
    path, did, _ = _write_ledger(tmp_path)
    good = open(path, "rb").read()
    for name, data in _variants(good):
        if name == "first_only_ok":
            continue
        p = tmp_path / f"{name}.jsonl"
        p.write_bytes(data)
        assert canon_verify_v2.verify_ledger(str(p), did) is False, name


# 4. test_deep_nesting
def test_deep_nesting(tmp_path):
    p = tmp_path / "deep.jsonl"
    p.write_bytes(b"[" * 100000 + b"]" * 100000 + b"\n")
    assert canon_verify_v2.verify_ledger(str(p), "did:key:z6Mk") is False


# 5. test_tamper_and_wrong_key
def test_tamper_and_wrong_key(tmp_path):
    path, did, _ = _write_ledger(tmp_path)
    other = envelope_v2.did_key_encode(Ed25519PrivateKey.generate().public_key())
    assert canon_verify_v2.verify_ledger(path, other) is False
    assert canon_verify_v2.verify_ledger(path, "not a did") is False
    assert canon_verify_v2.verify_ledger(path, None) is False


# 6. test_agrees_with_p4_v2
def test_agrees_with_p4_v2(tmp_path):
    path, did, pub = _write_ledger(tmp_path)
    good = open(path, "rb").read()
    cases = [("good", good)] + _variants(good)
    for name, data in cases:
        p = tmp_path / f"agree_{name}.jsonl"
        p.write_bytes(data)
        assert canon_verify_v2.verify_ledger(str(p), did) == ledger_v2.verify_ledger(str(p), pub), name


# 7. test_isolation
def test_isolation():
    src = open(os.path.join(_HERE, "canon_verify_v2.py"), encoding="utf-8").read()
    names = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    stack = {"envelope", "envelope_v2", "sign", "sign_v2", "ledger", "ledger_v2",
             "freeze", "genesis", "record", "store", "substrate"}
    assert not (names & stack), names & stack
    assert "canon_verify" in names
