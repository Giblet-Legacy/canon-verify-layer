"""
canon_verify_v2.py — P6 Canon Verify v2, strict layer over the frozen v1 verifier

Function:
    The verifier new code calls instead of canon_verify.py. It rejects
    an empty ledger and every line form P4 ledger_v2 rejects (CRLF,
    whitespace, extra or duplicate keys, non-ASCII, NaN), then hands a
    private copy of exactly the checked bytes to the frozen v1 verifier
    for the hash-chain and signature checks (SPEC_V2.md). Never raises
    on bad ledger data.

    Zero-trust isolation is kept: this file imports only the standard
    library and canon_verify (its own v1). The line-form check is
    written here, independently of P4.

Public API:
    1. verify_ledger — strict form and non-empty, then v1

Internal helpers (not exported):
    2. _no_constant  — parse_constant hook rejecting NaN / Infinity
    3. _no_dupes     — object_pairs_hook rejecting duplicate keys
    4. _line_ok      — one line matches the P4 SPEC_V2 §2 form
    5. _form_ok      — the whole file matches it and is non-empty

Layer:    P6 — Canon Verify, v2 (strict)
Depends:  canon_verify.py (P6 v1.0.1). No other Forge Stack layer.
Consumed: The Cockpit (`forge verify-ledger`), auditing
Spec:     SPEC_V2.md 2.0.0
Version:  2.0.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import canon_verify as _v1  # noqa: E402

_KEYS = ("seq", "prev", "record", "signer", "hash", "signature")


# ---------------------------------------------------------------------------
# 2. _no_constant
#    NaN / Infinity / -Infinity are not JSON (P1 v2) and have no canonical form.
# ---------------------------------------------------------------------------
def _no_constant(token):
    raise ValueError(f"non-finite constant {token}")


# ---------------------------------------------------------------------------
# 3. _no_dupes
#    A duplicate key would let two different parses of one line exist.
# ---------------------------------------------------------------------------
def _no_dupes(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate key {k!r}")
        obj[k] = v
    return obj


# ---------------------------------------------------------------------------
# 4. _line_ok
#    SPEC_V2 §3 step 3: ASCII, one object, exact keys, byte-identical to
#    its compact form.
# ---------------------------------------------------------------------------
def _line_ok(line):
    try:
        text = line.decode("ascii")
        obj = json.loads(text, parse_constant=_no_constant, object_pairs_hook=_no_dupes)
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(obj, dict) or tuple(obj.keys()) != _KEYS:
        return False
    return json.dumps(obj, separators=(",", ":")) == text


# ---------------------------------------------------------------------------
# 5. _form_ok
#    SPEC_V2 §3 steps 1–3 over the whole file's bytes.
# ---------------------------------------------------------------------------
def _form_ok(data):
    if not data or b"\r" in data or not data.endswith(b"\n"):
        return False
    return all(_line_ok(line) for line in data[:-1].split(b"\n"))


# ---------------------------------------------------------------------------
# 1. verify_ledger
#    SPEC_V2 §3. v1 checks a private copy of the bytes v2 already checked.
# ---------------------------------------------------------------------------
def verify_ledger(filepath, did_key):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if not _form_ok(data):
            return False
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "ledger.jsonl")
            with open(copy, "wb") as f:
                f.write(data)
            return _v1.verify_ledger(copy, did_key) is True
    except (OSError, TypeError, RecursionError):
        return False
