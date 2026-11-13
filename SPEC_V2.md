# SPEC V2 — canon-verify-layer (P6 Canon Verify, strict layer)

SPEC_V2.md — specification for canon_verify_v2.py, the layer above P6 v1.0.1.

Function:
    Specifies canon_verify_v2.py, a strict layer over the frozen P6
    v1.0.1 verifier (canon_verify.py). It makes P6 agree with P4
    ledger_v2 (frozen 2.0.0) on which files are valid ledgers, so the
    zero-trust check and the writer can never disagree in the
    verifier's favour. SPEC.md 1.0.1 remains authoritative for
    everything this document does not change.

Layer:     P6 — Canon Verify, v2 (strict)
Depends:   canon_verify.py (P6 v1.0.1). Still no other Forge Stack layer.
Consumed:  The Cockpit (`forge verify-ledger`), auditing
Version:   SPEC V2 2.0.0
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

---

## 1. Why v2

SPEC.md §2 says "an empty ledger (no entries) verifies as True". P4
ledger_v2 and P8 store_v2 both say an empty ledger is **not** valid
(P4 NOTES Q2, James: "keep"), because a ledger has at least its
genesis entry. On a fresh install, `forge verify-ledger` therefore
reported "intact" for a ledger with nothing in it.

v1 also accepts line forms that P4 v2 rejects (CRLF endings,
whitespace, extra keys, duplicate keys). An independent verifier that
is looser than the writer can certify a file the writer refuses.

## 2. Zero-trust isolation (unchanged)

canon_verify_v2 imports only the standard library, `cryptography`
and canon_verify (its own v1). It MUST NOT import envelope, ledger
or any other Forge Stack layer. Its line-form check is written here,
independently of P4.

## 3. verify_ledger(filepath, did_key) -> bool

Returns False — never raises — unless every check passes:

1. The file exists, is readable and is not empty.
2. It contains no `\r` byte and ends with `\n`.
3. Every line (split on `\n`) is ASCII, parses as a JSON object with
   no duplicate keys and no NaN/Infinity tokens, has exactly the keys
   `seq, prev, record, signer, hash, signature`, and is byte-identical
   to `json.dumps(obj, separators=(",", ":"))` of the parsed object.
   This is P4 SPEC_V2 §2's line form.
4. canon_verify.verify_ledger (v1) returns True for exactly the bytes
   checked above. v2 hands v1 a private copy, so the file cannot
   change between the form check and the cryptographic check.

A RecursionError (deeply nested record) is a False, not a crash.

## 4. Public API

1. verify_ledger — v2: strict form and non-empty, then v1

## 5. Tests (test_canon_verify_v2.py)

- A P4 ledger_v2 ledger verifies True; the same key under v1 too.
- Empty file, missing file → False (v1 said True for empty).
- CRLF endings, a trailing blank line, missing final LF, whitespace
  inside a line, an extra key, a duplicate key, a non-ASCII byte,
  NaN in a record → False, never raises.
- Deeply nested record line → False, never raises.
- Tampered line, wrong did:key → False (inherited from v1).
- Agreement: for every case above, v2's answer equals
  ledger_v2.verify_ledger's answer.
- canon_verify_v2.py imports no Forge Stack module other than
  canon_verify (checked by reading its source).

---

## Document control

- **SPEC V2 2.0.0** — 2026-11-13, by the VS Code AI on James's
  delegation ("fix all 11 issues"). Resolves the empty-ledger
  disagreement between P6 and P4 v2.
