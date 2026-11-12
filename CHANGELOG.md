# CHANGELOG — canon-verify-layer (P6 Canon Verify)

CHANGELOG.md — build history for P6 Canon Verify, latest entry at top.

## [v1.0.1] — 2026-11-12

### Good
- Signer check added: `entry["signer"]` must equal the supplied did:key
  (brings P6 in line with P4's `verify_ledger`). SPEC bumped to 1.0.1.
- Hardened: malformed lines (non-object JSON, wrong field types, non-hex
  signatures, bool `seq`), unreadable files and non-UTF-8 input now
  return False instead of raising.
- Ledger opened with explicit UTF-8 encoding (Windows default was cp1252).
- Replaced `__import__('os')` with a proper `import os`.
- Numbered headers added to every function (Header Discipline).
- Tests: sibling-repo paths resolved relative to the test file; 9 new
  cases (wrong key, bad signature, malformed inputs, bad did:key,
  missing file, did:key decode vs P1). 12/12 pass.
- README status corrected (was still 0.0.0-dev).

### Bad
- (none)

### Ugly
- v1.0.0 verifier could raise `TypeError`/`AttributeError` on malformed
  ledgers instead of returning False, breaking the SPEC contract.

## [v1.0.0] — 2026-11-11

### Good
- `canon_verify.py` implemented to SPEC v1.0.0.
- 3/3 pytest tests pass.
- Strict zero-trust: no imports from the Forge Stack.
- Independently verifies P4 ledgers (hash chain and Ed25519 signatures).

### Bad
- (none)

### Ugly
- (none)

## [v0.0.0-dev] — 2026-11-11

### Good
- Repository scaffolded: `Giblet-Legacy/canon-verify-layer` created for P6.
- Strict zero-trust isolation enforced (no imports from other layers).

### Bad
- (none)

### Ugly
- (none)
