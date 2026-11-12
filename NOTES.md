# NOTES — canon-verify-layer (P6 Canon Verify)

NOTES.md — open questions, divergences and decisions for P6 Canon Verify.

## Decisions
- The test suite imports `ledger` (P4) to generate a test ledger, but
  `canon_verify.py` itself imports nothing from the stack. This proves
  the independent implementation can read and verify what P4 writes.
- The tests locate `../envelope-layer` and `../ledger-layer` relative to
  the test file (not the working directory), so pytest can run from
  anywhere. Both sibling repos must be checked out next to this one.

## Divergences
- 1.0.1 adds a signer check (`entry["signer"] == did_key`) that SPEC
  1.0.0 omitted but P4's own `verify_ledger` performs. Without it, an
  entry signed by the right key but labelled with a different signer
  would pass P6 while failing P4. SPEC updated to 1.0.1.
