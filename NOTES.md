# NOTES — canon-verify-layer (P6 Canon Verify)

NOTES.md — open questions, divergences and decisions for P6 Canon Verify.

## Decisions
- The test suite imports `ledger` (P4) to generate a test ledger, but
  `canon_verify.py` itself imports nothing from the stack. This proves
  the independent implementation can read and verify what P4 writes.
