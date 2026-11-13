# NOTES — canon-verify-layer (P6 Canon Verify)

NOTES.md — open questions, divergences and decisions for P6 Canon Verify.

## Open questions

- **Q1 — Freeze canon_verify_v2 at 2.0.0?** **Resolved 2026-11-13 — James: "freeze all".** Frozen on the laptop run; confirmed on the S24 by James, 2026-11-13. Built and green on the
  laptop (19/19). Not yet run on the S24. Raised 2026-11-13. Owner:
  James.

## Decisions

- 2026-11-13 — canon_verify_v2 (SPEC_V2.md): empty ledger → False,
  and P4 SPEC_V2's strict line form is enforced, written
  independently here. Decided by the VS Code AI on James's delegation
  ("fix all 11 issues"). Reason: a zero-trust verifier must never be
  looser than the writer it checks.
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
