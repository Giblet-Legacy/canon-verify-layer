# canon-verify-layer — P6 Canon Verify

README.md — repository purpose and layer contract for P6 Canon Verify.

Function:
    This repository implements primitive layer P6 of the Forge Stack:
    the independent zero-trust ledger verifier. It is a standalone
    script that reimplements the cryptographic and hash-chain rules
    without importing any other Forge Stack layer.

Layer:    P6 — Canon Verify
Depends:  (nothing — standalone zero-trust script)
Consumed: Auditing, external verification
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
Status:   1.0.1 (frozen). canon_verify_v2.py (SPEC_V2.md) is built over
          it, not yet frozen. New code calls canon_verify_v2.
