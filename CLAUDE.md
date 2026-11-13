# Forge Stack Context — P6 Canon Verify

CLAUDE.md — Context briefing for AI assistants working in this repository.

## The Immutable Rule
Never rewrite a primitive. Add a layer.

## P6 ZERO-TRUST ISOLATION (CRITICAL)
`canon_verify.py` MUST NOT import any other Forge Stack layer.
It cannot import `envelope`, `ledger`, etc.
It is a standalone script that reimplements canonicalisation,
SHA-256, and Ed25519 verification from scratch using only the Python
standard library and `cryptography`.

## Dual-Device Workflow
We build on an S24 (Termux) and a laptop (VS Code). State is confirmed, never assumed. Always use LF line endings. Commit messages must be clear. We use the Good/Bad/Ugly CHANGELOG format (latest at top).

## Header Discipline
Every file MUST have a top header paragraph explaining its function.
Every function MUST have a numbered header.

## P6 Architecture Specifics
- `canon_verify_v2.py` (SPEC_V2.md, frozen 2.0.0) is the current layer: empty ledger is False and P4 SPEC_V2's line form is enforced. It may import `canon_verify`, nothing else from the stack.
- Reads `.jsonl` ledgers.
- Verifies the Ed25519 signature over the raw 32-byte digest.
- Checks the hash chain (prev, hash, seq).
- Must decode `did:key` independently.
