# ADR 0007: Argon2id floors and tuning

- Status: Accepted
- Ratified: 2026-10-02 by the team (M1 sprint Phase 0)
- Date: 2026-09-10

## Decision
- Algorithm: Argon2id (RFC 9106) via the Bouncy Castle `Argon2BytesGenerator`
  (the one audited third-party crypto dependency permitted in `pm-crypto`;
  pinned and checksum-verified).
- **Floors** (never lower): m = 64 MiB, t = 3, p = 1, salt = 32 bytes, output
  = 32 bytes. These meet the OWASP baseline (m=19 MiB,t=2 / m=64 MiB,t=3 etc.)
  with margin.
- **Tuning at vault creation**: benchmark on the creating machine to hit a
  target of ~500 ms for unlock; increase `m` first (cap 1 GiB), then `t`
  (cap 10). Store the result in the header. Never re-benchmark at unlock.
- **Re-tune** is an explicit Settings action that re-wraps the passphrase slot
  and requires the passphrase.
- Recovery key, keychain, and FIDO2 slots do not use Argon2id (their inputs are
  already high-entropy); they use HKDF only.

## Alternatives considered
- scrypt / PBKDF2: weaker memory-hardness or none.
- Re-benchmarking at every startup: parameters must match what wrapped the
  slot, so this is meaningless; misreading of the original plan corrected here.

## Consequences
Unlock costs ~0.5 s and ≥64 MiB RAM on the creating machine class; a much
weaker device may take a few seconds. Acceptable.

## Security considerations
Floors are enforced in code and in the parser: a header with sub-floor
parameters is refused as a downgrade attempt (TM-11).

## CERT rules referenced
MSC02-J, MSC03-J (parameters are not secrets but are integrity-protected).
