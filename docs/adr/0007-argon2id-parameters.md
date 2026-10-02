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

### Heap budget (amended 2026-10-02 after review)
- `Kdf.argon2id` refuses with `CryptoException(BAD_PARAMS)` before it allocates
  anything when `memoryKiB × 1024 × 1.1` is more than the free heap budget, which
  is the JVM max heap minus the heap in use. If the JVM reports no max heap, the
  budget falls back to the 1 GiB cap. The 10% margin covers BC's block
  bookkeeping, so the hash fails cleanly instead of with `OutOfMemoryError`.
- `Kdf.tune` caps `m` at half the max heap (and at the 1 GiB cap), so a vault
  created by this JVM can be unlocked by this JVM.
- **Consequence: portability.** A vault tuned on a big machine, or under a large
  `-Xmx`, stores a large `m` in its header. Opened by a JVM whose heap can't hold
  1.1 × m, it **refuses to unlock with `BAD_PARAMS`**. The passphrase may be right
  and the file intact. Nothing is retried at a lower `m`, because `m` must match
  what wrapped the slot.
- **`-Xmx` guidance.** Run with `-Xmx` above `1.1 × m` of the largest vault
  you open, plus the working set. `-Xmx2g` covers every vault the tuner can
  produce (m ≤ 1 GiB). The release launcher should set it; until it does, the
  default JVM heap (a quarter of RAM) is what decides. A user who hits the error
  on a small machine can re-tune on the big machine (Settings, re-wrap the
  passphrase slot) to a lower `m`.
- **Lane C must map this `BAD_PARAMS` to its own user-visible message**,
  distinct from `CORRUPT` and from `WRONG_CREDENTIAL`, along the lines of "This
  vault needs more memory than this program may use. Restart with a larger
  -Xmx." Reporting it as `CORRUPT` would send the user to restore a backup that
  has the same parameters and fails the same way. Lane C tells the two
  `BAD_PARAMS` sources apart by call site: from `Argon2Params.checked(m, t, p)`
  while decoding the header (values below the floors or above the caps), it is a
  refused header and stays `CORRUPT` (TM-11 downgrade); from `Kdf.argon2id`, it
  is the heap budget and gets the memory message.

## Security considerations
Floors are enforced in code and in the parser: a header with sub-floor
parameters is refused as a downgrade attempt (TM-11).

## CERT rules referenced
MSC02-J, MSC03-J (parameters are not secrets but are integrity-protected).
