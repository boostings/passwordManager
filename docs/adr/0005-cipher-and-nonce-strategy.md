# ADR 0005: AES-256-GCM with per-save derived keys

- Status: Accepted
- Ratified: 2026-10-02 by the team (M1 sprint Phase 0)
- Date: 2026-09-10

## Decision
Payload cipher: **AES-256-GCM** via the JDK `AES/GCM/NoPadding`, key = per-save
DK (ADR 0004), nonce = 12 zero bytes, tag = 128 bits, AAD = header bytes
(ADR 0003). Persisted nonce counters are prohibited. Random 96-bit nonces
under one long-lived key are prohibited.

Fallback if a platform lacks AES hardware and unlock is slow: none. GCM
without AES-NI is still fast enough for vault sizes in scope.

## Alternatives considered
- XChaCha20-Poly1305 with random 192-bit nonce: acceptable and equally safe,
  but not in the JDK (only ChaCha20-Poly1305 with 96-bit nonce is). Would add a
  dependency to a Tier 1 module.
- AES-GCM-SIV: nonce-misuse resistant, but not in the JDK.

## Consequences
One JDK-only cipher; the per-save salt costs 32 bytes per file.

## Security considerations
The known GCM weaknesses (nonce reuse, 2^32 message limit per key) are
structurally impossible: each DK encrypts exactly one message once.

### What the zero-nonce guarantee rests on (amended 2026-10-02 after review)
"Each DK encrypts exactly one message" is a property of the **caller** (Lane C,
`pm.vault`), not of `pm.crypto`. It holds only if every save does all of this:

1. Draws a **fresh 32-byte `dataSalt` from `Csprng.bytes(32)`** for that save.
   A `dataSalt` is never reused, never copied from the file just read, and never
   derived from a counter or the clock.
2. Derives a **new DK** with `HKDF(VK, dataSalt, "pm/data/v1", 32)` from that
   salt and uses it to seal exactly one payload.
3. **Never reuses an unlock-time DK.** The DK derived during unlock to open the
   existing ciphertext (`openWithFreshKey`) decrypts only. It is closed after the
   open and is never kept on the `Vault` to seal a later save.

Two saves that reach the same DK (same VK and same `dataSalt`) seal two different
plaintexts under the same key and the same zero nonce. That exposes the XOR of
the plaintexts and lets an attacker forge GCM tags. Nothing in `pm.crypto` can
detect it.

`Aead.sealWithFreshKey` consumes (closes) its key, and `openWithFreshKey` does
not. Closing the key only stops a **double seal inside one process with the same
`SecretBytes` object**. It does not stop a caller that derives the same DK again
from a reused `dataSalt`, or that keeps the unlock DK bytes and wraps them in a
new `SecretBytes`. The controls for those cases are the required Lane C test
`VaultServiceTest.saveUsesFreshDataSaltEachTime` (team plan §5 C: two saves give
a different `dataSalt` and a different ciphertext), the T-ENC-01 property in
ADR 0004, and code review of `Vault.save()`.

## CERT rules referenced
MSC02-J (salt from SecureRandom), ENV02-J/SEC02-J (algorithm names constant).
