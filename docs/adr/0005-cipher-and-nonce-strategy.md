# ADR 0005: AES-256-GCM with per-save derived keys

- Status: Proposed
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

## CERT rules referenced
MSC02-J (salt from SecureRandom), ENV02-J/SEC02-J (algorithm names constant).
