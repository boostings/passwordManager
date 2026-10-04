# ADR 0016: Passkey keys and ES256 signing in pm-crypto

- Status: Accepted
- Date: 2026-10-03
- Deciders: project team (Lane A)

## Context
M6 (plan.md §13) requires that passkey private keys never leave `pm-crypto` and that signing is
performed inside it (SR-402). Later phases need: a storage form the vault encrypts at rest
(M6.2), and assertion signatures plus the credential public key for the WebAuthn authenticator
(M6.3). WebAuthn's most widely supported algorithm is ES256 (COSE alg -7): ECDSA on P-256 with
SHA-256. For ES256, WebAuthn ("Signature Formats for Packed Attestation, FIDO U2F Attestation,
and Assertion Signatures") requires the signature as an ASN.1 DER `Ecdsa-Sig-Value`, not the
raw `r || s` that COSE itself uses; this was checked against the spec and is what browsers and
relying-party libraries verify.

## Decision
A new package `pm.crypto.passkey` (SR-080 to SR-084):

- **`PasskeyKey`.** `generate()` draws a 32-byte candidate from `Csprng` and keeps it only if it
  is in [1, n-1] (rejection sampling; a rejection has probability below 2^-32), then computes
  Q = d·G with BouncyCastle's fixed-point comb multiplier. The private key is the **raw 32-byte
  big-endian scalar** in a `SecretBytes` owned by the key, not PKCS#8: the raw scalar has one
  valid encoding, so validation is a range check with no ASN.1 parser in the trust path, and no
  JCA `PrivateKey` object is kept. No public method of `PasskeyKey` returns the scalar.
- **Storage form** (`PasskeyStorage.toStorage(PasskeyKey)` / `PasskeyStorage.fromStorage(SecretBytes)`
  in `pm.crypto.passkey.storage`, exported to `pm.vault` alone): 98 bytes,
  `0x01 (version) || d (32) || 0x04 || X (32) || Y (32)`. The public point is stored so a record
  can be checked without signing. Loading is strict: exact length, version 1, d in [1, n-1], the
  point uncompressed with coordinates below p and on the curve (P-256 has cofactor 1, so that
  also puts it in the prime-order group), and d·G equal to the stored point, compared with
  `ConstantTime.equals`. Any failure is `BAD_INPUT`, and the caller keeps ownership of the input.
  Lane C (M6.2) stores this `SecretBytes` inside the encrypted vault record; it is never written
  anywhere unencrypted.
- **Signing** (`sign(authenticatorData, clientDataHash)`): ECDSA-SHA-256 over
  `authenticatorData || clientDataHash` (authenticator data 37 bytes to 16 KiB, client data hash
  exactly 32 bytes), DER encoded. The nonce is **deterministic, RFC 6979** (BouncyCastle
  `HMacDSAKCalculator` with SHA-256): signing needs no random source, a weak or repeated RNG
  output cannot leak the key through nonce reuse, and the implementation is pinned to exact
  known-answer vectors (RFC 6979 A.2.5, P-256/SHA-256, messages "sample" and "test"). Relying
  parties cannot tell deterministic from random nonces. S is not normalized to low-S: WebAuthn
  does not require it and normalizing would break the RFC vectors.
- **Verify helper** (`Es256.verify(coseKey, authenticatorData, clientDataHash, signature)`):
  accepts only canonical DER (the signature must equal the DER re-encoding of its own r and s:
  no long-form lengths, non-minimal or negative integers, trailing bytes) with r and s in
  [1, n-1]. A malformed signature is `false`; a malformed key or input length is `BAD_INPUT`.
  High-S signatures are accepted (WebAuthn relying parties do not require low-S, and ECDSA's
  (r, s) / (r, n - s) malleability is harmless for assertions); the helper must not be used
  where a signature has to be unique. No strict mode is offered until a caller needs one.
- **COSE_Key** (`CoseKey.encodeEc2` / `decodeEc2`, `PasskeyKey.cosePublicKey()`): the EC2 map
  `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` in CTAP2 canonical CBOR (keys ordered 1, 3, -1, -2, -3,
  minimal lengths, 32-byte coordinates). Every such key is the same 77-byte layout, so encoding
  writes a fixed prefix and separator around X and Y, and decoding accepts only that exact
  layout with a point on the curve. pm-crypto is a leaf module and cannot use the vault's CBOR
  codec (`pm.vault.cbor`); a fixed template needs no general codec.
- **Credential IDs**: `PasskeyKey.newCredentialId()` returns 32 random bytes from `Csprng`
  (WebAuthn allows up to 1023; 32 bytes makes collisions negligible and is what common
  authenticators use).
- **Module boundary** (SR-080, SR-402): `exports pm.crypto.passkey to pm.vault, pm.domain,
  pm.browser` (generate, sign, public key, COSE) and `exports pm.crypto.passkey.storage to
  pm.vault` (the storage form). The vault stores the key (M6.2); the WebAuthn authenticator (M6.3)
  and the extension bridge (M6.4) sit in the domain or browser module and can sign but cannot
  extract the scalar. `PasskeyKey` hands its storage codec to `PasskeyStorage` through
  `pm.crypto.passkey.internal.PasskeyAccess`, which is not exported at all; the codec is installed
  once from `PasskeyKey`'s static initializer and a second install is refused. A qualified export
  makes the compiler refuse every other module (`pm.tui`, `pm.cli`, `pm.approval`, `pm.sharing`;
  and every module but `pm.vault` for the storage package), as `pm.crypto.ssh` does (ADR 0013).
  Checked at M6.1 by a planted `pm.browser.bridge` class calling `PasskeyStorage.toStorage`:
  javac failed with "package pm.crypto.passkey.storage is not visible" (then removed). ArchUnit
  rules `onlyVaultDomainAndBrowserReachPasskeys` and `onlyTheVaultReachesPasskeyStorage` mirror
  both exports in bytecode. javac's
  `module` lint for not-yet-visible targets is covered by the existing suppression (CE-021,
  widened scope recorded as CE-050). If M6.3 lands in a module not listed, the export is widened
  in that phase with a new CE note.
- BouncyCastle's low-level EC API (`org.bouncycastle.crypto`, `org.bouncycastle.math.ec`) is used
  from the already pinned `bcprov` (ADR 0007); no new dependency.

## Alternatives considered
- **PKCS#8 storage**: self-describing, but needs a DER parser on load and admits several encodings
  of one key (optional public key, parameters); the version byte gives the same evolvability.
- **JCA `KeyPairGenerator` / `Signature`**: the JDK generator draws from its own `SecureRandom`
  (not `Csprng`, SR-017), cannot derive Q from a stored d for the consistency check, and its
  ECDSA nonces are random, so no exact known-answer test is possible. The JDK's SunEC verifier is
  used in tests as the independent check instead.
- **Raw `r || s` signatures** (COSE style): rejected by WebAuthn relying parties for ES256.
- **A general CBOR encoder in pm-crypto**: more code for one fixed structure.

## Consequences
- Residual risk (as ADR 0008 and ADR 0013): copies of the private scalar that pm cannot zero,
  unreachable once the call returns: the `BigInteger` d built for every signature and the
  BouncyCastle `ECPrivateKeyParameters` holding it; inside `HMacDSAKCalculator`, the `byte[]`
  copy of d it makes for RFC 6979 and the HMAC key state (K, V) derived from d and the message
  hash, which BouncyCastle does not wipe; and the `BigInteger` scalar during generation and
  loading. Scalar multiplication uses BouncyCastle's P-256 field arithmetic and fixed-point comb,
  but the `BigInteger` steps around it (range checks, ECDSA's s computation, and the k^-1 mod n
  inversion via `modOddInverse`) are not strictly constant time. Signing runs only on an explicit WebAuthn request, so an observer gets few, coarse
  timings; recorded as accepted residual risk, to be revisited in the M6.5 security exit.
- Deterministic ECDSA is sensitive to fault injection; not a realistic threat for a software
  authenticator on the user's machine.
- Tests: RFC 6979 vectors, exact COSE bytes for the RFC public key, JDK SunEC verification of
  pm's signatures and pm verification of SunEC signatures, refusal of scalar 0, n, n + 1,
  2^256 - 1, wrong lengths and versions, compressed or off-curve points, coordinates at p and a
  valid point that is not d·G, malformed DER in every structural position, and zero-filling of
  the storage form on close. pm-crypto keeps 100% branch coverage.
