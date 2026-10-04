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

## Addendum (2026-10-04, M6.2, Lane C): passkey record and the atomic counter

### Record (`pm.vault.record.PasskeyRecord`, SR-085, SR-086, SR-089)
- Fifth member of the sealed `VaultRecord`, `passkey-record` in `docs/schemas/records.cddl`:
  `type, id, title, rp_id, credential_id, user_handle, user_name, display_name, private_key,
  sign_count, created, updated, last_used`.
- `rp_id`: lower-case ASCII host name, the same label rules as `pm.browser.bridge.Origin`
  (LDH labels of 1 to 63 characters, internationalised names only as `xn--` A-labels, no empty
  label or trailing dot, at most 253 characters). Unlike an origin host, an IPv4 literal is refused
  (any all-digit last label): WebAuthn RP IDs are domains. The model refuses non-canonical input;
  it never lower-cases or maps. `credential_id` is 16 to 1023 bytes (WebAuthn maximum; 16 is the
  entropy floor), `user_handle` 1 to 64 bytes (WebAuthn: non-empty, at most 64).
- `user_name` (WebAuthn `user.name`; `accountName()` in Java, because SpotBugs `NM_CONFUSING`
  refuses `userName` next to `LoginRecord.username`) and `display_name`: at most 256 UTF-16 units,
  well-formed, and no control, format (bidi controls, zero-width), line or paragraph separator
  character, the set the CLI already refuses on a terminal, and must have at least one visible
  character. Visible is an allowlist: a code point of general category L (letter), N (number),
  P (punctuation) or S (symbol), except the blank ones, the Hangul fillers U+115F, U+1160,
  U+3164, U+FFA0, the braille blank U+2800 and the blank musical noteheads U+1D159, U+1D15A.
  Separators, marks (including spacing marks such as U+0903), format, unassigned and private-use
  code points never count, so a prompt cannot show an account as blank. (Round 3 replaced an
  earlier blocklist that let U+1D159/U+1D15A and spacing marks through.) `user_name` must be
  non-empty; `display_name` may be empty. The model refuses them; the public
  `PasskeyRecord.displaySafe` strips them and truncates without splitting a surrogate pair, for
  the WebAuthn layer to apply to names a relying party sends (M6.3).
- `private_key`: the 98-byte `PasskeyStorage` form in a `SecretBytes` owned by the record, a CBOR
  byte string on disk inside the AES-GCM payload, never a `String`. The vault-internal decode
  loads every passkey key with `PasskeyStorage.fromStorage` (d in range, d·G equal to the stored
  point) and refuses the payload (`SCHEMA`) if one does not load; `Vault.put` checks a new passkey
  the same way (`BAD_KEY`). This costs one scalar multiplication per passkey at unlock (well under
  a millisecond each), accepted so that a corrupt key is found at unlock, not after a counter
  has been burnt.
- **The key and the counter are vault-owned (SR-085, SR-086).** The first M6.2 commit claimed
  "no public accessor returns the key"; the adversarial review showed that was not enough,
  because the public `RecordCodec.encodePayload` serialised the key for any module, and the
  public constructor let any module build a record with a chosen key and counter. Now:
  - the constructor is package-private, so only `pm.vault` builds passkey records (javac proof in
    `PasskeyOutsideModuleTest`, ArchUnit rule `onlyTheVaultBuildsPasskeyRecords`);
  - the public `RecordCodec.encodePayload`/`decodePayload` refuse a passkey record
    (`IllegalArgumentException("VAULT_ONLY…")` / `RecordException.Code.VAULT_ONLY`); the vault's
    payload codec writes and reads them through package-private `encodeVaultPayload`/
    `decodeVaultPayload`, reached via the hook. A future export or LAN share (M3.6) that uses the
    public codec therefore refuses passkeys: sharing a passkey is not supported;
  - the key accessor is package-private, and `pm.vault` reaches it, the counter advance, the
    keyless view and the edit merge through `pm.vault.internal.PasskeyRecordAccess`, an unexported
    package (ArchUnit rule `onlyTheVaultReachesVaultInternals`) whose hook `PasskeyRecord`
    installs once from its static initializer (the `PasskeyAccess` pattern of M6.1);
  - `Vault.records()`, `search()` and the `AssertionPort` get **keyless views**: a copy of the
    public fields whose key is an already-closed `SecretBytes`. Closing a view, or anything else
    handed out, never touches the live key. A view cannot be put back as a new passkey
    (`BAD_KEY`: its key does not load);
  - `Vault.put` of a passkey whose id the vault already holds takes only the title, account name,
    display name and update time; the key, counter, creation and last use stay the vault's. A
    stale record put back therefore cannot roll the counter back (review repro: sign, sign,
    put the old snapshot, save, sign gave 1, 2, 1; now 1, 2, 3).
  `toString()` shows id, RP ID and counter only.
- `sign_count` is an unsigned 32-bit value (0 to 2^32 - 1), as in authenticator data.
- **Exact key set.** A passkey record with a missing or unknown key rejects the whole payload,
  unlike the other record types, which ignore unknown keys (ADR 0006). Dropping an unknown field
  on rewrite could silently lose counter-related state written by a newer version. Consequence:
  adding a passkey field later needs a payload schema version bump and a migration (ADR 0015),
  not a silent extension.
- `RecordSearch` matches RP ID, account name, display name and title; never the key, the
  credential ID or the user handle.

### Counter (`Vault.signWithPasskey`, SR-087, SR-088, implements SR-401)
`signWithPasskey(id, clientDataHash, AssertionPort)` returns a `PasskeyAssertion`
(counter, authenticator data, DER signature). Under the vault lock:
1. refuse `LOCKED`, `REENTRANT` (a nested call from inside the port on the same thread),
   `BAD_INPUT` (client data hash not 32 bytes), `NOT_FOUND` (absent or not a passkey) and
   `COUNTER_EXHAUSTED`; nothing changes on any of these;
2. replace the record in memory with a copy whose counter is one higher (last use = clock) and
   close the old one (it was never handed out);
3. write the whole vault, with the new counter, atomically (temp file, fsync, rename; ADR 0005).
   Any failure, a `VaultException` or an unchecked failure of the codec or store, is
   `SAVE_FAILED` with the cause, and nothing is signed;
4. only then load the key from the storage form (`BAD_KEY` if invalid, unreachable since keys are
   checked at decode and put), give the `AssertionPort` a keyless view for the authenticator data
   (it embeds the persisted counter), check that the data is bound to this record (below), sign
   (`SIGN_FAILED` if the port throws, returns null, returns data that is not 37 B to 16 KiB or
   fails the binding check), close the key, return.

**Binding.** The vault, not the port, decides what it signs. It computes SHA-256 of the record's
RP ID itself and refuses (`SIGN_FAILED`) authenticator data unless bytes 0..31 equal it (constant
time), the UP flag (0x01) is set, the AT flag (0x40) is clear (no attested credential data in an
assertion), trailing bytes are present exactly when ED (0x80) is set, and bytes 33..36 equal the
counter just persisted (big-endian u32). So no caller of `signWithPasskey` can get a signature
over another site's RP ID hash or over any counter but the fresh one. UV and the content of
extensions are left to the WebAuthn layer (M6.3). The vault checks rather than builds the first
37 bytes so that the port keeps control of the UV/BE/BS flags; the check gives the same
guarantee. A refused value is **burnt** like a failed save: the advanced counter is already on
disk and is never reused, so a refusal costs one counter value.

**Backups.** A save made only to advance a counter does not rotate the `.bak.N` generations
(`VaultFileStore.backup()` is skipped). Before this fix every assertion rotated them, so three
sign-ins pushed out the only backup holding a record the user had just deleted. A sign while a
put or remove is pending is a content save and rotates as `save()` does.

The port builds authenticator data only; the key never leaves the vault, so `pm.vault`'s public
API does not mention `PasskeyKey` (which is exported only to three modules and would trip javac's
`exports` lint, with no suppression needed now).

- **Never backwards.** The counter is on disk before the signature exists. A crash between the
  save and the signature loses one assertion but the next one carries a higher value. A value
  whose save failed is **burnt**: it stays in memory and is never handed out, so even a write
  that reported failure after reaching disk cannot lead to the same value being signed twice.
- **Concurrency.** The vault's single lock serialises signers: each gets a distinct value, and
  signing order equals counter order. Signing runs under the lock (one ES256 signature). The lock
  is reentrant, so a port that called back into `signWithPasskey` on the same thread would sign
  a later counter first; that call is refused (`REENTRANT`).
- **Overflow at 2^32 - 1.** A record at 2^32 - 1 has signed its last assertion; the next call is
  `COUNTER_EXHAUSTED`, nothing is saved and nothing is signed. Wrapping to 0 would make a relying
  party that stores a non-zero counter flag a cloned authenticator, and sticking at the maximum
  would repeat a released value. The user registers a new passkey. At one assertion per second
  this takes 136 years.
- The save writes every pending in-memory change, not just the counter: callers that keep
  unsaved edits get them saved by an assertion. Every copy (advance, view, edit merge) has its
  own key buffer or none, so no two records share a closable key; snapshots taken earlier from
  `records()` keep showing the old counter and are harmless to close or put back.

### Restore (AC-51)
A backup holds the counters of the day it was taken; a relying party has since seen higher ones.
`VaultBackups.restore` therefore does not install a backup that holds a passkey byte for byte: it
decodes the verified records, raises every passkey counter to
`max(backup + RESTORE_COUNTER_MARGIN, existing + 1)` with the margin 2^20, and seals them as the
next save (`save_seq + 1`) under the same vault key. `existing` is the counter of the same record
id in the vault being overwritten, read with the restore passphrase; if that vault does not open
with it (other passphrase, corrupt, needs migration) or holds no such record, the raise uses the
backup alone. Restoring the same backup twice therefore never goes below a counter signed between
the two restores. A raise that would reach 2^32 - 1 sets 2^32 - 1, which is exhausted: the
credential refuses to sign (`COUNTER_EXHAUSTED`) rather than repeat a value (an earlier cap at
2^32 - 2 re-issued counters signed after a backup taken near the top). Never lowered. Assertions
after a restore onto a fresh location reuse no counter unless more than 2^20 (about one million)
were signed after the backup was taken. A backup with no passkey is still installed byte for
byte. `verify` does not change. The cost is 2^20 of the
2^32 counter space per restore, about 4000 restores.

### Residual risks and follow-ups
- AC-51 residual: copying a `.bak.N` file (or any older vault file) over the vault by hand, outside
  `VaultBackups.restore`, still brings back older counters; so does a restore onto a fresh machine
  or a target that does not open with the restore passphrase after more than 2^20 assertions. A
  vault-independent high-water mark (a counter file outside the vault) was not added: it would be
  a second file to keep consistent with the vault and would not survive the move to a new
  machine either. Revisit in the M6.5 security exit.
- `pm.cli` `Cli.typeOf` shows `passkey` and `pm.tui` `RecordDetailWindow` shows type, title, RP
  ID, account name and counter only; `DashboardWindow` shows `Passkey` and "account @ RP ID" for
  a passkey row (minimal edits made with these fixes, coordinator-approved).
- Registration and editing: outside modules cannot build a `PasskeyRecord`, so the title and
  names of a passkey cannot be edited from outside `pm.vault` yet (`Vault.put` merges only those
  fields, but a caller cannot construct the edited record). M6.3 adds a vault-side factory (new
  key → record) and vault methods to edit title and names.
- The public codec no longer decodes passkeys, so `RecordCodecFuzzTest` reaches the passkey
  decoder only up to the `VAULT_ONLY` refusal; the vault-internal path is covered by the vault
  tests.
- Tests: `PasskeyRecordTest` (bounds, display safety, visible-character rule, no public key
  accessor or constructor, `VAULT_ONLY` both ways, key checked at decode, toString, search,
  round trip at counter 2^32 - 1, exact key set, u32 limit, CDDL keys equal the codec's keys),
  `PasskeyVaultOwnershipTest` (`T-PK-02`: stale put, put keeps key and counter, keyless views,
  closing handed-out records, `REENTRANT`, backups survive signing, authenticator data with a
  foreign or other-site RP hash, UP clear, AT set, a stale, later or zero counter, short data or
  an ED/trailing-bytes mismatch is `SIGN_FAILED` with the counter burnt while UV and extension
  data are accepted, restore raises by 2^20 and above the overwritten vault, restoring the same
  backup twice reuses nothing, a raise reaching the top leaves the credential exhausted),
  `PasskeyOutsideModuleTest` (javac refuses a `module evil` that builds a record, calls the
  vault-only codec or reaches `pm.vault.internal` or the storage form; a public-codec control
  compiles), ArchUnit `onlyTheVaultReachesVaultInternals` and `onlyTheVaultBuildsPasskeyRecords`,
  `PasskeyCounterTest` (`T-PK-02`: the file as it was while the port ran already holds the
  counter and signatures verify; save failure by a read-only directory and by a failing codec
  is `SAVE_FAILED`, releases nothing and burns the value; a port that throws or returns null is
  `SIGN_FAILED` after the save; a broken key is refused at put; 4 threads x 10 signers give
  1..40 exactly once in order; exhaustion at 2^32 - 1 leaves the file byte-identical).
