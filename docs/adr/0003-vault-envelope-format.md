# ADR 0003: Vault envelope format

- Status: Accepted
- Ratified 2026-10-03 by the M1 team
- Date: 2026-09-10
- Deciders: project team

## Context
The vault must be tamper-evident before any record is parsed (SR-020), carry
its own version and KDF parameters authenticated (SR-015), support multiple
unlock slots (SR-013), and be migratable (`plan.md` §21).

## Decision
A single file `vault.pmv` with this layout (all integers big-endian):

```
magic        8 bytes   "PMVAULT\0"
version      u16       format version (starts at 1)
header_len   u32       length of CBOR header
header       CBOR map  (see below)                       -- covered by AAD
data_salt    32 bytes  random per save; HKDF salt        -- covered by AAD
ciphertext   ...       AES-256-GCM(payload) with 16-byte tag
```

Header CBOR map (deterministic encoding, RFC 8949 §4.2):
```
{ "kdf": {"alg":"argon2id","m":<KiB>,"t":<iters>,"p":<lanes>,"salt":<32B>},
  "slots": [ {"id":<uuid>,"type":"passphrase"|"keychain"|"fido2"|"recovery",
              "wrapped_key":<bytes>, "params":{...per type...}} ... ],
  "created": <epoch s>, "saved": <epoch s>, "save_seq": <u64> }
```

AAD = magic ‖ version ‖ header_len ‖ header ‖ data_salt. Any change to any of
those fails tag verification. Payload is a CBOR-encoded, schema-validated record
set (ADR 0006).

Rules:
- Parser reads `header_len` and refuses values above 64 KiB; refuses files
  above 256 MiB; rejects unknown `version` greater than supported.
- `save_seq` is monotonic; a restore that would lower it warns (rollback
  detection, not prevention: the user may legitimately restore).
- Version downgrade on open is refused unless forced (SR-701).
- Writes are temp-file-in-same-directory + fsync + atomic rename (SR-041).

## Alternatives considered
- Age/PGP-style containers: no multi-slot model matching ours, and we would
  still need our own header.
- SQLite with SQLCipher: a large native dependency in a Tier 1 module.
- JSON header: non-deterministic encoding complicates AAD; CBOR deterministic
  encoding is specified.

## Consequences
One authenticated blob; no partial reads, so the whole vault is decrypted on
unlock. Acceptable for the expected size (thousands of records, well under
10 MB). Revisit chunking if that assumption breaks.

## Security considerations
Header is authenticated but not encrypted: it reveals slot types and KDF
parameters (Metadata class). No Sensitive or Secret fields are permitted in the
header; `data-classification.md` is the authority.

## CERT rules referenced
SER03-J, SER12-J (no native serialization), MSC05-J (size bounds), FIO02-J,
IDS11-J (validate final representation).

## Implementation note (2026-10-03, checked against the M1 code at ratification)

The layout, AAD, 64 KiB header cap (`EnvelopeCodec.MAX_HEADER`), 256 MiB file
cap (`VaultFileStore.MAX_FILE_BYTES`), newer-version refusal
(`UNSUPPORTED_VERSION`) and atomic temp-file + fsync + rename write
(`VaultFileStore`) are implemented as stated. The header differs from the
sketch above. `docs/schemas/vault-header.cddl` is authoritative:

- The header carries `"schema_version": 1` (ADR 0006).
- Slots have no `"params"` map. A slot is exactly `id` (16-byte UUID),
  `type` and `wrapped_key` (40 bytes).
- M1 accepts only the slot types `"passphrase"` and `"recovery"`, with exactly
  one passphrase slot and at most one recovery slot. `"keychain"` and `"fido2"`
  are rejected as `CORRUPT` until a later milestone adds them.
- `save_seq` must be >= 1 and is bumped on every save. M1 has no restore
  operation, so the rollback warning is not implemented yet. M1 also has no
  forced open: a version older than 1 is `CORRUPT`, and one newer than 1 is
  `UNSUPPORTED_VERSION`.
