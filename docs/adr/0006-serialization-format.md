# ADR 0006: CBOR with schema validation for all serialized data

- Status: Accepted
- Ratified 2026-10-03 by the M1 team
- Date: 2026-09-10

## Context
The vault payload, backups, LAN messages, and IPC messages all need a
serialization format. Java native serialization is banned (SER12-J).

## Decision
**CBOR (RFC 8949)**, deterministic encoding, via a small, well-maintained
Java CBOR library with no reflection-based object mapping. Every message and
record type has a hand-written codec in a `codec` package and a **CDDL**
schema in `docs/schemas/`. Decoding is two-phase: (1) structural parse with
depth ≤ 16, total size bound, string/bytes length bounds; (2) codec
validation against the CDDL-derived rules (required keys, types, enum values,
ranges). Unknown keys are ignored on read (forward compatibility) but a
`schema_version` int is mandatory in every top-level map.

Backups use the same envelope as the vault (ADR 0003) with an outer CBOR map
adding `{"kind":"backup","app_version":..,"created":..}`.

## Alternatives considered
- JSON: text, larger, non-deterministic by default, no native bytes.
- Protobuf: good, but the generated-code toolchain and reflection-based
  runtime are more surface than CBOR needs.
- Java serialization: banned.

## Consequences
Hand-written codecs are more work but make every field's validation explicit
and reviewable, and the fuzz harness targets one decoder entry point per type.

## Security considerations
No polymorphic type dispatch from data; the codec chosen is determined by the
caller's context, never by a field in the input (prevents gadget-style
attacks).

## CERT rules referenced
SER12-J, SER00-J (compatibility via schema_version), MSC05-J, IDS11-J, OBJ06-J
(defensive copies of byte fields).

## Amendment 1 (2026-10-02): in-house CBOR subset, no library

The Decision above says "via a small, well-maintained Java CBOR library". No
library is used. The candidate, `co.nstant.in:cbor:0.9`, has had no release
since 2020-04-04 (Maven Central `maven-metadata.xml`: latest 0.9, last updated
2020-04-04) and ships no JPMS descriptor: its jar contains no
`module-info.class` and its manifest has no `Automatic-Module-Name`, so it
could only join the module graph as a filename-derived automatic module.

Instead `pm.vault.cbor` hand-rolls the deterministic subset the vault needs:
unsigned integers, byte strings, text strings, arrays, maps with text keys, and
booleans (`CborValue.UInt`, `Bytes`, `Text`, `Array`, `MapV`, `Bool`). The
reader rejects everything else: indefinite lengths, tags, floats, negative
integers, non-shortest integer or length encodings, unsorted or duplicate map
keys, invalid UTF-8, trailing bytes, and any `CborLimits` bound exceeded. The
writer emits RFC 8949 §4.2.1 deterministic encoding only.

Consequences: the bounded parser that reads the unauthenticated header is
entirely project code, covered by the fuzz harnesses in `pm-fuzz`, and a
Tier 1 module gains no third-party dependency (plan.md Part II Phase 5). The
cost is that the subset must be extended by hand if a later schema needs a
type outside it (for example negative integers or floats); such a change needs
its own amendment. The package is not exported from `pm.vault`.

## Implementation note (2026-10-03, checked against the M1 code at ratification)

The Decision and Amendment 1 hold, with these differences from the code:

- Integer range. `CborValue.UInt` holds a Java `long`, so the subset covers
  unsigned integers 0 to 2^63 - 1 only. The reader rejects a major type 0
  argument of 2^63 or more with `CborException.Code.LIMIT`, not as malformed.
- Bounds. `CborLimits` sets two profiles, both with nesting depth <= 16.
  `HEADER`: 1,024 items, 4,096-byte strings, 64 KiB total. `PAYLOAD`:
  1,000,000 items, 1 MiB strings, 256 MiB total. Items are a running total in
  which every map key and every map value counts as one. `CborWriter.encode`
  enforces the same limits, so the writer cannot produce what the reader refuses.
- Codec location. There is no `codec` package. The hand-written codecs are
  `pm.vault.envelope.EnvelopeCodec` (header, `docs/schemas/vault-header.cddl`)
  and `pm.vault.record.RecordCodec` (payload, `docs/schemas/records.cddl`).
- Backups. M1 does not implement the backup outer map
  (`{"kind":"backup",...}`). It stays a decision for the milestone that adds
  backups.
