# ADR 0006: CBOR with schema validation for all serialized data

- Status: Proposed
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
