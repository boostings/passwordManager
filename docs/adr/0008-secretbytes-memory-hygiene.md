# ADR 0008: SecretBytes and memory hygiene

- Status: Proposed
- Date: 2026-09-10

## Decision
All secret material in project code is held in `pm.crypto.SecretBytes`:

- `final` class, wraps a `byte[]`, `AutoCloseable`; `close()` overwrites with
  zeros then marks closed; any access after close throws
  `IllegalStateException` (OBJ14-J).
- Does not implement `Serializable` or `Cloneable`; `clone()` is declared and
  throws (OBJ07-J). `toString()` returns `"SecretBytes[redacted]"`. `equals`
  is constant-time and `hashCode` is not derived from content (returns a
  constant) so secrets cannot be used as map keys and cannot leak via hash.
- Constructor copies the input array and zeroes the caller's array if
  requested (`SecretBytes.takeOwnership(byte[])`), otherwise `copyOf`.
- `withBytes(Consumer<byte[]>)` exposes the buffer to a scoped callback only;
  no getter returns the internal array (OBJ05-J, FIO05-J).
- `SecretChars` is the `char[]` twin for passphrase entry and converts to
  `SecretBytes` via UTF-8 with explicit charset, zeroing the char array.
- Project logger has a type check that refuses `SecretBytes`, `SecretChars`,
  and any class annotated `@Sensitive`; the Semgrep rule
  `cert.FIO13-J.log-secret` backs it statically.
- JVM launch flags in release: `-XX:-HeapDumpOnOutOfMemoryError`,
  `-XX:+DisableAttachMechanism`, no JMX, no JDWP (ENV05-J, ENV06-J).
- Documented limitation: the JVM may copy arrays during GC; zeroing is
  best-effort (R-003).

## Alternatives considered
- `javax.security.auth.Destroyable` alone: no ownership semantics, no
  scoping API.
- Off-heap `ByteBuffer`: avoids GC copies but complicates every JCA call which
  wants `byte[]`; not worth it for v1. Revisit if R-003 is ever upgraded.

## CERT rules referenced
OBJ05-J, OBJ07-J, OBJ13-J, OBJ14-J, FIO05-J, FIO13-J, SER03-J, STR03-J, MET12-J,
ENV05-J, ENV06-J.
