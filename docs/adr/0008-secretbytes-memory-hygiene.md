# ADR 0008: SecretBytes and memory hygiene

- Status: Accepted
- Ratified: 2026-10-02 by the team (M1 sprint Phase 0)
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
- Project logger (`SafeLog`) is allowlist-only: it logs `String`, `Boolean`,
  `Character`, `UUID`, `Duration`, enum names, and JDK `Number`,
  `TemporalAccessor` and `Path` values, and refuses everything else, including
  `SecretBytes`, `SecretChars`, `byte[]`, `char[]`, and any class annotated
  `@Sensitive` (which is `@Inherited`). Event codes must match
  `[A-Z][A-Z0-9_]{0,63}`. The Semgrep rule `cert.FIO13-J.log-secret` backs it
  statically.
- JVM launch flags in release: `-XX:-HeapDumpOnOutOfMemoryError`,
  `-XX:+DisableAttachMechanism`, no JMX, no JDWP (ENV05-J, ENV06-J).
- Documented limitation: the JVM may copy arrays during GC; zeroing is
  best-effort (R-003).

## Known limitations
Some deterministic copies of key material live inside library objects that
project code cannot reach, so `SecretBytes.close()` cannot zero them:

- **JCA `SecretKeySpec`.** Every `Cipher.init` needs a `SecretKeySpec`, which
  clones the key bytes. `SecretKeySpec.clear()` is not public API in JDK 21,
  and `destroy()` is not implemented, so the clone stays until the object is
  collected.
- **AES key schedules inside `Cipher`.** The provider expands the key into
  round-key arrays held by the `Cipher`'s internal state (AES-GCM and
  AES-KWP). There is no API to wipe them.
- **Bouncy Castle `HKDFParameters`.** The constructor clones the IKM; the clone
  is reachable only through the parameters object and cannot be zeroed.
- **`MessageDigest` internal buffer.** The digest keeps the last partial input
  block in its buffer after `digest()`. `RecoveryKey` mitigates this by
  digesting a block of zeros after the secret input, which overwrites the
  buffer. Other digest users have no such step.

Measured: a heap dump taken after every project buffer was closed still held
2 to 4 full copies of a canary key for each of the AEAD, KWP and HKDF paths.

Residual risk is the same as R-003 (Likely / Medium): an attacker who can read
process memory or a heap dump, swap file or core dump can recover keys while
the library objects are still on the heap. These copies are accepted for M1.
The JVM-level mitigation (no swap, for example by locking memory, and no core
dumps) is deferred to a later milestone; until then the release launch flags
above (no heap dump on OOM, no attach, no JMX, no JDWP) are the only control.

## Alternatives considered
- `javax.security.auth.Destroyable` alone: no ownership semantics, no
  scoping API.
- Off-heap `ByteBuffer`: avoids GC copies but complicates every JCA call which
  wants `byte[]`; not worth it for v1. Revisit if R-003 is ever upgraded.

## CERT rules referenced
OBJ05-J, OBJ07-J, OBJ13-J, OBJ14-J, FIO05-J, FIO13-J, SER03-J, STR03-J, MET12-J,
ENV05-J, ENV06-J.
