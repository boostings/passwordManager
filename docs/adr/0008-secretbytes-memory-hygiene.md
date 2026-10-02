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
- `equals` and `hashCode` never throw, even after `close()` (amended
  2026-10-02 after review): a closed secret equals only itself, and `hashCode`
  stays the constant. So a closed secret left in a collection cannot make
  `remove`/`contains` throw.
- Project logger (`SafeLog`) is allowlist-only (amended 2026-10-02 after
  review). It accepts exactly: `null`, `String`, `Boolean`, `Character`,
  `UUID`, `Duration`, any `Enum` (logged by `name()`, never `toString()`),
  `Integer`, `Long`, `Short`, `Byte`, `Float`, `Double`, and `java.base`
  implementations of `TemporalAccessor` and `Path`. Everything else throws
  `IllegalArgumentException`: `SECRET_ARG` for `SecretBytes`, `SecretChars`,
  `byte[]`, `char[]` and `@Sensitive` types, and `UNLOGGABLE_ARG` for any other
  type, **including `Throwable`** (a stack trace or message can carry a path or
  a secret; log the exception's code enum instead). The event code must match
  `[A-Z][A-Z0-9_]{0,63}`, else `BAD_EVENT_CODE`, so free text such as
  `log.info("vault unlocked")` is refused. The Semgrep rule
  `cert.FIO13-J.log-secret` backs it statically.
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

## Residual risks in the API (amended 2026-10-02 after review)
Two gaps remain by design. Code review must catch them; no gate does today.

1. **`SafeLog` still accepts `String` and `Path`.** Either can carry a secret: a
   passphrase already turned into a `String`, a recovery key put into a file
   name, a TOTP seed inside a URL. `SafeLog` cannot tell such a value from a
   harmless one. Keeping secrets out of `String` is MSC03-J's job
   (`cert.MSC03-J.secret-in-string` and `@SecretBoundary`), and FIO13-J's
   Semgrep rule flags secret-named arguments. Neither sees a secret held in a
   variable with an innocent name. Residual: Possible / Medium.
2. **`SecretBytes.apply` and `withBytes` trust the caller.** The callback gets
   the live internal buffer. The `SECRET_ESCAPE` guard only catches a callback
   that returns that exact array (an identity check). It does **not** catch:
   - a wrapper around the buffer: `ByteBuffer.wrap(b)`, `List.of(b)`, a record
     or lambda holding `b`;
   - stashing `b` in a field, a collection, or a captured variable, including
     from `withBytes`, which returns nothing and so has no guard at all;
   - returning a **copy** (`b.clone()`, `Arrays.copyOf`, `new String(b, ...)`,
     a hex string). The copy is a plain array or object that `close()` never
     zeroes, so it stays on the heap until collected.

   A wrapper or a stashed reference sees zeros after `close()`, but until then
   it is a second live handle on the secret. Reviewers check every `apply` and
   `withBytes` callback: the callback hands `b` only to a JCA/BC call that
   consumes it, and returns a result that is not the secret, or wraps it at once
   in `SecretBytes.takeOwnership`. Residual: Possible / Medium (same class as
   R-003).

## Alternatives considered
- `javax.security.auth.Destroyable` alone: no ownership semantics, no
  scoping API.
- Off-heap `ByteBuffer`: avoids GC copies but complicates every JCA call which
  wants `byte[]`; not worth it for v1. Revisit if R-003 is ever upgraded.

## CERT rules referenced
OBJ05-J, OBJ07-J, OBJ13-J, OBJ14-J, FIO05-J, FIO13-J, SER03-J, STR03-J, MET12-J,
ENV05-J, ENV06-J.
