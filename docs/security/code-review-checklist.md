# Code Review Checklist (by CERT family)

Reviewers tick the families touched and note any Review-only rule attestation.
Enforced rules are checked by CI; this list covers what tooling cannot see.

- **IDS** — Inputs normalized before validation? Validation on the final form? No user text in format strings, regexes, or exec args? Nothing sensitive crossing a boundary (IDS15-J)?
- **DCL / EXP** — No class-init cycles; no reused JDK identifiers; return values used; no null where an object is required.
- **NUM** — Overflow checked with `Math.*Exact`; no float for exact values; narrowing casts justified.
- **STR** — Charset explicit; no partial-character slicing; no binary data in `String` (STR03-J).
- **OBJ** — Fields private; mutable inputs/outputs defensively copied; sensitive classes uncopyable; no `this` escape; no use after close.
- **MET** — Arguments validated (not with `assert`); security-check methods `private`/`final`; constructors call no overridable methods; `equals`/`hashCode`/`compareTo` contracts; no finalizers.
- **ERR** — No swallowed checked exceptions; exception messages from the code catalogue only (ERR01-J); state restored on failure; no throw/return in `finally`; no catching NPE/Throwable; no `System.exit`.
- **VNA / LCK / THI / TPS / TSM** — Shared state visibility (`volatile`/lock); compound ops atomic; private final lock objects; consistent lock order; no blocking under lock; `wait` in loop; `notifyAll`; tasks interruptible; no partial publication; thread pools bounded.
- **FIO** — No shared/temp directories; permissions set before write; errors from file ops handled; resources in try-with-resources; paths canonicalized before checks; nothing sensitive logged.
- **SER** — No native serialization; CBOR codec has bounds and copies bytes; schema_version present.
- **SEC / ENV** — No reflection accessibility changes; env/config treated as untrusted; no debug/JMX entry points.
- **MSC** — `SecureRandom` via pm-crypto only; no hard-coded secrets; parsers bounded (heap); no iteration-time mutation; singletons thread-safe.
- **Project rules** — `SecretBytes` everywhere; `@SecretBoundary` documented; only pm-crypto/pm-storage touch JCA/filesystem; broker is the sole release path; new inputs have fuzz harnesses in this PR.

Any violation found is a **blocking** change request.
