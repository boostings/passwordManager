# M1 Team Sprint — Local Vault Foundation in 120 Minutes

Execution plan for `plan.md` §13 **M1: Local vault foundation**, split across five
people so each owns non-overlapping files and lands a similar number of commits.

Every line of Java must pass `RULES.md` (SEI CERT Java) via the gate below. A red
gate means the commit does not merge. No exceptions during the sprint.

---

## 0. Read this first (everyone, 3 minutes)

### Lanes

| Lane | Person | Owns (files nobody else touches) | Tier |
| --- | --- | --- | --- |
| **A — Crypto** | _name_ | `modules/pm-crypto/**` | 1 |
| **B — Storage** | _name_ | `modules/pm-storage/**`, `CODEOWNERS` | 1 |
| **C — Vault core** | _name_ | `modules/pm-vault/src/**/pm/vault/*.java` (top-level package), `pm/vault/envelope/**`, `pm/vault/slot/**`, `modules/pm-vault/build.gradle.kts`, `modules/pm-vault/src/main/java/module-info.java`, `docs/schemas/vault-header.cddl` | 1 |
| **D — Records & parsing** | _name_ | `pm/vault/cbor/**`, `pm/vault/record/**` (main + test), `modules/pm-fuzz/**`, `docs/schemas/records.cddl`, `docs/adr/0006-*` | 1 |
| **E — CLI/TUI & integration** | _name_ | `modules/pm-cli/**`, `modules/pm-tui/**`, `gradle/verification-metadata.xml`, external-dependency lines in any `build.gradle.kts` (Phase 0 only) | 3 |

Shared files that only get one edit, in Phase 0, by one person: `gradle/verification-metadata.xml` (E).
`docs/security/milestone-signoff.md` is split into five subsections in Phase 4; each person edits only theirs.

### Rules for the sprint

1. **Branch per PR:** `m1/<lane>/<topic>`, for example `m1/a/secretbytes`. Never commit to `main`.
2. **Small commits.** Each commit compiles and passes the gate. Commit messages use the format `M1.<phase> <lane>: <imperative summary>`, for example `M1.2 A: implement AES-256-GCM seal/open`.
3. **Merging:** rebase-merge or merge commit. **Never squash.** Squashing deletes everyone's individual commits.
4. **Reviews:** 5-minute turnaround. Tier 1 PRs need 2 approvals, Tier 3 PRs need 1.

   | Author | Reviewer 1 | Reviewer 2 (Tier 1) |
   | --- | --- | --- |
   | A | B | C |
   | B | C | D |
   | C | D | E |
   | D | E | A |
   | E | A | — |

   Reviewers walk `docs/security/code-review-checklist.md`. Any CERT violation is a blocking change request.
5. **The gate.** Run it before every push, and paste the last 15 lines into the PR:
   ```sh
   ./gradlew check certReport && gitleaks git --redact --no-banner --config tools/cert-rules/gitleaks.toml .
   ```
   While iterating, run just your module, for example `./gradlew :modules:pm-crypto:check`. Run the full gate before you push.
6. **If you're blocked on someone else's stub,** code against the contract in §2 and use a test double. Don't wait.
7. **Ask in chat before touching another lane's files.** If a contract in §2 has to change, the owner makes the change in a tiny PR, and everyone rebases.

---

## Pre-flight: before the clock starts (user-only blockers)

These items can't be handed off to anyone else. Each person checks them before minute 0.

| # | Item | Who | Check command | Status at write-up |
| --- | --- | --- | --- | --- |
| P1 | JDK 21 installed **and visible to Gradle** | all | `./gradlew -q javaToolchains` lists a 21 | **Problem found:** on the author's Mac, `java_home` only sees JDK 17, so the gate fails with "Cannot find a Java installation … languageVersion=21". **Fix:** add `org.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21` to `~/.gradle/gradle.properties` (use your own JDK 21 path). With that path set, the gate is green on `4b7860a`. |
| P2 | `semgrep` and `gitleaks` on PATH | all | `semgrep --version && gitleaks version` | PASS on the author's machine |
| P3 | `git config user.email` matches your GitHub account email | all | `git config user.email` | UNKNOWN for each person. If it doesn't match, your commits won't be credited to you. |
| P4 | Write access to `boostings/passwordManager` | all | `gh repo view boostings/passwordManager --json viewerPermission` | UNKNOWN for 4 of 5 |
| P5 | **Disable squash merging** | repo admin | `gh repo edit boostings/passwordManager --enable-squash-merge=false` | **FAIL:** squash merging is currently enabled |
| P6 | Branch protection on `main`: require PR, require `gate (*)` checks, require 1 review | repo admin | GitHub Settings → Branches | UNKNOWN |
| P7 | Full gate green locally on fresh `main` | all | gate command above | must PASS before minute 0 |

---

## 1. Timeline

| Clock | Phase | Goal | Merge deadline |
| --- | --- | --- | --- |
| 0:00–0:10 | **Phase 0: Setup** | Dependencies added, ADRs ratified, CODEOWNERS real, schemas drafted | 0:12 |
| 0:10–0:25 | **Phase 1: Contracts** | Every public API in §2 exists as a compiling stub | A by 0:16, everyone else by 0:25 |
| 0:25–1:10 | **Phase 2: Implementation** | Each lane fully implemented, with unit and property tests | Rolling, 2–3 PRs per person |
| 1:10–1:35 | **Phase 3: Integration and exit criteria** | `pm init/add/list/tui` works end to end. M1 security exit tests written. | 1:35 |
| 1:35–2:00 | **Phase 4: Hardening and sign-off** | CI green on 3 OSes, sign-off doc, tag `m1` | 2:00 |

Target is about 7 commits per person: Phase 0: 1, Phase 1: 1, Phase 2: 3, Phase 3: 1–2, Phase 4: 1.

---

## 2. Frozen contracts

Every person copies their own section as a compiling stub in Phase 1. Method bodies are
`throw new UnsupportedOperationException("M1 stub");`.
Javadoc is required on every public type, and each one cites the ADR or SR it implements.

### Module graph (JPMS `requires`)

```
pm.crypto   requires org.bouncycastle.provider;           exports pm.crypto, pm.crypto.log
pm.storage  (no project deps)                             exports pm.storage
pm.vault    requires transitive pm.crypto; requires transitive pm.storage;
            exports pm.vault, pm.vault.record             (cbor, envelope, slot: NOT exported)
pm.tui      requires transitive pm.vault; requires transitive com.googlecode.lanterna;   exports pm.tui
pm.cli      requires pm.tui;                              (exports nothing)
```

Module-graph notes (amended 2026-10-02 after review):
- `pm.tui` declares `requires transitive com.googlecode.lanterna`, not a plain `requires`. `TuiApp.run(Terminal)` is public API that takes a Lanterna type, and `javac -Xlint:exports` under `-Werror` fails the build unless the module passes Lanterna on to its readers. So `pm.cli` reads Lanterna through `pm.tui` and needs no `requires` of its own. Lane E has done this in code.
- `pm.crypto` needs no `java.management`. `Kdf` reads the max and used heap from `Runtime` for the Argon2id heap budget; the ArchUnit process rule bans only `Runtime.exec`, `ProcessBuilder` and `ProcessHandle` outside pm-approval (amended 2026-10-02 after review).

Gradle wiring: in `pm-vault`, `api(project(":modules:pm-crypto"))` and `api(project(":modules:pm-storage"))`. In `pm-tui`, `api(project(":modules:pm-vault"))`. In `pm-cli`, `implementation(project(":modules:pm-tui"))`. In `pm-fuzz`, `testImplementation(project(":modules:pm-vault"))`. Each owner adds their own module's project dependencies in Phase 1.

### A: `pm.crypto` (module pm-crypto)

Contract amendments (amended 2026-10-02 after review), each marked inline below: Argon2id heap budget and `tune` cap (ADR 0007), `SafeLog` allowlist-only, `Aead.sealWithFreshKey` consumes its key, `Argon2Params.checked`, `hkdfSha256` IKM ≥ 32 bytes, new `ConstantTime.equals`, `SecretBytes.equals`/`hashCode` safe after close. pm-crypto's `check` also enforces 100% **branch** coverage (§8).

```java
package pm.crypto;

/** ADR 0008. Final, not Serializable, not Cloneable. */
public final class SecretBytes implements AutoCloseable {
    public static SecretBytes copyOf(byte[] src);            // defensive copy
    public static SecretBytes takeOwnership(byte[] src);     // copies, then zeroes src
    public int length();
    public void withBytes(java.util.function.Consumer<byte[]> use);           // scoped access only
    public <R> R apply(java.util.function.Function<byte[], R> fn);            // fn must not retain the array
        // (amended 2026-10-02 after review) returning the buffer itself throws SECRET_ESCAPE. Wrappers,
        // stashing and returned copies are NOT caught (ADR 0008 residual risk 2): review every callback.
    public boolean isClosed();
    @Override public void close();                           // zero-fill, mark closed; idempotent
    @Override public boolean equals(Object o);               // MessageDigest.isEqual
        // (amended 2026-10-02 after review) never throws after close; a closed secret equals only itself
    @Override public int hashCode();                         // constant 0x5EC2E7; never throws after close
    @Override public String toString();                      // "SecretBytes[redacted]"
    @Override protected Object clone() throws CloneNotSupportedException;  // always throws
}

/** char[] twin for passphrase entry. */
public final class SecretChars implements AutoCloseable {
    public static SecretChars takeOwnership(char[] src);     // copies, zeroes src
    public int length();
    public SecretBytes toUtf8();                             // explicit UTF-8 via CharsetEncoder, zeroes intermediates
    public void withChars(java.util.function.Consumer<char[]> use);
    @Override public void close();
    @Override public String toString();                      // "SecretChars[redacted]"
}

/** Only SecureRandom in the codebase (SR-017, MSC02-J). */
public final class Csprng {
    public static byte[] bytes(int n);                       // n in 1..1024
    public static SecretBytes secretBytes(int n);
    public static java.util.UUID uuid();                     // v4 from SecureRandom
}

/** ADR 0007. */
public record Argon2Params(int memoryKiB, int iterations, int parallelism) {
    public static final Argon2Params FLOOR = new Argon2Params(65_536, 3, 1);
    public Argon2Params { /* reject below FLOOR, memoryKiB > 1_048_576, iterations > 10 */ }
    // (amended 2026-10-02 after review) for values read from a vault header (untrusted input):
    // out of range => CryptoException(BAD_PARAMS) instead of IllegalArgumentException
    public static Argon2Params checked(int m, int t, int p) throws CryptoException;
}

public final class Kdf {
    public static SecretBytes argon2id(SecretBytes password, byte[] salt32, Argon2Params p) throws CryptoException;
        // (amended 2026-10-02 after review) BAD_PARAMS, before allocating, when
        // memoryKiB*1024*1.1 > max heap - used heap (1 GiB cap if the JVM reports no max). ADR 0007.
    public static Argon2Params tune(java.time.Duration target);          // m first (cap 1 GiB), then t (cap 10)
        // (amended 2026-10-02 after review) m is also capped at half the max heap
    public static SecretBytes hkdfSha256(SecretBytes ikm, byte[] salt, byte[] info, int outLen) throws CryptoException;
        // (amended 2026-10-02 after review) IKM shorter than 32 bytes => BAD_INPUT
}

/** RFC 5649 via JDK "AES/KWP/NoPadding". Wrong KEK => CryptoException(AUTH_FAILED). */
public final class KeyWrap {
    public static byte[] wrap(SecretBytes kek, SecretBytes key) throws CryptoException;
    public static SecretBytes unwrap(SecretBytes kek, byte[] wrapped) throws CryptoException;
}

/** ADR 0005. Zero nonce is safe ONLY because every key is a fresh per-save HKDF output. */
public final class Aead {
    public static byte[] sealWithFreshKey(SecretBytes freshKey, SecretBytes plaintext, byte[] aad) throws CryptoException;
        // (amended 2026-10-02 after review) CONSUMES (closes) freshKey, also on throw; sealing again
        // with it throws SECRET_CLOSED. That only stops an in-process double seal with the same object.
        // The zero-nonce guarantee rests on C: a fresh Csprng dataSalt and a new DK on EVERY save (ADR 0005).
    public static SecretBytes openWithFreshKey(SecretBytes key, byte[] ciphertextAndTag, byte[] aad) throws CryptoException;
        // does NOT consume key; the caller still closes it
}

/** (amended 2026-10-02 after review) SR-016 constant-time compare for modules outside pm.crypto.
 *  ArchUnit bans java.security there, so they cannot call MessageDigest.isEqual themselves. */
public final class ConstantTime {
    public static boolean equals(byte[] a, byte[] b);        // delegates to MessageDigest.isEqual
}

/** ADR 0004: 32 random bytes + 3-byte SHA-256 checksum = 35 B = 56 base32 chars = 8 groups of 7. */
public final class RecoveryKey {
    public static SecretBytes generate();
    public static SecretChars format(SecretBytes key);       // "ABCDEFG-HIJKLMN-...": 8 groups
    public static SecretBytes parse(SecretChars typed) throws CryptoException;   // case/space/dash tolerant; checksum → BAD_INPUT
}

public final class CryptoException extends Exception {
    public enum Code { AUTH_FAILED, BAD_INPUT, BAD_PARAMS, INTERNAL }
    public CryptoException(Code code);                       // message = code.name() only (SR-501)
    public Code code();
}

/** Marks the few methods allowed to hold a secret in String (Semgrep MSC03-J allowlist). */
@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.CLASS)
@java.lang.annotation.Target(java.lang.annotation.ElementType.METHOD)
public @interface SecretBoundary { String reason(); }

/** Types that SafeLog refuses. */
@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
@java.lang.annotation.Target(java.lang.annotation.ElementType.TYPE)
public @interface Sensitive {}
```

```java
package pm.crypto.log;

/** SR-500. Wraps System.Logger. (amended 2026-10-02 after review) ALLOWLIST-ONLY:
 *  - eventCode must match [A-Z][A-Z0-9_]{0,63}, else IllegalArgumentException("BAD_EVENT_CODE").
 *    So log.info("vault unlocked") is refused; write log.info("VAULT_UNLOCKED").
 *  - Allowed args: null, String, Boolean, Character, UUID, Duration, Enum (logged by name()),
 *    Integer, Long, Short, Byte, Float, Double, and java.base TemporalAccessor and Path.
 *  - SecretBytes, SecretChars, byte[], char[] and @Sensitive types => IllegalArgumentException("SECRET_ARG").
 *  - Anything else, INCLUDING a Throwable, => IllegalArgumentException("UNLOGGABLE_ARG"). Log the
 *    exception's code enum instead (log.warn("UNLOCK_FAILED", e.code())).
 *  String and Path can still carry a secret: keeping secrets out of them is MSC03-J's job
 *  (ADR 0008, residual risk 1). */
public final class SafeLog {
    public static SafeLog of(Class<?> owner);
    public void info(String eventCode, Object... args);
    public void warn(String eventCode, Object... args);
    public void error(String eventCode, Object... args);
}
```

### B: `pm.storage` (module pm-storage) (Naren)

```java
package pm.storage;

/** ADR 0003 write rules, SR-041. One instance per vault path. */
public final class VaultFileStore implements AutoCloseable {
    public static final long MAX_FILE_BYTES = 256L * 1024 * 1024;
    public static VaultFileStore open(java.nio.file.Path vaultFile) throws StorageException;
        // canonicalize parent via toRealPath(); refuse if vaultFile is a symlink (NOFOLLOW_LINKS);
        // create parent dir owner-only if missing; acquire exclusive FileChannel.tryLock on "<name>.lock"
    public boolean exists();
    public byte[] readAll() throws StorageException;          // refuses > MAX_FILE_BYTES; NOFOLLOW_LINKS
    public void writeAtomically(byte[] data) throws StorageException;
        // 1 write "<name>.tmp" (CREATE_NEW, owner-only; delete stale regular-file tmp first)
        // 2 channel.force(true)  3 Files.move(ATOMIC_MOVE, REPLACE_EXISTING)
        // 4 fsync parent dir (POSIX only; skip on Windows)
    public void backup() throws StorageException;             // copy to "<name>.bak.1", rotate .bak.1..3
    @Override public void close();                            // releases lock
}

public final class OwnerOnly {
    public static void apply(java.nio.file.Path p) throws StorageException;   // POSIX rw------- / rwx------ for dirs; Windows ACL: owner only
    public static boolean isOwnerOnly(java.nio.file.Path p) throws StorageException;
}

public final class StorageException extends Exception {
    public enum Code { NOT_FOUND, TOO_LARGE, SYMLINK_REFUSED, LOCKED_BY_OTHER, PERMISSIONS, IO }
    public StorageException(Code code, Throwable cause);      // message = code only; never a path (SR-501)
    public Code code();
}
```

### C: `pm.vault` (top-level, envelope, slot; module pm-vault)

```java
package pm.vault;

public final class VaultService {
    public VaultService(pm.storage.VaultFileStore store, java.time.Clock clock, pm.crypto.Argon2Params kdf);
        // production passes Kdf.tune(500 ms); tests pass Argon2Params.FLOOR
    public CreatedVault create(pm.crypto.SecretChars passphrase) throws VaultException;  // refuses if file exists
    public Vault unlockWithPassphrase(pm.crypto.SecretChars passphrase) throws VaultException;
    public Vault unlockWithRecoveryKey(pm.crypto.SecretChars recoveryKey) throws VaultException;
}

/** Shown once, then closed by the caller. */
public record CreatedVault(Vault vault, pm.crypto.SecretChars recoveryKey) {}

/** Unlocked vault. close() == lock: zero VK and close every record's secrets. */
public final class Vault implements AutoCloseable {
    public java.util.List<pm.vault.record.VaultRecord> records();              // unmodifiable snapshot
    public java.util.List<pm.vault.record.VaultRecord> search(String query);   // delegates to RecordSearch
    public void put(pm.vault.record.VaultRecord r);                            // insert or replace by id
    public boolean remove(java.util.UUID id);
    public void save() throws VaultException;                                  // backup() then writeAtomically
    public boolean isLocked();
    @Override public void close();
}

public final class VaultException extends Exception {
    public enum Code { WRONG_CREDENTIAL, CORRUPT, UNSUPPORTED_VERSION, ALREADY_EXISTS, LOCKED, STORAGE }
    public VaultException(Code code, Throwable cause);
    public Code code();
}
```

```java
package pm.vault.envelope;   // NOT exported

public record KdfHeader(String alg, int m, int t, int p, byte[] salt) {}
public record SlotHeader(java.util.UUID id, String type /* "passphrase"|"recovery" */, byte[] wrappedKey) {}
public record EnvelopeHeader(KdfHeader kdf, java.util.List<SlotHeader> slots,
                             long created, long saved, long saveSeq) {}
public record ParsedEnvelope(EnvelopeHeader header, byte[] aad, byte[] dataSalt, byte[] ciphertext) {}

public final class EnvelopeCodec {
    public static final byte[] MAGIC = {'P','M','V','A','U','L','T',0};
    public static final int VERSION = 1, MAX_HEADER = 64 * 1024;
    public static byte[] encode(EnvelopeHeader h, byte[] dataSalt32, byte[] ciphertext);
    public static ParsedEnvelope decode(byte[] file) throws pm.vault.VaultException;   // CORRUPT / UNSUPPORTED_VERSION
    public static byte[] aadOf(byte[] headerCbor, byte[] dataSalt32);                  // magic‖version‖len‖header‖salt
}
```

```java
package pm.vault.slot;       // NOT exported
public final class SlotCrypto {
    // KEK = HKDF(input, salt=null, info="pm/slot/v1/" + slotUuid); passphrase input = Argon2id output
    public static pm.crypto.SecretBytes kekFromPassphrase(pm.crypto.SecretChars pw, pm.vault.envelope.KdfHeader k, java.util.UUID slot) throws pm.crypto.CryptoException;
    public static pm.crypto.SecretBytes kekFromRecovery(pm.crypto.SecretBytes rk, java.util.UUID slot) throws pm.crypto.CryptoException;
}
```

### D: `pm.vault.cbor` + `pm.vault.record` (module pm-vault)

```java
package pm.vault.cbor;       // NOT exported. Hand-rolled deterministic subset (see ADR 0006 amendment).

public sealed interface CborValue permits CborValue.UInt, CborValue.Bytes, CborValue.Text,
                                          CborValue.Array, CborValue.MapV, CborValue.Bool {
    record UInt(long value) implements CborValue {}           // value >= 0
    record Bytes(byte[] value) implements CborValue {}
    record Text(String value) implements CborValue {}
    record Array(java.util.List<CborValue> items) implements CborValue {}
    record MapV(java.util.Map<String, CborValue> entries) implements CborValue {}   // text keys only
    record Bool(boolean value) implements CborValue {}
}

public record CborLimits(int maxDepth, int maxItems, int maxStringBytes, int maxTotalBytes) {
    public static final CborLimits HEADER  = new CborLimits(16, 1_024, 4_096, 64 * 1024);
    public static final CborLimits PAYLOAD = new CborLimits(16, 1_000_000, 1 << 20, 256 * 1024 * 1024);
}

public final class CborWriter { public static byte[] encode(CborValue v); }   // RFC 8949 §4.2.1 deterministic
public final class CborReader { public static CborValue decode(byte[] in, CborLimits lim) throws CborException; }
    // rejects: indefinite length, tags, floats, negative ints, non-shortest ints, duplicate or
    // unsorted map keys, invalid UTF-8, trailing bytes, any limit exceeded
public final class CborException extends Exception { public enum Code { MALFORMED, LIMIT, NON_CANONICAL } ... }
```

```java
package pm.vault.record;     // exported

public sealed interface VaultRecord extends AutoCloseable
        permits LoginRecord, WifiRecord, SshKeyRecord, ProjectRecord {
    java.util.UUID id(); String title(); java.time.Instant created(); java.time.Instant updated();
    @Override void close();                                    // closes contained SecretBytes
}
public record LoginRecord(UUID id, String title, String username, SecretBytes password,
        List<String> urls, String notes, List<String> tags, Instant created, Instant updated,
        Instant lastUsed) implements VaultRecord {}
public record WifiRecord(UUID id, String title, String ssid, String security /* WPA2|WPA3|WEP|OPEN */,
        SecretBytes password, boolean hidden, String notes, Instant created, Instant updated) implements VaultRecord {}
public record SshKeyRecord(UUID id, String title, String keyType, SecretBytes privateKey, String publicKey,
        String fingerprint, String comment, List<String> hosts, Instant created, Instant updated) implements VaultRecord {}
public record ProjectRecord(UUID id, String title, String canonicalPath, String gitRemote,
        Map<String, SecretBytes> variables, Map<String, String> config, Instant created, Instant updated) implements VaultRecord {}
    // every compact constructor: requireNonNull, length bounds (title ≤ 256, notes ≤ 64 KiB, ≤ 64 urls/tags/hosts),
    // defensive List.copyOf / Map.copyOf (OBJ06-J)

public final class RecordCodec {
    public static final int SCHEMA_VERSION = 1;
    public static SecretBytes encodePayload(java.util.List<VaultRecord> records);            // {"schema_version":1,"records":[...]}
    public static java.util.List<VaultRecord> decodePayload(SecretBytes plaintext) throws RecordException;  // all-or-nothing
}
public final class RecordSearch {
    public static boolean matches(VaultRecord r, String query);   // case-insensitive (Locale.ROOT) on title, username, urls, tags, ssid, hosts. NEVER secrets.
}
public final class RecordException extends Exception { public enum Code { SCHEMA, LIMIT, MALFORMED } ... }
```

### E: `pm.tui` + `pm.cli`

```java
package pm.tui;
public final class TuiApp {
    public TuiApp(pm.vault.VaultService service, java.time.Duration idleLock);   // default 5 min (SR-504)
    public void run(com.googlecode.lanterna.terminal.Terminal terminal) throws java.io.IOException;
}
public final class IdleLock implements AutoCloseable {
    public IdleLock(java.time.Duration timeout, Runnable onLock, java.util.concurrent.ScheduledExecutorService ses);
    public void touch();            // called on every key event
    @Override public void close();
}
```

```java
package pm.cli;
public final class Main { public static void main(String[] args); }   // ONLY place System.exit is allowed
// commands: init | add-login | list | search <q> | tui      global option: --vault <path>
```

---

## 3. Phase 0: Setup (0:00–0:10)

Everyone first runs: `git switch main && git pull && git switch -c m1/<lane>/phase0`.

### A: Ratify crypto ADRs
- [ ] Set **Status: Accepted** in ADR 0005, 0007 and 0008. Add the line `Ratified 2026-10-02 by <team>`.
- [ ] Skim `RULES.md`: MSC (randomness), NUM (integer overflow in lengths), OBJ05/06/07/13/14 (defensive copies, clone, closed state), STR03 (no `new String(byte[])` for secrets).
- Commit: `M1.0 A: ratify ADRs 0005, 0007, 0008`

### B: Fill in real CODEOWNERS
- [ ] Replace every `@TEAM-*` placeholder with real GitHub handles. Mapping: SECURITY-OWNER = A, CRYPTO-REVIEWER = C, BACKEND-REVIEWER = B, NETWORK-REVIEWER = D. Add E to `modules/pm-tui/` and `modules/pm-cli/`.
- [ ] Skim `RULES.md` FIO family, especially FIO00/01/02/03/04/14/16.
- Commit: `M1.0 B: assign real CODEOWNERS handles`

### C: Vault header CDDL
- [ ] Create `docs/schemas/vault-header.cddl` by transcribing the ADR 0003 header map: `kdf`, `slots`, `created`, `saved`, `save_seq`, and **`schema_version: 1`**. ADR 0006 makes `schema_version` mandatory. Restrict slot `type` to `"passphrase" / "recovery"` for M1.
- [ ] Set ADR 0003 and 0004 to **Accepted**.
- Commit: `M1.0 C: add vault header CDDL, ratify ADRs 0003, 0004`

### D: Records CDDL + ADR 0006 amendment
- [ ] Create `docs/schemas/records.cddl` with one map per record type from §2. Use `bstr` for secret fields and `uint` epoch seconds for instants.
- [ ] Add an **Amendment 1** section to ADR 0006. It says: no CBOR library is used. The candidate `co.nstant.in:cbor:0.9` has had no release since 2020 and has no JPMS descriptor (verified). We hand-roll a deterministic subset (uint, bstr, tstr, array, map with tstr keys, bool) in `pm.vault.cbor`. This keeps the bounded, fuzzed parser entirely ours and adds no dependency to a Tier 1 module. Then set the ADR to Accepted.
- Commit: `M1.0 D: add records CDDL, amend ADR 0006 to in-house CBOR subset`

### E: External dependencies + verification metadata (the only shared-file edit)
- [ ] `modules/pm-crypto/build.gradle.kts`: `implementation("org.bouncycastle:bcprov-jdk18on:1.86")`. Its JPMS name is `org.bouncycastle.provider` (verified).
- [ ] `modules/pm-tui/build.gradle.kts`: `implementation("com.googlecode.lanterna:lanterna:3.1.3")`. Its JPMS name is `com.googlecode.lanterna` (verified). Don't use 3.2.0-alpha.
- [ ] Run `./gradlew --write-verification-metadata sha256 help`. Then **read the diff** to confirm only BC and Lanterna artifacts were added, and compare each sha256 to the `.sha256` published on Maven Central.
- [ ] Run the gate. Push. Ping A and B for review. **Merge by 0:12.** Everyone rebases on it.
- Commit: `M1.0 E: add Bouncy Castle and Lanterna with verified checksums`

---

## 4. Phase 1: Contracts (0:10–0:25)

Each person types their §2 section as stubs, adds `module-info` requires and exports, adds project dependencies to their own build file, and runs the gate.
**A must merge by 0:16** because every other module compiles against `pm.crypto`.
Until then, others build on `m1/a/contracts` locally: `git fetch && git rebase origin/m1/a/contracts`.

| Lane | Files created | Commit |
| --- | --- | --- |
| A | `pm/crypto/{SecretBytes,SecretChars,Csprng,Argon2Params,Kdf,KeyWrap,Aead,RecoveryKey,CryptoException,SecretBoundary,Sensitive}.java`, `pm/crypto/log/SafeLog.java`, module-info (`requires org.bouncycastle.provider; exports pm.crypto; exports pm.crypto.log;`) | `M1.1 A: pm-crypto public API stubs` |
| B | `pm/storage/{VaultFileStore,OwnerOnly,StorageException}.java`, module-info `exports pm.storage;` | `M1.1 B: pm-storage public API stubs` |
| C | `pm/vault/{VaultService,CreatedVault,Vault,VaultException}.java`, `pm/vault/envelope/*`, `pm/vault/slot/SlotCrypto.java`, module-info with all `requires`/`exports` for pm-vault, plus build.gradle.kts `api(...)` lines | `M1.1 C: pm-vault service, envelope, slot stubs` |
| D | `pm/vault/cbor/*`, `pm/vault/record/*` stubs. D does **not** touch module-info; C owns it and already exports `pm.vault.record`. | `M1.1 D: CBOR and record model stubs` |
| E | `pm/tui/{TuiApp,IdleLock}.java`, `pm/cli/Main.java`, both module-infos and build files | `M1.1 E: TUI and CLI stubs` |

**Phase 1 is done when** `main` builds with every stub and the gate is green. Mark it in §9.

---

## 5. Phase 2: Implementation (0:25–1:10)

Each lane opens 2–3 PRs here. Each bullet group below is one commit.

### A: Crypto (3 commits)

**Commit 2a: `M1.2 A: implement SecretBytes, SecretChars, Csprng`**
- `SecretBytes`: a `private final byte[] buf` and a `private boolean closed`. Every method calls `ensureOpen()` first, which throws `IllegalStateException`. `close()` runs `Arrays.fill(buf, (byte) 0)`. Mark the class `@Sensitive`.
- `SecretChars.toUtf8()`: use `StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(chars))`. Copy the `remaining()` bytes into a new array, then zero the ByteBuffer's backing array and the CharBuffer. Never call `new String(...)`.
- `Csprng`: one `private static final SecureRandom RNG = new SecureRandom();`. Bounds-check `n`.
- Tests (`modules/pm-crypto/src/test/java/pm/crypto/`):
  - `SecretBytesTest`: use-after-close throws for every method. `toString` contains no byte values. `hashCode` is constant. `clone` throws. `takeOwnership` zeroes the source.
  - `SecretCharsTest`: UTF-8 round trip for ASCII, "pässwörd" and an emoji. The source char[] is zeroed.
  - jqwik `@Property`: `copyOf(x).equals(copyOf(x))` holds, and `!copyOf(x).equals(copyOf(y))` when x ≠ y.

**Commit 2b: `M1.2 A: implement Argon2id, HKDF, AES-KWP, AES-GCM`**
- `Kdf.argon2id`: BC `Argon2BytesGenerator` with `Argon2Parameters.Builder(ARGON2_id).withVersion(ARGON2_VERSION_13).withSalt(salt).withMemoryAsKB(m).withIterations(t).withParallelism(p)`. Hand the password to BC inside `password.withBytes(...)`. Write output into a `byte[32]`, then `SecretBytes.takeOwnership`. Reject salt length ≠ 32.
- `Kdf.hkdfSha256`: BC `HKDFBytesGenerator(new SHA256Digest())` with `HKDFParameters`. Bound `outLen` to 1..255*32.
- `KeyWrap`: `Cipher.getInstance("AES/KWP/NoPadding")`, `init(ENCRYPT_MODE/DECRYPT_MODE, new SecretKeySpec(kekBytes, "AES"))`. Map `GeneralSecurityException` to `CryptoException(AUTH_FAILED)` on unwrap. Never put exception text or the cause message in the result.
- `Aead`: create a **new** `Cipher.getInstance("AES/GCM/NoPadding")` per call. Use `GCMParameterSpec(128, new byte[12])` and `updateAAD(aad)`. Map `AEADBadTagException` to `AUTH_FAILED`. Require a 32-byte key. (amended 2026-10-02 after review) `sealWithFreshKey` closes its key in a try-with-resources, so it is consumed even on throw; `openWithFreshKey` leaves its key open.
- Known-answer tests, written into test files as hex constants: RFC 9106 §5.3 Argon2id; RFC 5869 test cases 1–3 (HKDF-SHA256); RFC 5649 §6 (KWP, both vectors); one NIST GCM vector with a 96-bit zero IV, or a round trip plus tamper test if no zero-IV vector is handy.
- jqwik properties: `open(seal(k,p,aad)) == p`. Flipping any single bit of the ciphertext or AAD gives `AUTH_FAILED`. Unwrapping with the wrong KEK gives `AUTH_FAILED`.
- **Keep the suite fast.** Argon2 at FLOOR takes about 0.3–0.5 s, so cap `@Property(tries = 5)` on anything that calls `argon2id`.

**Commit 2c: `M1.2 A: implement RecoveryKey, Kdf.tune, SafeLog`**
- `RecoveryKey`: checksum = first 3 bytes of `SHA-256(key)`. Encode with RFC 4648 base32, no padding, hand-rolled over `char[]`. 35 bytes give exactly 56 chars, split into 8 groups of 7 joined by `-`. `parse` strips spaces and dashes, uppercases with `Character.toUpperCase` per char, decodes, and verifies the checksum with `MessageDigest.isEqual`.
- `Kdf.tune`: starting at FLOOR, double `m` until a single hash takes at least `target` or `m` hits 1 GiB, then raise `t`. Use `System.nanoTime`. Never return below FLOOR.
- `SafeLog` (amended 2026-10-02 after review: allowlist-only, replacing the original denylist): use `System.getLogger(owner.getName())`. Reject an event code that doesn't match `[A-Z][A-Z0-9_]{0,63}` with `IllegalArgumentException("BAD_EVENT_CODE")`. For each arg: `SecretBytes`, `SecretChars`, `byte[]`, `char[]` or an `@Sensitive` type throws `SECRET_ARG`. Then allow only `null`, `String`, `Boolean`, `Character`, `UUID`, `Duration`, `Enum` (logged by `name()`), `Integer`/`Long`/`Short`/`Byte`/`Float`/`Double`, and `java.base` `TemporalAccessor` and `Path`. Anything else, including any `Throwable`, throws `UNLOGGABLE_ARG`. Callers therefore can't write `log.info("vault unlocked")` (free text is not an event code) or pass an exception (pass its code enum).
- Tests: format/parse round trip (property). A single-char typo is rejected. `SafeLogTest` asserts it throws for each refused type (including a `Throwable`, a `BigInteger` and a non-`java.base` `Path`), for a bad event code such as `"vault unlocked"`, and that each allowed type logs.

### B: Storage (3 commits)

**Commit 2a: `M1.2 B: implement OwnerOnly and StorageException`**
- POSIX: if `FileSystems.getDefault().supportedFileAttributeViews().contains("posix")`, use `Files.setPosixFilePermissions` with `rw-------` for files and `rwx------` for dirs.
- Windows: use `AclFileAttributeView`. Owner = `Files.getOwner(p)`. Set exactly one ACL entry: ALLOW, owner, all permissions, no inheritance.
- `isOwnerOnly`: on POSIX, check the permission set has no group or other bits. On Windows, check every ACL entry's principal equals the owner.
- Test `OwnerOnlyTest` uses `@TempDir`, **not** `Files.createTempFile` (banned by Semgrep FIO03-J). It applies permissions, then asserts `isOwnerOnly` for both a file and a dir. **CI runs this on all three OSes; that is the M1 permission exit criterion.**

**Commit 2b: `M1.2 B: implement VaultFileStore read, lock, and atomic write`**
- `open`: `parent.toRealPath()`. If `Files.isSymbolicLink(vaultFile)`, throw `SYMLINK_REFUSED`. Create the parent with `Files.createDirectories` and then apply `OwnerOnly`. Open the lock with `FileChannel.open(lockPath, CREATE, WRITE)` and `tryLock()`; null means `LOCKED_BY_OTHER`.
- `readAll`: check `Files.size` first, then read through `Files.newInputStream(p, LinkOption.NOFOLLOW_LINKS)` with an explicit bounded loop. Over the limit gives `TOO_LARGE`.
- `writeAtomically`, implemented as steps so tests can crash at each one:
  ```java
  enum Step { TMP_CREATED, TMP_WRITTEN, TMP_SYNCED, RENAMED, DIR_SYNCED }
  /* package-private */ interface CrashHook { void at(Step s) throws IOException; }   // NOOP in prod
  ```
  1. If a stale `<name>.tmp` exists and is a regular non-symlink file, delete it.
  2. `FileChannel.open(tmp, CREATE_NEW, WRITE)`, then `OwnerOnly.apply`, write the full buffer in a loop, then `force(true)`.
  3. `Files.move(tmp, target, ATOMIC_MOVE, REPLACE_EXISTING)`. If that throws `AtomicMoveNotSupportedException`, fail with `IO`. **Never fall back to a non-atomic move.**
  4. On POSIX, run `FileChannel.open(parentDir, READ).force(true)` inside try/catch. Some filesystems refuse it; ignoring that is fine.
- Tests:
  - `AtomicWriteCrashTest`: this is the M1 exit criterion. Use JUnit `@ParameterizedTest` over every `Step`. Write version 1, set a hook that throws at the step, attempt version 2, then reopen. The file bytes must equal **exactly v1 or exactly v2**. They are never partial or missing, and no `.tmp` remains after the next successful write.
  - `SymlinkRefusedTest`: skip with `assumeTrue` on Windows if symlink creation fails.
  - `SizeLimitTest`: feed an oversized file to the read path through a package-private constructor that takes a smaller limit. Don't write 256 MiB.
  - `LockTest`: a second `open` on the same path gives `LOCKED_BY_OTHER`.
- Note in a PR comment: this test proves crash safety by throwing at each step. It does not kill a real process; that version lives in M7, because `ProcessBuilder` outside pm-approval is banned by Semgrep.

**Commit 2c: `M1.2 B: implement backup rotation`**
- `backup()`: if the vault exists, shift `.bak.2` to `.bak.3` and `.bak.1` to `.bak.2`, then copy the vault to `.bak.1` using the same atomic-write steps. Apply `OwnerOnly` to each backup.
- Test: after 5 saves, exactly `.bak.1..3` exist, each owner-only, and `.bak.1` equals the previous vault contents.

### C: Vault core (3 commits; start with fakes until A and D merge)

**Commit 2a: `M1.2 C: implement EnvelopeCodec`**
- Encoding layout (big-endian through `ByteBuffer`): `MAGIC(8) ‖ u16 VERSION ‖ u32 headerLen ‖ headerCbor ‖ dataSalt(32) ‖ ciphertext`.
- Header to CBOR: build a `CborValue.MapV` with keys `schema_version, kdf{alg,m,t,p,salt}, slots[{id,type,wrapped_key}], created, saved, save_seq`, then `CborWriter.encode`. Until D merges, stub this with a test fake that returns fixed bytes.
- `decode` checks, in this order, and fails at the first problem:
  1. `file.length >= 8+2+4+32+16`, else CORRUPT.
  2. Magic matches using `pm.crypto.ConstantTime.equals`. Else CORRUPT. (amended 2026-10-02 after review: not `MessageDigest.isEqual` directly, because ArchUnit bans `java.security` outside `pm.crypto`. The same goes for every other tag, checksum or key compare in C.)
  3. `version == 1`. If it's greater, UNSUPPORTED_VERSION; if it's less, CORRUPT.
  4. `0 < headerLen <= MAX_HEADER` and `14 + headerLen + 32 + 16 <= file.length`. Do the arithmetic with `Math.addExact`/`long` (NUM00-J).
  5. `CborReader.decode(header, CborLimits.HEADER)`, then validate fields: alg is "argon2id", salt is 32 bytes, at least 1 slot, slot types are known, wrapped_key is 40 bytes.
- `aadOf` covers bytes `[0, 14 + headerLen + 32)` exactly.
- Tests: an encode/decode round trip, plus one test per check above, each feeding a crafted file.

**Commit 2b: `M1.2 C: implement slot crypto and create/unlock`**
- `create(pw)`:
  1. VK = `Csprng.secretBytes(32)`. kdfSalt = `Csprng.bytes(32)`. Generate two slot UUIDs.
  2. KEK_p = `HKDF(argon2id(pw.toUtf8(), kdfSalt, params), null, "pm/slot/v1/"+uuid_p, 32)`. KEK_r = `HKDF(rk, null, "pm/slot/v1/"+uuid_r, 32)`, where `rk = RecoveryKey.generate()`.
  3. Each slot gets `wrapped_key = KeyWrap.wrap(KEK_x, VK)`.
  4. Save an empty record list with `save_seq = 1`. Return `CreatedVault(vault, RecoveryKey.format(rk))`.
  5. Close every intermediate `SecretBytes` in try-with-resources.
- `unlockWithPassphrase(pw)`:
  1. `decode`.
  2. **Always run Argon2id to completion**, even if the header looks odd later.
  3. Try `KeyWrap.unwrap` on the `passphrase` slot. AUTH_FAILED becomes `WRONG_CREDENTIAL`.
  4. `DK = HKDF(VK, dataSalt, "pm/data/v1", 32)`.
  5. `Aead.openWithFreshKey(DK, ciphertext, aad)`. Failure means CORRUPT.
  6. **Only after the tag verifies**, call `RecordCodec.decodePayload`.
- `save()`: new `dataSalt = Csprng.bytes(32)`, new DK, `saved = clock`, `save_seq + 1`. Encode the header first, compute AAD, then seal. Call `store.backup()`, then `store.writeAtomically`.
  - (amended 2026-10-02 after review) **The zero-nonce guarantee (ADR 0005) rests on this step.** Every save draws a FRESH 32-byte `dataSalt` from `Csprng` and derives a NEW DK from it. Never reuse the `dataSalt` read at unlock, and never keep the unlock-time DK on the `Vault` to seal with later: close it right after `openWithFreshKey`. `Aead.sealWithFreshKey` consumes its key, but that only stops a second seal with the same `SecretBytes` object in one process; it can't detect a DK derived again from a reused salt.
  - (amended 2026-10-02 after review) `pm.crypto` errors: `AUTH_FAILED` on the slot unwrap becomes `WRONG_CREDENTIAL`. `BAD_PARAMS` from `Argon2Params.checked` while decoding the header becomes `CORRUPT`. `BAD_PARAMS` from `Kdf.argon2id` means the heap can't hold 1.1 × m (ADR 0007): map it to a distinct `VaultException` code (for example `INSUFFICIENT_MEMORY`) with its own user-visible message (restart with a larger `-Xmx`), never `CORRUPT`.
- `Vault.close()`: zero VK and close every record. After that, any method throws `VaultException(LOCKED)` or `IllegalStateException`. Pick one and document it.
- Tests use `Argon2Params.FLOOR`:
  - create, then unlock with the passphrase, then unlock with the recovery key.
  - Wrong passphrase gives WRONG_CREDENTIAL.
  - Wrong recovery key: a typo gives BAD_INPUT from `parse`; a valid but different key gives WRONG_CREDENTIAL.
  - `save_seq` increases on each save.
  - (amended 2026-10-02 after review) **Required:** `VaultServiceTest.saveUsesFreshDataSaltEachTime`. Save the same records twice from one unlocked vault. Decode both files: the two `dataSalt` values differ, and the two ciphertexts differ.

**Commit 2c: `M1.2 C: implement Vault record ops and search`**
- `put`/`remove`/`records`/`search` work on a `LinkedHashMap<UUID, VaultRecord>`. `records()` returns `List.copyOf`. Search delegates to `RecordSearch.matches`.
- Test: put → save → close → unlock → the records are present and equal. For secret fields, compare with `SecretBytes.equals`.

### D: CBOR and records (3 commits)

**Commit 2a: `M1.2 D: implement deterministic CBOR writer and reader`**
- Writer: major types 0 (uint), 2 (bstr), 3 (tstr), 4 (array), 5 (map), and simple values 20/21 (false/true). Always use the shortest argument encoding. Map keys are sorted by **bytewise lexicographic order of their encoded form** (RFC 8949 §4.2.1). Text is encoded UTF-8 through `StandardCharsets.UTF_8`.
- Reader is a recursive descent with an explicit `depth` counter and a running `items` counter. Before allocating, check every length against `maxStringBytes`, the remaining input, and `Integer.MAX_VALUE`. Decode UTF-8 with a `CharsetDecoder` set to `CodingErrorAction.REPORT`. Track the previous key bytes to reject unsorted or duplicate keys. After the top-level item, `pos == in.length` must hold.
- Tests:
  - Hex vectors from RFC 8949 Appendix A, limited to the subset we support.
  - Each rejection case: indefinite length (0x5f), a tag (0xc0), a float (0xf9), negative int (0x20), non-shortest `0x18 0x05`, unsorted map, duplicate key, overlong length, trailing byte, depth 17.
  - jqwik: for an arbitrary `CborValue` tree, `decode(encode(v)) == v`.

**Commit 2b: `M1.2 D: implement record model and RecordCodec`**
- The four record types from §2. Compact constructors validate bounds and make defensive copies.
- `encodePayload`: `{"schema_version":1,"records":[{"type":"login", ...}, ...]}`. Secret fields go in as `CborValue.Bytes` copied out via `apply`. Wrap the encoded result with `SecretBytes.takeOwnership(bytes)`. Document in javadoc that the intermediate `byte[]` copies are best-effort zeroed (R-003).
- `decodePayload`: `CborReader.decode(..., PAYLOAD)`. Check `schema_version == 1` and ignore unknown keys. Build the full list in a local `ArrayList`; on **any** error, close every record built so far and throw. **Never return a partial list.** This is the M1 exit criterion "corrupted input never yields a partial record".
- `RecordSearch`: lowercase with `toLowerCase(Locale.ROOT)` and use `contains`. An empty query matches all.
- Tests:
  - jqwik `Arbitrary<VaultRecord>` for all four types, checking `decode(encode(list))` equals the list.
  - Truncating the payload at every offset either throws `RecordException`/`CborException` or yields the full list. It never yields a shorter list.
  - Search never matches on password contents. For example, a record with password "hunter2" is not found by the query "hunter".

**Commit 2c: `M1.2 D: add Jazzer fuzz harnesses for CBOR and records`**
- `modules/pm-fuzz/src/test/java/pm/fuzz/CborReaderFuzzTest.java`:
  ```java
  @FuzzTest void fuzz(byte[] in) { try { CborReader.decode(in, CborLimits.HEADER); } catch (CborException expected) { } }
  ```
- `RecordCodecFuzzTest`: same pattern on `RecordCodec.decodePayload(SecretBytes.copyOf(in))`.
- Seed corpus: `src/test/resources/pm/fuzz/CborReaderFuzzTestInputs/` with five valid encodings produced by the writer.
- CI runs the regression seeds only. Locally, run `JAZZER_FUZZ=1 ./gradlew :modules:pm-fuzz:test --tests '*CborReaderFuzzTest'` for 5 minutes and fix any crashes. Note the run time and the result in the PR.

### E: CLI and TUI (3 commits)

**Commit 2a: `M1.2 E: implement CLI init, add-login, list, search`**
- `Main.main`: parse args by hand with a `switch`. No reflection-based CLI library. Default vault path, chosen with `System.getProperty("os.name")`:
  - macOS: `~/Library/Application Support/pm/vault.pmv`
  - Linux: `~/.local/share/pm/vault.pmv`
  - Windows: `~\AppData\Roaming\pm\vault.pmv`

  Build these from `System.getProperty("user.home")`. **Don't use `getenv`**; Semgrep ENV02 only allows it in the pm-domain accessor.
- Read the passphrase only through `System.console().readPassword()`, then pass it to `SecretChars.takeOwnership`. If `System.console()` is null, exit with code 2 and the message "interactive terminal required".
- `init` asks for the passphrase twice. Compare the two inside `withChars` using `MessageDigest.isEqual` over `toUtf8()` bytes. Then print the recovery key **once**, through `withChars` straight to `console.writer()`, and close it. This is the one `@SecretBoundary(reason="display recovery key once")` method.
- `list` prints `id  type  title  updated`. It never prints a secret field.
- Exit codes: 0 ok, 1 wrong credential, 2 usage, 3 corrupt or unsupported, 4 storage. Map these from the `Code` enums. Messages come from a fixed `Messages` catalogue (SR-501).
- `System.exit` appears only in `Main`.
- Tests: `MainArgsTest` covers argument parsing and exit-code mapping without a console. Factor `run(String[] args, ConsoleIo io)` behind a small interface so tests can inject passphrases as `char[]`.

**Commit 2b: `M1.2 E: implement TUI unlock and dashboard with search`**
- Lanterna `MultiWindowTextGUI` over a `Screen`.
- `UnlockWindow`: a `TextBox` with mask `'*'`. Read its value into a `char[]` and clear the box right after. **Avoid `getText()` returning a String where possible.** If you can't avoid it, isolate the call in one `@SecretBoundary` method and explain why in the PR.
- `DashboardWindow`: a `Table<String>` with columns Type | Title | Username/SSID | Updated. A search `TextBox` with a text-change listener filters through `vault.search(q)`. Status bar text: "Locked in m:ss".
- `RecordDetailWindow`: secrets are shown as `••••••••`. Reveal and copy are out of scope for M1 and listed for M4/SR-503.
- `AddLoginDialog`: fields title, username, password (masked), urls (comma-separated), tags. On OK, `vault.put(...)` then `vault.save()`.
- Tests: `DashboardTest` drives the UI with `DefaultVirtualTerminal` (headless), feeds key strokes, and asserts the table contents after a search.

**Commit 2c: `M1.2 E: implement idle auto-lock`**
- `IdleLock`: a single-thread `ScheduledExecutorService` with a named daemon `ThreadFactory`. `touch()` cancels the pending future and schedules a new one. `onLock` posts to Lanterna through `gui.getGUIThread().invokeLater(...)`, which closes the vault and returns to `UnlockWindow`. Guard shared state with a `private final ReentrantLock` (PMD bans `synchronized`). Error Prone `GuardedBy` is on.
- Tests: inject a manual `ScheduledExecutorService` or a deterministic fake. `touch` at t=4 min means no lock at 5 min; a lock fires at 9 min. After the lock, `vault.isLocked()` is true.

---

## 6. Phase 3: Integration and M1 exit criteria (1:10–1:35)

| Lane | Task | Commit |
| --- | --- | --- |
| **E** | `pm-cli` integration test `EndToEndTest` with `@TempDir` vault path and the console fake: init with the canary passphrase `System.getProperty("pm.canary.secret")` → add-login → list → reopen and unlock → list. Then a wrong passphrase gives exit code 1. The CI canary grep proves the passphrase never reached any output (SR-500). Run `./gradlew run` or the installed distribution by hand once and paste a terminal transcript into the PR. | `M1.3 E: end-to-end CLI test with canary passphrase` |
| **C** | `TamperTest`, an M1 exit criterion. (1) Build a vault with 3 records. Bypass Argon2 by opening at the VK layer through a package-private `VaultService.openWithVaultKey(bytes, vk)`. For **every byte index**, flip it: the open must fail with CORRUPT/UNSUPPORTED_VERSION, and a counting hook on `RecordCodec` must show **0 decode calls**. (2) Run 10 sampled flips through full passphrase unlock. This split keeps the suite under 30 s; a full unlock per byte at the Argon2 floor would take minutes. | `M1.3 C: byte-flip tamper test proving detection before parse` |
| **A** | `ConstantTimeReviewTest`, an M1 exit criterion. A source-level check: grep `modules/*/src/main` and assert no `Arrays.equals` is called on SecretBytes, keys or tags. The Semgrep rule `cert.CT-compare` is already enforced; this test documents it. Also confirm the wrong-passphrase path runs Argon2 to completion: a test with a counting `Kdf` seam asserts exactly one argon2 call on a wrong passphrase. Then review C's unlock code for early returns before KDF completion. | `M1.3 A: constant-time and full-KDF assertions for unlock` |
| **B** | Run `OwnerOnlyTest` and `AtomicWriteCrashTest` on all 3 CI OSes. Read the `gate (windows-2022)` log and fix any Windows ACL issues. Then add `VaultPermissionsTest` in pm-vault: after `create` + `save`, the vault file, `.bak.1` and the parent dir are owner-only. This is the only file B adds in pm-vault; agree on it with C first. | `M1.3 B: verify owner-only perms on vault and backups across OSes` |
| **D** | `EnvelopeFuzzTest` in pm-fuzz targeting C's `EnvelopeCodec.decode`. Fuzz both decoders for 5 minutes each locally and record the results. Then run `semgrep --config tools/cert-rules/semgrep modules` over the whole tree and report any findings to the owning lane. | `M1.3 D: envelope fuzz harness and fuzz run results` |

---

## 7. Phase 4: Hardening and sign-off (1:35–2:00)

1. **Everyone:** rebase, run the full gate, and confirm `build/reports/cert-compliance.md` says **0 findings**. Don't paste over red results.
2. **Everyone:** add your subsection to `docs/security/milestone-signoff.md` under `## M1`, with five headers `### A`…`### E` that E creates first at 1:35. List each exit criterion you own, the test ID that proves it, and the actual command output line. Commit message: `M1.4 <lane>: sign off <lane> exit criteria`.
3. **E:** once the last PR merges, confirm the CI `gate` job is green on all three OSes. Then tag: `git tag -a m1 -m "M1 local vault foundation" && git push origin m1`.
4. **A (security owner):** confirm `docs/security/cert-exceptions.md` is empty or every entry is justified. Tick M1 in `plan.md` §13 "Project status".

### M1 exit criteria → owner → proof

| Exit criterion (plan.md §13 M1) | Owner | Test |
| --- | --- | --- |
| Byte flip detected before any record is parsed | C | `TamperTest` |
| Encrypt/decrypt round trip; corrupted input never gives a partial record | A, D | `AeadProperties`, `RecordCodecTest.truncationNeverPartial` |
| Killing mid-save never corrupts | B | `AtomicWriteCrashTest` (step-injected; real kill test in M7) |
| File permissions on all 3 OSes | B | `OwnerOnlyTest`, `VaultPermissionsTest` on the CI matrix |
| No secret in a String outside `@SecretBoundary` | all | Semgrep `cert.MSC03-J`, plus review |
| KDF always completes; tags compared with `MessageDigest.isEqual` | A, C | `ConstantTimeReviewTest`, Semgrep `cert.CT-compare` |
| Create/unlock/lock/save, passphrase, recovery key | C | `VaultServiceTest` |
| Login/Wi-Fi/SSH/Project records | D | `RecordCodecTest` |
| TUI dashboard and search | E | `DashboardTest` |
| Auto-lock | E | `IdleLockTest` |

---

## 8. Gotchas that will cost you 10 minutes each

- **`-Werror -Xlint:all` is on.**
  - Every `Exception` subclass needs `private static final long serialVersionUID = 1L;` because of the `serial` lint.
  - A try-with-resources variable that isn't used in the block triggers the `try` lint. Use it, or don't put it in try.
  - Constructors that call overridable methods trigger `this-escape`. Make classes `final`.
- **Error Prone `CheckReturnValue`:** don't ignore return values. Write `boolean unused = list.remove(x);` if you must.
- **Banned by Semgrep** (enforced on tests too): `Files.createTempFile`/`createTempDirectory` (use `@TempDir`), `new SecureRandom` outside pm-crypto, `new ProcessBuilder` outside pm-approval/pm-platform, `System.exit` outside `pm/cli/Main.java`, `Arrays.equals` on secrets, `String password = …` and similar names. (amended 2026-10-02 after review) The secret names now also include `pw`, `passwd`, `vk`, `rk`, `credential(s)`, `seed` and `keyBytes`, so `log.info("x" + vk)` and `String pw = …` fail too.
- **Banned by ArchUnit:** `javax.crypto`/`java.security` imports outside `pm.crypto`. C and D must go through `pm.crypto` APIs, even for SHA-256. Ask A to add a helper rather than importing `MessageDigest`. (amended 2026-10-02 after review) For constant-time byte compares, use `pm.crypto.ConstantTime.equals`.
- **Argon2 floor is slow** (64 MiB, t=3). Never put it in a loop in tests. Use `tries = 5` and the VK-layer seam.
- **jacoco 100% coverage on Tier 1** (amended 2026-10-02 after review). For **pm-crypto** it is now enforced: `:modules:pm-crypto:check` depends on `jacocoTestCoverageVerification`, and the rule is 100% of **branches** (the BRANCH counter only; line coverage is not checked). A pm-crypto change with an untested branch fails the gate. The other Tier 1 modules have the same rule configured but are **not wired into `check` yet**, so for them it won't fail the gate. Run `./gradlew :modules:<module>:jacocoTestCoverageVerification` yourself; wiring the rest is a post-sprint task.
- **Default charset:** always pass `StandardCharsets.UTF_8` (Error Prone `DefaultCharset` is an error).
- **Phase 1 stubs fail the gate as written.** Error Prone `DoNotCallSuggester` flags every method whose body is only `throw`. Put `@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)` on each stub class, and delete it when you implement the class. Routing the throw through a helper method does not help (verified in Lane A).
- **PMD `AvoidSynchronizedStatement` and `AvoidSynchronizedAtMethodLevel` are on.** `synchronized` is banned everywhere, so the §5 E advice ("guard with `synchronized`") is wrong. Use a `private final ReentrantLock` with `lock()` and `try/finally unlock()`.
- **PMD `AvoidLiteralsInIfCondition`:** only `-1` and `0` may appear in an `if` condition. Write `if (n > MAX_BYTES)` with a named constant, not `if (n > 1024)`.
- **Error Prone `ByteBufferBackingArray`:** don't call `.array()` on a buffer you didn't create with `allocate`/`wrap`. For example, `CharsetEncoder.encode(CharBuffer)` returns such a buffer. Encode into your own `ByteBuffer.allocate(...)` instead.
- **Gradle can't find JDK 21 even though it's installed:** pass `-Dorg.gradle.java.installations.paths=<jdk21 home>`, or put it in `~/.gradle/gradle.properties`.
- **jqwik writes a `.jqwik-database` file into each module.** It's git-ignored; don't commit it.

---

## 9. Progress (tick as phases close; each line gets a one-line result)

- [ ] **Phase 0 Setup:** deps merged, ADRs 0003–0008 Accepted, CODEOWNERS real, both CDDL files present
  - 2026-10-03: all done except CODEOWNERS, which still needs Lane E's GitHub handle (pm-cli, pm-tui).
- [x] **Phase 1 Contracts:** all §2 stubs on main, gate green
  - Result: all five lanes' contracts on main; gate green.
- [x] **Phase 2 Implementation:** 15 implementation commits merged (3 per lane), gate green
  - Result: all lanes merged by d4f6c36; jqwik round trips in CborWriterReaderTest/RecordCodecTest; gate green, 668 tests.
- [x] **Phase 3 Integration:** end-to-end test green, tamper/permission/constant-time/fuzz tests green on 3 OSes
  - Result: CI run 37136437530 green on ubuntu/macos/windows (678 tests, 0 findings); fuzz 3x5 min, 0 crashes.
- [ ] **Phase 4 Sign-off:** milestone-signoff M1 written by all five, tag `m1` pushed

## 10. Explicitly out of scope for this sprint (do not start)

Keychain or FIDO2 unlock slots, clipboard copy and reveal, password health, auto-lock on OS sleep,
`env` commands (M2), LAN (M3), jacoco wiring for Tier 1 modules other than pm-crypto (amended 2026-10-02 after review: pm-crypto is wired, §8), a real-process kill test (M7), and the 24 CPU-hour fuzz run.
