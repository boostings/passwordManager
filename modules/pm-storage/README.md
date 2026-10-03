# Lane B storage guide

Naren owns the storage lane in `docs/plans/M1-team-sprint.md`. This module
receives encrypted bytes from Lane C and handles their safe storage. Encryption,
password validation, and decoding vault records belong to the other lanes.

## Implementation

| File | Responsibility | Rules and requirements |
| --- | --- | --- |
| `OwnerOnly.java` | Apply and check POSIX permissions or Windows owner ACLs; supply restrictive attributes at file creation | FIO01-J, SR-040 |
| `StorageException.java` | Return a fixed error code without retaining path-bearing causes or suppressed exceptions | ERR01-J, SR-501 |
| `VaultFileStore.java` | Canonicalize paths, hold an exclusive lock, read within a size limit, replace files atomically, rotate backups, release resources | FIO00/02/03/04/08/10/16-J, OBJ06/14-J, ADR 0003, SR-041 |

The public signatures match the sprint's frozen storage contract. `pm.storage`
is exported through `module-info.java` and has no project or runtime library
dependencies.

## How a save works

1. `open(path)` resolves the parent directory and creates missing directories
   with owner-only permissions. A directory that already exists is never
   modified. It must be secure in the FIO00-J sense (see "Directory policy"
   below); a shared directory is rejected with `PERMISSIONS`.
2. The store acquires an exclusive lock on `vault.pmv.lock`. A process-local
   registry prevents duplicate opens of the canonical path in the same JVM.
3. `backup()` preserves the current encrypted vault as `.bak.1` and shifts older
   versions to `.bak.2` and `.bak.3`. Before the first save it does nothing. The
   new backup is staged completely before the older ones move, and a vault that
   `.bak.1` already holds byte for byte is not backed up again, so a failed or
   retried save cannot push older generations out.
4. `writeAtomically(data)` copies the input and creates `vault.pmv.tmp` with
   restrictive permissions before writing any bytes. It writes the complete
   buffer, calls `force(true)`, and atomically replaces the vault.
5. Temporary staging files are cleaned up on normal completion and exceptions.
   A stale regular staging file left by process termination is removed by the
   next write, whatever its permissions. Symbolic links are refused.
6. `close()` closes the channel and releases its lock. The empty lock file stays
   on disk so subsequent processes continue locking the same filesystem object.

### Directory policy (FIO00-J, FIO01-J)

Everything the store creates is owner-only before it holds a byte: the vault,
`.tmp`, `.bak.N`, `.lock`, and a parent directory that was missing (POSIX
`rw-------` / `rwx------`; Windows one ALLOW entry for the owner, no
inheritance). A parent directory that already exists is judged as found:

- POSIX: owned by the current user, no group or other write bit. Read and
  search bits for others are tolerated.
- Windows: no ALLOW entry that applies to the directory may give a write right
  (add file or subdirectory, delete, delete child, write attributes, change
  permissions, take ownership) to anyone but the directory's owner,
  `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`. The two accounts are
  recognised by security identifier (S-1-5-18, S-1-5-32-544), not by their
  localised names. DENY entries are not grants; inherit-only entries do not
  apply to the directory. A directory owned by one of the two accounts may also
  be written by the account named by `user.name`.
- Every store file must be owned by the directory's owner (on Windows also by
  the current user when one of the two administrative accounts owns the
  directory), so a directory that belongs to somebody else cannot be used.

Vault names that end in a dot or a space are refused, because Windows drops
those characters and one vault would otherwise get two lock files. An existing
vault is addressed by the name stored on disk (case, Windows short names).

Lane C calls the methods in this order:

```java
/** Saves bytes which the crypto and vault layers have already encrypted. */
public static void saveEncrypted(Path vaultPath, byte[] encrypted)
        throws StorageException {
    try (VaultFileStore store = VaultFileStore.open(vaultPath)) {
        store.backup();
        store.writeAtomically(encrypted);
    }
}
```

Import `java.nio.file.Path`, `pm.storage.StorageException`, and
`pm.storage.VaultFileStore` for this example. A running vault normally retains
its store until the vault session ends, rather than reopening for each save.
The caller coordinates the backup/save sequence as one logical operation.

## Tests

| Test class | Demonstration |
| --- | --- |
| `OwnerOnlyTest` | File and directory permissions, exact POSIX modes, Windows ACLs |
| `StorageExceptionTest` | Error messages, causes, and suppressed errors do not disclose a sentinel path |
| `AtomicWriteCrashTest` | Every interrupted replacement leaves the complete old or new vault; staging permissions precede data writes |
| `LockTest` | A competing open is rejected, a lock held through an independent channel is honoured, close allows reopening, closed instances cannot be reused |
| `SizeLimitTest` | Oversized files and writes are rejected; partial reads and byte `0xff` are preserved |
| `BackupRotationTest` | Five saves retain the expected three previous versions with owner-only permissions; repeated or failed backups keep every generation; stale staging recovery whatever the stale file's permissions |
| `SymlinkRefusedTest` | Vault, lock, staging, and backup links are rejected; parent aliases share a lock; group- or other-writable directories are refused unchanged (POSIX) |
| `ExistingDirectoryTest` | An existing secure directory is accepted and left unchanged on POSIX and Windows; a write grant to another principal is refused; a DENY entry is not a grant; administrative accounts are recognised by SID |
| `PathHandlingTest` | A directory name the filesystem alters stays usable; vault names ending in a dot are refused; an absent filesystem root gives `NOT_FOUND` |
| `BoundedReadProperties` | Generated binary inputs preserve every byte within the limit and never return partial data when oversized |

With JDK 21 available to Gradle, run:

```sh
./gradlew :modules:pm-storage:check
./gradlew check certReport
gitleaks git --redact --no-banner --config tools/cert-rules/gitleaks.toml .
```

## Local verification on 2026-10-02

The exact working-tree Java sources were tested on macOS with Temurin JDK 21.
The Gradle test and PMD tasks ran in a temporary project copy with independently
verified missing dependency metadata and corrected PMD rule references.
No shared build configuration was changed by Lane B. The subsequent merge from
`main` includes the team's PMD corrections.

| Check | Actual result |
| --- | --- |
| Compilation with `-Xlint:all`, `-Werror`, and Error Prone | Passed for production and tests |
| JUnit and jqwik | 40 tests discovered, 39 passed, 1 Windows-only ACL test skipped, 0 failures |
| Generated input properties | 100 attempts per property; oversized-input property discards empty input |
| PMD production and tests | 0 violations using the corrected rule references in the temporary copy |
| Semgrep CERT pack | 0 findings across all 13 explicitly selected Java files, including tests |
| Gitleaks | No leaks in storage files or repository history (7 commits) |
| JaCoCo | 77% instruction coverage, 62% branch coverage; the Tier 1 100% branch target is not met |
| SpotBugs and the complete repository gate | Blocked by pre-existing dependency-verification settings; not claimed to pass |

The tested Gradle task selection was `:modules:pm-storage:test`,
`:modules:pm-storage:pmdMain`, `:modules:pm-storage:pmdTest`, and
`:modules:pm-storage:jacocoTestReport`. It completed with `BUILD SUCCESSFUL`.
The full storage `check` also includes SpotBugs and is still blocked.

After merging the updated `main`, the two storage-stub conflicts were resolved
by retaining Lane B's complete implementations. The full `check certReport`
was rerun; dependency verification still blocks it (including Apache, SLF4J,
FindSecBugs, and jqwik artifacts). This merge does not claim a passing full gate.

## Review limits

- The crash tests inject exceptions at write checkpoints. They do not simulate
  abrupt process termination, physical power loss, or filesystem corruption.
  The real-process kill test remains M7 work in the sprint plan.
- Directory fsync is best effort on POSIX and skipped on Windows, as specified
  by M1. The file itself is flushed before rename; durability across power loss
  still depends on the filesystem. Atomic-move failure has no non-atomic fallback.
- A failure after rename may leave the complete new version installed. Reopen
  and inspect state before deciding whether a failed save should be retried.
- Rotation is a sequence of atomic file operations, not a transaction spanning
  all three backups. The new backup is written before the older ones move, so
  a failed write changes nothing; a failure during the renames themselves can
  still leave a gap among the backup names. It does not overwrite the active
  vault with partial data.
- Owner-only permissions protect against other OS users. They do not isolate
  this application from malware running as the same user or from administrators.
  File locks coordinate cooperating processes. Use a directory whose hierarchy
  is controlled by the user; portable path-based checks cannot eliminate every
  hostile concurrent path replacement.

## Team work still pending

- Lane E's GitHub username is still needed for the CLI/TUI CODEOWNERS entries.
- Lane C's `VaultService` is now included from `main`. Coordinate the sprint's
  `VaultPermissionsTest` in `pm-vault` with C before adding it.
- Run storage tests on the existing Linux, macOS, and Windows CI matrix before
  signing off cross-platform permissions. A local Mac run cannot certify Windows.
- Extend failure-path and platform coverage to meet the Tier 1 branch-coverage
  target before claiming the full hardening/sign-off phase is complete.
- The checked-in Gradle verification configuration currently cannot complete a
  fresh build: several already-trusted public signing keys are unavailable
  locally, some dependency metadata lacks fallback checksums, and SpotBugs'
  dependency metadata introduces signing keys not in the trust list. Those
  require independent review by the build/security owners; verification has not
  been disabled. Build verification belongs to E.

The JetBrains public-key fingerprint already trusted in the repository is
`2E3A1AFFE42B5F53AF19F780BCF4173966770193`. The independently checked Guava parent
POM SHA-256 is `3a499ed34a0d9ee0f1bcc39230021a1cd4e2f7dd0426ab6844f585465d41dcd7`.
These are two concrete examples for Lane E's build-repair review, not an exhaustive
list of the unresolved dependency-verification entries. Package the needed
trusted public keys and review missing metadata while retaining strict checks.
