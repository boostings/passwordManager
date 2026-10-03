# ADR 0015: Format migrations and encrypted backups

- Status: Accepted
- Date: 2026-10-03
- Deciders: project team (Lane C)

## Context
`plan.md` §21 asks for a versioned vault format whose migrations make a backup first, validate
the migrated vault, allow rollback and refuse a downgrade unless forced (SR-701). The M7 exit
criterion is "migration rollback tested from every prior format version". ADR 0003 fixed the
envelope and its `u16 version`; M1 shipped version 1 and treated any other version as
`CORRUPT` (older) or `UNSUPPORTED_VERSION` (newer). Format 1 is the first format ever written, so
there is no real older file to migrate yet; the framework has to exist and be proven before the
first format change, not with it.

## Decision: migrations (M7.1)

**Frozen prefix.** Every format version keeps `magic(8) ‖ u16 version` as its first ten bytes.
`EnvelopeCodec.peekVersion` reads only that prefix, and the version chooses the reader. A future
version that changes the envelope beyond the header and payload adds its own reader; versions
that only change the header or payload schema reuse the version-1 envelope, whose AAD already
covers the version, so relabelling a file's version fails authentication.

**Registry.** `MigrationRegistry` holds the ordered steps this build ships. Each step is a
`Migration` from version N to N + 1, a pure function over the authenticated plaintext payload:
no I/O, clock, randomness or state. The constructor accepts only one contiguous chain that ends
at `EnvelopeCodec.VERSION`, so no version can be skipped and the oldest readable version is
`VERSION - steps`. The production registry is empty (format 1 is the oldest).

**Order.** `VaultService.unlockWithPassphrase` and `unlockWithRecoveryKey` (through
`VaultReader`, shared with backups):

1. read the prefix; a version newer than the build, or older than the oldest registered step,
   is `UNSUPPORTED_VERSION` and nothing is written (downgrade refused; there is no forced mode,
   because this build cannot read a newer format at all);
2. structural decode at that version, slot unwrap (`WRONG_CREDENTIAL`), AES-GCM open over the
   AAD (`CORRUPT`);
3. only then the migration chain, and the result is decoded by the current record codec; a step
   that fails, or output the codec rejects, is `CORRUPT` and nothing is written;
4. the original bytes are written as an owner-only rollback copy `<vault>.pre-migration-v<N>`
   (`VaultFileStore.createSibling`: create-new under the store's exclusive lock, owner-only before
   the first byte, fsync, atomic rename);
5. the vault is saved at the current version with the normal save, which also rotates the
   original into `.bak.1` (plan.md §21 "make a backup before migration");
6. the new file is re-read from disk and opened in full with the VK (verify on re-open);
7. the rollback copy is deleted.

Any failure in steps 5–6, including a runtime exception or an `Error` such as
`OutOfMemoryError`, writes the original bytes back atomically if the disk no longer holds them,
then deletes the copy; the unlocked vault is closed (VK and records wiped) on every failure path. If that restore fails, the
copy stays and the restore failure is attached to the reported exception as suppressed. A copy
left by an interrupted earlier run is reused if it is byte-identical to the current file and is
never overwritten otherwise (the migration is refused with `STORAGE`), because it may be the
only good copy. A process killed between steps 5 and 7 leaves the copy beside a migrated file:
the next unlock that opens the current file in full deletes every `.pre-migration-v<N>` copy
for older versions (best effort; a copy that is unsafe to touch is left and does not fail the
unlock), while a current file that fails to open keeps the copy.

`VaultService.fileFormatVersion()` and `currentFormatVersion()` let a caller tell the user before
unlocking that the unlock will migrate the file.

**Golden fixtures.** `modules/pm-vault/src/test/resources/pm/vault/golden/v<N>.bin` holds one
vault file per format version the production build reads, written once by the code of its time
and never regenerated; `GoldenFixtureTest` pins each file's SHA-256, requires a fixture for
every readable version, and opens each with the current code on every build. The throwaway
passphrase of every golden fixture is `golden fixture throwaway phrase` (it protects nothing
else); the content is `Formats.goldenRecords()`, one record of each type. The extension is
`.bin` because the gitleaks `pm-vault-file` rule exists to catch an accidentally committed real
vault, and these files are deliberate test data with a published passphrase.

**Proof without a real old format.** Tests inject a registry with a synthetic format 0 (the
version-1 envelope with prefix version 0 and a payload that is the bare record array) and its
step to format 1. `MigrationTest` migrates every version from the oldest readable to the
current one, and injects failures after the rollback copy, after the new file is installed,
during verification (the installed file is corrupted before re-open), in the step itself, and
with invalid step output; every case ends with the original bytes on disk and no copy or
staging file left.

## Decision: backups and restore (M7.2)

**File.** A backup is one file, `"PMBACKUP"(8) ‖ u16 1 ‖ u32 headerLen ‖ CBOR header ‖ vault file
‖ tag(32)` (`BackupFormat`). The vault file is embedded byte for byte as last saved, so it stays
encrypted under the VK and authenticated by its own AES-GCM tag; plaintext is never written. The
header is the deterministic CBOR map `{created, format_version, vault_length, content_sha256,
mac_salt}` with exactly those keys. The tag is HMAC-SHA256 over everything before it under
`BK = HKDF-SHA256(VK, mac_salt, "pm/backup/v1", 32)`, a fresh salt per backup, so the header
cannot be edited without the vault key. The extension is `.pmbackup`, which the gitleaks
`pm-vault-file` rule refuses in commits.

**API** (`VaultBackups`, for the CLI):

- `create(vault, dir, keep)` runs under the vault's lock: it reads the saved file, opens it in
  full with the vault's own key (a damaged file on disk is never backed up), and writes
  `pm-backup-<UTC yyyyMMdd'T'HHmmss'Z'>-<nnn>.pmbackup` through `BackupDirectory.createNew`
  (owner-only staging sibling, fsync, atomic rename, create-new). Unsaved edits are not included.
- Rotation then deletes the oldest backups with exactly that name pattern until `keep` remain.
  The new backup is written before anything is deleted and is never itself deleted, even when
  the clock went backwards; other files in the directory are never touched. Order is by the
  time in the name, except that a name dated more than one day after the current clock (clock
  skew) or with an impossible date sorts as the oldest, so it cannot hold a slot forever. A
  backup-named entry that is not an owner-only regular file is neither counted nor deleted, and
  neither is one whose deletion fails; both are returned as `skipped`. Rotation problems never
  fail `create` once the backup is written: it returns `Created` with a `Rotation` result
  (`complete = false` if the directory could not be listed again). `list` applies the same
  owner-only check.
- The header's `created` is limited to 0 through 9999-12-31T23:59:59Z, so every accepted
  value is a valid `Instant`; anything else is `CORRUPT`.
- `inspect(file)` checks framing, header and content hash with no passphrase; its facts are
  unauthenticated.
- `verify(file, passphrase)` writes nothing. Order: framing and content hash (a truncated or
  damaged file is `CORRUPT` before any KDF runs), then the passphrase against the embedded
  vault's slot (`WRONG_CREDENTIAL`), then the backup tag (`CORRUPT`), then the vault's AES-GCM tag
  and a full record decode through `VaultReader`, including any migration (M7.1).
- `restore(file, target, passphrase, overwrite)` verifies first, then opens the target store
  (exclusive lock; an open vault is refused). An existing vault is replaced only when `overwrite`
  is true (otherwise `ALREADY_EXISTS`) and is kept as `.bak.1`. The vault file is installed
  with `writeAtomically` and read back for a constant-time comparison. Any failure before the
  rename leaves the target unchanged; the rename is atomic. As in every save (ADR 0003),
  `.bak.1` is written before the vault is replaced, so a write that then fails has already
  shifted the older `.bak.N` generations and dropped the oldest. This is accepted: the target
  and its newest backup are intact, and reordering would replace the vault before its backup
  exists. The result reports
  `lowersSaveSeq` when the replaced vault had a higher `save_seq`, so the CLI can warn that the
  restore rolls content back (ADR 0003).

**Directory policy.** `BackupDirectory` (pm-storage) applies the vault store's rules: a missing
directory is created owner-only, an existing one must be secure and is never modified, files
are owner-only before they hold a byte, links are refused, names are restricted to
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. A backup named on the command line is read with
`BackupDirectory.readFile`, which refuses links and oversize files but not foreign permissions,
because a copied backup is authenticated by its content. `createNew` checks that the name is
free and then renames; `rename(2)` would replace a file created between the two steps. The
race is accepted: the directory is secure, so only the owner or an administrator can create
files in it, and the realistic racer is a second backup by the same user with the same name in
the same second, which replaces one complete backup with another and never exposes a partial
file. A hard link (`link(2)` fails if the name exists) would close it, but FAT and exFAT drives,
common backup targets, do not support hard links. SR-700's "entry whose canonical path
escapes the target" cannot arise: a backup holds one vault and no paths, and the target path is
the caller's.

## Alternatives considered
- Migrate in a separate explicit command only: an old vault would not open after an upgrade
  until the user found the command. The unlock already holds the key and has authenticated the
  file, so migrating there is safe, and the caller can still warn first.
- Keep only `.bak.1` as the rollback copy: rotation can push it out, and a failed save before
  the rotation would leave no copy. The dedicated create-new copy is independent of rotation.
- Backup as a plain copy of the vault file: the AES-GCM tag already covers the vault, but the
  creation time and version would be unauthenticated and truncation would only show up after a
  passphrase and a full KDF run. The small authenticated header fixes both.
- A tar or zip archive: multiple entries bring path traversal (SR-700) and a parser for a
  format we do not otherwise need.
- Migrations over decoded records instead of payload bytes: the old record classes would have to
  live on beside the current ones. Byte-level steps keep each version's knowledge in its step.

## Consequences
- Adding format 2 means: bump `EnvelopeCodec.VERSION`, add the 1→2 step to
  `MigrationRegistry.PRODUCTION`, commit `golden/v2.bin` from the new code, pin its hash.
  `GoldenFixtureTest` fails until the fixture exists, and the v1 fixture keeps proving the
  1→2 path forever.
- ADR 0003's implementation note ("a version older than 1 is `CORRUPT`") is superseded: an
  older version with no registered step is `UNSUPPORTED_VERSION`. `EnvelopeCodec.decode(file)`
  itself still reports it as `CORRUPT`; only the service layer knows about the registry.
- Backups made before a format change still restore: `verify` migrates in memory and the
  restored file migrates on its first unlock.
- Backups are bound to the master passphrase at the time of the backup; a recovery-key verify
  is a later addition if needed.
- No new `VaultException` codes: the CLI maps every code to an exit status and message, and the
  existing codes cover every outcome.

## Security considerations
Nothing from an older file is parsed before its tag verifies (SR-020), and the version cannot
be changed without failing the tag (SR-015). The rollback copy has the same encryption and
owner-only permissions as the vault (SR-040). A failed migration never leaves a partly written
vault (SR-041). A backup never contains plaintext and its header cannot be edited without the
VK (SR-703); restore verifies everything before it writes, and installs with one atomic rename
(SR-704). Rotation counts and deletes only files with the exact backup name pattern.

## CERT rules referenced
FIO01-J, FIO02-J, FIO03-J (no temp files; staging siblings only), ERR03-J (restore prior state
on failure), SER12-J, MSC05-J, NUM03-J.
