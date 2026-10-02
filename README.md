# passwordManager

A local, offline password manager written in Java 21 with JPMS modules, built as a five-person
class project. Secrets are stored in a single encrypted vault file: Argon2id stretches the
passphrase, AES key wrap protects the vault key, and AES-256-GCM with a fresh per-save key
encrypts the records (ADRs 0003 to 0008). You use it through a command-line interface (`pm`) and
a Lanterna text UI. All Java must follow the SEI CERT Java rules in [RULES.md](RULES.md), and a
Gradle gate enforces them.

The current milestone is **M1, local vault foundation**. M1 is not finished yet; see
[Current state](#current-state).

## Module layout

All modules live under `modules/` and are listed in `settings.gradle.kts`.

| Module | JPMS name | Lane | Contents |
| --- | --- | --- | --- |
| `pm-crypto` | `pm.crypto` | A | `SecretBytes`/`SecretChars`, CSPRNG, Argon2id, HKDF, AES-KWP, AES-GCM, recovery key, `SafeLog`. The only module allowed to use JCA and Bouncy Castle. |
| `pm-storage` | `pm.storage` | B | `VaultFileStore` (atomic writes, lock file, backups), `OwnerOnly` permissions |
| `pm-vault` | `pm.vault` | C, D | `VaultService`, envelope, key slots (C); CBOR codec, record types, search (D) |
| `pm-tui` | `pm.tui` | E | Lanterna UI: unlock, dashboard, search, add login, idle auto-lock |
| `pm-cli` | `pm.cli` | E | `pm` entry point (`pm.cli.Main`) |
| `pm-arch-tests` | | | ArchUnit rules: module boundaries, banned APIs, constant-time compares |
| `pm-fuzz` | | D | Fuzz harnesses (placeholder) |
| `pm-domain`, `pm-approval`, `pm-sharing`, `pm-browser`, `pm-platform-{macos,windows,linux}` | | | Placeholders for later milestones |

Module graph: `pm.cli -> pm.tui -> pm.vault -> {pm.crypto, pm.storage}`. `pm.crypto` requires
`org.bouncycastle.provider`, and `pm.tui` requires `com.googlecode.lanterna`.

Key docs: [plan.md](plan.md) (product plan), [docs/plans/M1-team-sprint.md](docs/plans/M1-team-sprint.md)
(lanes and frozen API contracts), [docs/adr/](docs/adr/), [docs/security/](docs/security/),
[docs/security/cert-exceptions.md](docs/security/cert-exceptions.md) (every scanner suppression).

## Prerequisites

| Tool | Version used | Why |
| --- | --- | --- |
| JDK 21 | Homebrew `openjdk@21` (21.0.12.1), at `/opt/homebrew/opt/openjdk@21` | Gradle toolchain is pinned to 21 |
| Gradle | wrapper, 9.7.1 (`./gradlew`, no install needed) | build |
| semgrep | 1.176.0 (same as CI) | the `semgrepCert` task runs `semgrep scan --config tools/cert-rules/semgrep`, and `certReport` depends on it |
| gitleaks | 8.30.1 (same as CI) | the `gitleaksScan` task runs `gitleaks git --redact --no-banner --config tools/cert-rules/gitleaks.toml .` |

On macOS: `brew install openjdk@21 semgrep gitleaks`. Both scanners must be on `PATH`, because Gradle
runs them as external commands.

If Gradle reports "Cannot find a Java installation ... languageVersion=21" (for example when
`java_home` only sees JDK 17), pass the JDK path as in the commands below, or add
`org.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21` to `~/.gradle/gradle.properties`.

## Build and gate

The full gate (compile with `-Werror` and Error Prone, tests, PMD, SpotBugs with FindSecBugs,
ArchUnit, 100% branch coverage on pm-crypto, Semgrep, then the CERT report):

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew \
  -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 \
  check certReport
```

The report is written to `build/reports/cert-compliance.md` and also printed. A green gate shows
`**Result: 0 findings.**` followed by `BUILD SUCCESSFUL`.

**The full gate is red at the moment**: `:modules:pm-vault:test` fails 66 of 87 tests (see
[Current state](#current-state)). Until Lanes B and D land, run the gate with that one task
excluded:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew \
  -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 \
  check certReport -x :modules:pm-vault:test
```

`check` does not run the secret scan. Run it separately (CI runs it as its own step):

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew \
  -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 gitleaksScan
```

`./gradlew verifyAll` runs `check`, `gitleaksScan` and `certReport` together, but it is red for the
same pm-vault reason. To work on one module, run `./gradlew :modules:pm-crypto:check` (with the
same JDK flags).

## Running the CLI

There is no Gradle `application` plugin and no `run` task. The `pm-cli` module has an
`installModules` task that copies the pm-cli jar and all of its runtime jars (pm-tui, pm-vault,
pm-crypto, pm-storage, lanterna-3.1.3, bcprov-jdk18on-1.86) into `modules/pm-cli/build/modules`.
`scripts/pm` runs that task and then launches the CLI on the module path:

```sh
scripts/pm [--vault <path>] [--] init | add-login | list | search <query> | tui
```

`scripts/pm` uses the following environment variables:

- `PM_JAVA_HOME`: the JDK 21 to use. The default is `/opt/homebrew/opt/openjdk@21`, falling back to `$JAVA_HOME`.
- `PM_JAVA_OPTS`: extra JVM options, for example `-Xmx1200m`.
- `PM_SKIP_BUILD=1`: skip the Gradle step and run the jars from the last build.

Without the script, the same thing by hand:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew \
  -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 :modules:pm-cli:installModules
/opt/homebrew/opt/openjdk@21/bin/java -p modules/pm-cli/build/modules -m pm.cli/pm.cli.Main --help
```

### Commands

| Command | What it does |
| --- | --- |
| `init` | Asks for a new passphrase twice, creates the vault, and prints the recovery key once |
| `add-login` | Unlocks the vault and prompts for title, username, password, URLs and tags |
| `list` | Prints `id  type  title  updated` for each record. Secret fields are never printed. |
| `search <query>` | Same output as `list`, filtered by the query |
| `tui` | Opens the full-screen Lanterna UI (unlock window, dashboard, search, add login, idle lock) |
| `--help`, `-h`, `help` | Prints the usage line |

**A real terminal is required.** Passphrases are read only through `System.console()`. When stdin
or stdout is not a terminal (a pipe, CI, an IDE run window), every command, including `--help`,
prints `interactive terminal required` and exits with 2. To test from a script, run the command
under a pseudo-terminal, for example `script -q /dev/null scripts/pm --help` or `expect`.

### Default vault path

If you don't pass `--vault`, the CLI picks a path from the `os.name` and `user.home` system
properties. It never reads environment variables.

| OS | Path |
| --- | --- |
| macOS | `~/Library/Application Support/pm/vault.pmv` |
| Windows | `~\AppData\Roaming\pm\vault.pmv` |
| Linux and others | `~/.local/share/pm/vault.pmv` |

`--vault` must name a file. A leading `~` is refused, not expanded, so give a full or relative
path. Directories, trailing separators, and `.` or `..` as the last element are refused too.

### Exit codes

Defined in `modules/pm-cli/src/main/java/pm/cli/ExitCodes.java`:

| Code | Meaning |
| --- | --- |
| 0 | OK |
| 1 | Wrong passphrase or recovery key |
| 2 | Usage error, no interactive terminal, or `init` on a path that already holds a vault |
| 3 | Vault file corrupt, tampered with, or an unsupported format version |
| 4 | Storage error, or the vault is locked by another process |
| 5 | Internal error (a bug; only "internal error" is printed, never a stack trace) |
| 6 | `init` created the vault but could not show the recovery key: delete the new vault file and run `init` again |

### What you will see today

The commands below were run on macOS (JDK 21.0.12.1) against commit `a995556`. They show the
current state:

```text
$ script -q /dev/null scripts/pm --help
usage: pm [--vault <path>] [--] init | add-login | list | search <query> | tui
(exit 0)

$ script -q /dev/null scripts/pm frob
usage: pm [--vault <path>] [--] init | add-login | list | search <query> | tui
unknown command
(exit 2)

$ scripts/pm --help            # stdout not a terminal
interactive terminal required
(exit 2)

$ scripts/pm --vault /tmp/x/vault.pmv init      # under expect, both passphrases typed
New passphrase:
Repeat passphrase:
internal error
(exit 5)
```

`list`, `search foo` and `add-login` against that path each ask for `Passphrase:`, then print
`internal error` and exit with 5. `tui` draws the "Unlock vault" window
(`Passphrase or recovery key`, `<Unlock> <Use recovery key> < Quit >`). After you submit a
passphrase it exits the UI, prints `internal error`, and exits with 5. No vault file is created.

## Current state

M1 is **not finished**: no vault can be created or opened yet.

- **Lane B (`pm-storage`)**: `VaultFileStore` is still a stub. Every method throws
  `UnsupportedOperationException("M1 stub")`.
- **Lane D (`pm.vault.cbor`, `pm.vault.record`)**: `CborReader`, `CborWriter`, `RecordCodec` and
  `RecordSearch` are still stubs that throw the same exception.
- So `init` and every other vault operation fail. Per the integration notes
  ([M1-integration.md](docs/plans/M1-integration.md) I4), `VaultService.create` first hits the
  `VaultFileStore.open` stub and then the `CborWriter.encode`/`RecordCodec` stubs. The CLI maps the
  unexpected exception to exit 5, `internal error`, as shown above.
- Tests, as of `a995556`:

  | Module | Tests | Failed |
  | --- | --- | --- |
  | pm-crypto | 144 | 0 |
  | pm-cli | 127 | 0 |
  | pm-tui | 41 | 0 |
  | pm-arch-tests | 15 | 0 |
  | pm-vault | 87 | **66**, all because of the Lane B and D stubs |

- Lanes A (crypto), C (vault core) and E (CLI/TUI) are implemented and merged to `main`. The CLI and
  TUI tests run against an in-memory fake vault port, not the real vault.

## Remaining work

Lanes B and D:

- [ ] Lane B: implement `VaultFileStore` (symlink refusal, owner-only parent dir, lock file,
      atomic write with fsync, `.bak.1..3` rotation) and `OwnerOnly`. Add `OwnerOnlyTest`,
      `AtomicWriteCrashTest`, and `VaultPermissionsTest` in pm-vault.
- [ ] Lane D: implement `CborReader`/`CborWriter` (a hand-rolled deterministic subset, per ADR 0006
      Amendment 1), `RecordCodec` and `RecordSearch`. Add `RecordCodecTest` (including
      `truncationNeverPartial`), `docs/schemas/records.cddl`, and `EnvelopeFuzzTest` in pm-fuzz,
      with recorded fuzz runs.

After B and D land:

- [ ] The 66 failing pm-vault tests pass, so the full gate (`check certReport`, nothing excluded) is green.
- [ ] E3: `EndToEndTest` in pm-cli: init with the canary passphrase, add-login, list, reopen,
      list, and a wrong passphrase gives exit 1. Then a manual terminal transcript of a real run.
- [ ] Lane A: `ConstantTimeReviewTest` (M1.3). The wrong-passphrase full-Argon2 proof (A3b) is
      already done at slot level.
- [ ] CI `gate` job green on all three OSes (ubuntu-22.04, macos-14, windows-2022), including
      Windows ACLs for `OwnerOnly`.

Sign-off and setup:

- [ ] Security owner signs off CE-001 to CE-005 in `docs/security/cert-exceptions.md`. All five
      are "Pending security-owner sign-off".
- [ ] `docs/security/milestone-signoff.md` gets an M1 section with `### A` through `### E`, one
      written by each lane. Then tag `m1`, and tick M1 in `plan.md` §13.
- [ ] Sprint Phase 0 leftovers: replace the `@TEAM-*` placeholders in `CODEOWNERS` with real
      handles, and set ADRs 0002, 0003, 0004 and 0006 to Accepted (they are still Proposed).
- [ ] Repo settings (admin only): disable squash merging
      (`gh repo edit boostings/passwordManager --enable-squash-merge=false`; squash is still
      enabled), and turn on branch protection on `main` (require a PR, the `gate (*)` checks and
      one review).
- [ ] Dependency-Check needs an NVD API key (user-only follow-up from M0).

Known open items:

- [ ] Lanterna 3.1.3 is pinned by checksum only. Its signing key (94483BA5F4740C42) is not on any
      public keyserver, so the signature cannot be verified.
- [ ] If `Session.close` throws while the TUI is locking, the exception escapes `TuiApp.run`, and
      the CLI turns it into exit 5.
- [ ] Refusing a symlinked `--vault` path belongs to Lane B (`VaultFileStore.open`, `NOFOLLOW_LINKS`).
      The CLI does not check for it.
- [ ] `pm list --help` prints the usage line and exits 0 instead of treating `--help` as a usage
      error for `list`.
- [ ] Vaults with 1 GiB Argon2 memory need `-Xmx1150m` or more (for example
      `PM_JAVA_OPTS=-Xmx1200m scripts/pm ...`). `Kdf` refuses to run when
      `memoryKiB * 1024 * 1.1` exceeds the free heap (ADR 0007).
- [ ] Jacoco 100% branch coverage is enforced only for pm-crypto. The other Tier 1 modules have
      the rule configured but not wired into `check` (post-sprint task).

## Team workflow

Lanes and file ownership (full table in
[docs/plans/M1-team-sprint.md §0](docs/plans/M1-team-sprint.md)):

| Lane | Area | Owns |
| --- | --- | --- |
| A | Crypto (also the security owner) | `modules/pm-crypto/**` |
| B | Storage | `modules/pm-storage/**`, `CODEOWNERS` |
| C | Vault core | `pm/vault/*.java`, `pm/vault/envelope/**`, `pm/vault/slot/**`, pm-vault build and module-info, `docs/schemas/vault-header.cddl` |
| D | Records and CBOR | `pm/vault/cbor/**`, `pm/vault/record/**`, `modules/pm-fuzz/**`, `docs/schemas/records.cddl`, ADR 0006 |
| E | CLI, TUI and integration | `modules/pm-cli/**`, `modules/pm-tui/**`, `gradle/verification-metadata.xml` |

Rules:

- Use one branch per PR, named `m1/<lane>/<topic>`. Never commit to `main`.
- Commit messages use the format `M1.<phase> <lane>: <imperative summary>`, for example
  `M1.2 A: implement AES-256-GCM seal/open`. Every commit compiles and passes the gate.
- The gate must be green (`BUILD SUCCESSFUL` and `0 findings`) before you push. Paste its last
  lines into the PR.
- All Java (main, test and build code) must follow [RULES.md](RULES.md). Any CERT violation found
  in review blocks the PR. Every scanner suppression needs a row in
  [docs/security/cert-exceptions.md](docs/security/cert-exceptions.md).
- **Never squash-merge.** Use rebase-merge or a merge commit so everyone's individual commits are kept.
- Tier 1 modules (pm-crypto, pm-vault, pm-storage) need two approvals; other modules need one.
  Reviewers work through `docs/security/code-review-checklist.md`.
- Ask in chat before editing another lane's files. A change to a §2 contract is made by its owner
  in a small PR, and everyone rebases on it.
- See [CONTRIBUTING.md](CONTRIBUTING.md) for the rest (ADR-before-code, fuzz harness for every new
  input, and what must never be committed).
