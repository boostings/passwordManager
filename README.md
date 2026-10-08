# passwordManager

pm is a local, offline password manager written in Java 21 with JPMS modules, built as a
five-person class project. It keeps logins, Wi-Fi networks, SSH keys and per-project environment
variables in a single encrypted vault file. Argon2id stretches the passphrase, AES key wrap
protects the vault key, and AES-256-GCM encrypts the records (ADRs 0003 to 0008). A secret leaves
the vault only after you approve it, and every release is written to a hash-chained audit log
first.

You use it through a command-line interface (`pm`), a full-screen Lanterna app, a Chrome-family
browser extension, and LAN pairing and sharing between your own devices. There is no server, no
account and no sync service. All Java follows the SEI CERT Java rules in [RULES.md](RULES.md), and
a Gradle gate enforces them.

**Version 1.0.0.** Milestones M0 to M7 of [plan.md](plan.md) are built; the plan and each phase's
result are in [docs/plans/M2-M7.md](docs/plans/M2-M7.md). Start with the
[user guide](docs/user-guide.md). [Release notes](docs/release/release-notes-1.0.0.md) list what
v1 does and does not include (no passkeys, unsigned installers, Copy only on macOS).

## Module layout

All modules live under `modules/` and are listed in `settings.gradle.kts`. The six Tier 1
modules are held at 100% branch coverage by `check`.

| Module | Tier | Contents |
| --- | --- | --- |
| `pm-crypto` | 1 | `SecretBytes`/`SecretChars`, CSPRNG, Argon2id, HKDF, AES-KWP, AES-GCM, recovery key, TLS and Ed25519 helpers, SSH key parsing and the ssh-agent client, `SafeLog`. The only module allowed to use JCA and Bouncy Castle |
| `pm-storage` | 1 | `VaultFileStore` (atomic writes, lock file, `.bak` rotation), backup folders, `OwnerOnly` permissions on POSIX and ACL file systems |
| `pm-vault` | 1 | `VaultService`, envelope, key slots, passphrase change, format migration, backups, CBOR codec and record types |
| `pm-approval` | 1 | Approval broker, grants and policies, hash-chained audit log, IPC between `pm env run` and the app |
| `pm-sharing` | 1 | LAN pairing (TLS 1.3, SAS), one-time shares, the browser receiving page |
| `pm-browser` | 1 | Native messaging host, origin binding and fill rules, relay to the app; passkey code is present but unreachable in v1 (ADR 0016) |
| `pm-domain` | 2 | Password generator, health and breach checks, `.env` parsing, environment variables pm reads |
| `pm-tui` | 2 | Lanterna app: unlock, dashboard, record cards, dialogs, approvals, devices, idle lock |
| `pm-cli` | 2 | `pm` entry point (`pm.cli.Main`) and every command |
| `pm-platform-macos` | 2 | macOS clipboard adapter (`pbcopy`/`pbpaste`) |
| `pm-platform-linux`, `pm-platform-windows` | 2 | Empty in v1 |
| `pm-arch-tests` | | ArchUnit rules: module tiers, banned APIs (JCA outside pm-crypto, serialization, process spawning outside the env runner and platform adapters), SSH key and passkey reach, constant-time compares |
| `pm-fuzz` | | Fuzz harnesses for every parser that reads outside input, with seed replay in `check` |

`extension/` holds the browser extension (Manifest V3, `node --test` suite) and `tools/` the CERT
rule packs, packaging and CI scripts.

Key docs: [plan.md](plan.md) (product plan), [docs/adr/](docs/adr/), [docs/security/](docs/security/)
(threat model, requirements, traceability, risk register,
[security review record](docs/security/security-review-record.md)),
[docs/security/cert-exceptions.md](docs/security/cert-exceptions.md) (every scanner suppression),
[docs/platform-matrix.md](docs/platform-matrix.md), [docs/release/packaging.md](docs/release/packaging.md).

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

The full gate: compile with `-Werror` and Error Prone, tests, PMD, SpotBugs with FindSecBugs,
ArchUnit, fuzz seed replay, the extension's Node tests, 100% branch coverage on the six Tier 1
modules, Semgrep and the CERT report, then the gitleaks secret scan:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew \
  -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 \
  check certReport gitleaksScan
```

The report is written to `build/reports/cert-compliance.md` and also printed. A green gate shows
`**Result: 0 findings.**`, `no leaks found` and `BUILD SUCCESSFUL`. `./gradlew verifyAll` runs the
same three tasks. To work on one module, run `./gradlew :modules:pm-crypto:check` (with the same
JDK flags). Release archives and installers are built by `./gradlew release`
([packaging](docs/release/packaging.md)).

## Running the CLI

### One command: `pm`

Install once, then `pm` opens the whole app from any directory:

```sh
scripts/install-pm   # links scripts/pm to ~/.local/bin/pm and builds; pass another bin dir if you like
pm                   # opens the full-screen app
```

On the first run there is no vault yet, so `pm` asks for a new passphrase twice, creates the
vault, prints the recovery key once, and waits for Enter so you can write the key down. Then it
opens the full-screen app, which asks you to unlock. After that, `pm` goes straight to the unlock
screen. `pm --vault <path>` does the same for a vault file elsewhere. The subcommands below still
work for scripting and quick lookups.

### How it is launched

There is no Gradle `application` plugin and no `run` task. The `pm-cli` module has an
`installModules` task that syncs the pm-cli jar and all of its runtime jars (the other pm modules,
Lanterna and Bouncy Castle) into `modules/pm-cli/build/modules`.
`scripts/pm` runs that task and then launches the CLI on the module path:

```sh
scripts/pm [--vault <path>] [--] [<command> [<arguments>]]   # scripts/pm --help lists every command
```

`scripts/pm` uses the following environment variables:

- `PM_JAVA_HOME`: the JDK 21 to use. The default is `/opt/homebrew/opt/openjdk@21`, falling back to `$JAVA_HOME`.
- `PM_JAVA_OPTS`: extra JVM options, for example `-Xmx1200m`.
- `PM_SKIP_BUILD=1`: skip the Gradle step and run the jars from the last build.

pm itself reads `PM_CLIPBOARD_CLEAR`: the seconds a password copied in the app stays on the
clipboard, a whole number from 5 to 300 (default 30; any other value means 30).

Without the script, the same thing by hand:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew \
  -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 :modules:pm-cli:installModules
/opt/homebrew/opt/openjdk@21/bin/java -p modules/pm-cli/build/modules -m pm.cli/pm.cli.Main --help
```

### Commands

| Command | What it does |
| --- | --- |
| (none) | Opens the app: the full-screen UI, after creating the vault first if none exists |
| `init` | Asks for a new passphrase twice, creates the vault, and prints the recovery key once |
| `add-login` | Unlocks the vault and prompts for title, username, password, URLs and tags |
| `list` | Prints `id  type  title  updated` for each record. Secret fields are never printed. |
| `search <query>` | Same output as `list`, filtered by the query |
| `show <item> [--reveal]` | Prints one item's fields with every secret masked. `--reveal` is the one way the CLI prints a secret, and only a login's password or a Wi-Fi PSK; SSH private keys are never printed and project values leave only through `env`. `<item>` is a title or an id from `list`; a title several items share is refused with their ids |
| `edit <item> [--title T] [--username U] [--urls U] [--tags T] [--notes N] [--password \| --generate]` | Changes a login; `--password` prompts twice (never a value on the command line), `--generate` takes the `generate` options; `""` clears username, URLs, tags or notes |
| `edit <item> [--title T] [--ssid S] [--security WPA2\|WPA3\|WEP\|OPEN] [--hidden \| --not-hidden] [--notes N] [--password \| --generate]` | Changes a Wi-Fi network the same way |
| `rm <item> [--yes]` | Removes any item after you type `y` (or at once with `--yes`); for an SSH key it reminds you that `ssh-agent` keeps a loaded copy |
| `wifi add <ssid> [--title T] [--security S] [--hidden] [--notes N]` | Adds a Wi-Fi network; the PSK is prompted twice (none for `OPEN`); security defaults to `WPA2` |
| `tui` | Opens the full-screen app, the same as `pm` with no command once the vault exists |
| `generate [--length N] [--classes lower,upper,digits,symbols] [--exclude-ambiguous]` | Prints one random password on stdout and its entropy on stderr. Needs no vault and no terminal, so `pm generate \| pbcopy` works |
| `generate --passphrase [--words N] [--separator C]` | Same, as a word passphrase |
| `health [--max-age-days N]` | Reports weak, reused and old passwords by title only, offline |
| `health --breach` | Also checks passwords against the Pwned Passwords range API, after you type exactly `y`; only 5-character SHA-1 prefixes are sent, one per distinct password |
| `ssh import <file> [--title T]` | Stores an unencrypted OpenSSH Ed25519 or ECDSA P-256 key; warns if others can read the file, and tells you to delete the plaintext original |
| `ssh list` | Lists the identities your `ssh-agent` holds |
| `ssh add <item> [--lifetime 1h] [--confirm]` | Sends a stored key to `ssh-agent` (audited first) |
| `ssh remove <item>` or `ssh remove --all` | Removes a key, or every key, from `ssh-agent` |
| `ssh export <item> <file>` | Writes the key to a new owner-only (0600) file; never overwrites (audited first) |
| `project add <title> [--dir <path>]` | Registers a directory (default: the current one) as a project, so `env` commands run there find it |
| `project list` | Lists the projects: title, directory and profiles |
| `env list [--project T] [--profile P]` | Lists the variable names of a profile; values are never printed |
| `env import <file> [--project T] [--profile P]` | Imports a `.env` file into a profile; delete the plaintext file once the import is checked |
| `env export <file> --plaintext [--project T] [--profile P]` | Writes a profile to a new owner-only `.env` file, never overwriting one; `--plaintext` confirms the values are written unencrypted |
| `env run [--only A,B] [--project T] [--profile P] -- <command> [args...]` | Runs a command with the profile's variables once approved: in the open pm window if one runs, otherwise here by typing `y`. Nothing is written to disk |
| `devices` | Shows this device's name and fingerprint and lists the paired devices |
| `devices remove <name\|fingerprint>` | Unpairs a device and lists the items that were offered to it, so you can change those secrets |
| `pair --listen [--bind <ip>] [--name <name>]` or `pair <ip:port> [--name <name>]` | Pairs with another device on the local network: one side listens, the other connects, then both compare a code |
| `share <title> --to <device> [--ttl 10m] [--bind <ip>]` | Offers one item, after you type `y`, to a paired device; the window closes after one delivery or when its time (1s to 24h) is up |
| `share <title> --browser [--ttl 10m] [--bind <ip>]` | The same, to a browser through a one-time link |
| `receive <ip:port>` | Accepts the item a paired device is sharing, after you type `y` |
| `revoke <share-id>` | Closes a share window this machine has open; nothing more is sent |
| `browser install [--browser chrome\|chromium\|edge\|brave\|all] [--extension-id <id>]` | Registers pm as the native messaging host of the pm extension for this user and allows that extension (default vault only; on Windows it prints the manual steps). Every request still needs your yes in the open pm window |
| `browser uninstall [--browser B] [--extension-id <id>]` | Removes pm's manifest from the named browsers, or only that extension from them |
| `browser status [--browser B]` | Shows each browser's manifest, the extensions it allows, and pm's allowlist |
| `passphrase [--recovery]` | Changes the master passphrase: asks for the current one (or, with `--recovery`, the recovery key), then the new one twice. The recovery key and every item stay as they are; earlier `.bak` files and backups still open with the old passphrase |
| `recover` | For a lost passphrase: asks for the recovery key, then a new passphrase twice (the same as `passphrase --recovery`); the recovery key stays valid |
| `backup create <folder> [--keep N]` | Writes an encrypted backup of the vault as last saved into the folder (created owner-only), then keeps the newest `N` (default 10) |
| `backup verify <file>` | Checks a backup is intact, authentic and fully readable with the passphrase it was made with; writes nothing |
| `restore <file> [--overwrite]` | Verifies the backup, then installs it at the vault path; an existing vault is replaced only with `--overwrite` and kept as `<vault>.bak.1`. The restored vault opens with the passphrase and recovery key it had when the backup was made |
| `help`, `help <command> [<sub>]`, `--help`, `-h`, `<command> [<sub>] --help` | Prints the usage, grouped by area, or one command's help; exits 0 |
| `--version` | Prints `pm <version>` |

### Keys in the app

| Key | Where | Does |
| --- | --- | --- |
| Enter | Unlock | Unlocks with the passphrase (Tab reaches "Use recovery key") |
| Type | Dashboard | Filters the list live |
| ↑ ↓, Enter | Dashboard | Selects a record and opens its card (secrets stay masked) |
| Tab, Enter | Card | Reveal (masked again after 15 s), Copy (cleared from the clipboard after 30 s or on lock; macOS only in v1), Edit (logins and Wi-Fi networks), Delete, Close |
| Ctrl+N | Dashboard | New login |
| Ctrl+L | Dashboard | Locks now |
| Ctrl+T | Dashboard | Tools: password generator, health report, ssh-agent actions on the selected SSH key, new Wi-Fi network, change passphrase |
| Ctrl+S | Dashboard | Shares the selected item with a paired device |
| Ctrl+D | Dashboard | Devices: this device, paired devices, pairing |
| Esc | Dashboard, cards | Clears the search, or closes the card or dialog (cancel) |
| Ctrl+X | Everywhere | Locks and quits |

The header counts down to the idle lock: its meter drains from green through amber to red and
pulses in the last 30 seconds. Colors use the 256-color palette, which macOS Terminal and other
common terminals support. Ctrl+X quits rather than Ctrl+Q, because many terminals
use Ctrl+Q and Ctrl+S for flow control.

**A real terminal is required.** Passphrases are read only through `System.console()`. When stdin
or stdout is not a terminal (a pipe, CI, an IDE run window), every command prints
`interactive terminal required` and exits with 2, except `generate`, `help`, `--help` and
`--version`, which read nothing and also run without a terminal. To test the other commands from a
script, run them under a pseudo-terminal, for example `script -q /dev/null scripts/pm list` or
`expect`.

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
| 2 | Usage error, no interactive terminal, `init` on a path that already holds a vault, or `restore` onto a vault without `--overwrite` |
| 3 | Vault file corrupt, tampered with, or an unsupported format version; for `backup verify` and `restore`, the backup file |
| 4 | Storage error, no vault at the path, or the vault is locked by another process |
| 5 | Internal error (a bug; only "internal error" is printed, never a stack trace) |
| 6 | `init` created the vault but could not show the recovery key: delete the new vault file and run `init` again |
| 7 | Not enough Java heap for the vault's Argon2id memory: restart with a larger `-Xmx` (the vault is intact) |
| 8 | `env run`: the approval was denied, timed out, or the vault was locked; nothing ran. `rm`: not confirmed; nothing was removed |
| 9 | A service outside pm failed: no `ssh-agent` (`SSH_AUTH_SOCK` unset or nothing listening), an unsafe agent socket, the agent refused, sent a bad reply or did not answer within 10 seconds; or the `health --breach` service failed |
| 10 | A LAN step did not complete: `pair` was not confirmed, failed or is locked out after repeated failures, a `share` window expired or was revoked (also when the target device was removed), or `receive` found no paired peer, was refused or got an item that did not match the offer. Nothing was pinned or applied |
| 11 | The change was made (or the item sent) but its audit log entry could not be written: `passphrase`, `recover`, `pair`, a delivered `share`, `receive`, `revoke`. Do not retry the change |

## Status and known limitations (1.0.0)

The full gate is green with 0 findings. CI (`.github/workflows/ci.yml`) is started by hand
(`gh workflow run ci.yml --ref main`) and runs the gate on Ubuntu, macOS and Windows.

What v1 does not do, and the risks it accepts, are recorded rather than hidden:

- No passkeys: pm does not act as a WebAuthn authenticator and stores no passkeys (ADR 0016, v1
  addendum).
- Installers are not signed or notarized (R-008). Check `SHA256SUMS`.
- Copy in the app works on macOS only; a clipboard manager can keep its own copy (R-012).
- Only macOS is exercised by hand; Windows and Linux rely on the CI matrix, and their native
  installers have never been built ([platform matrix](docs/platform-matrix.md)). The Linux and
  macOS CI gates pass; the Windows gate fails because the test suites assume POSIX, so Windows is
  built but not verified (R-014).
- Vaults with 1 GiB Argon2 memory need `PM_JAVA_OPTS=-Xmx1200m` (exit 7 otherwise; ADR 0007).
- Lanterna 3.1.3 is pinned by checksum only: its signing key (94483BA5F4740C42) is not on any
  public keyserver.
- No dependency vulnerability scan runs: OWASP Dependency-Check needs an NVD API key that has not
  been provisioned. Dependencies are pinned by checksum in `gradle/verification-metadata.xml`.
- Process gaps (no branch protection, private vulnerability reporting off, no external review of
  the LAN SAS, no real-browser test) are listed in the
  [security review record](docs/security/security-review-record.md). Accepted risks are in the
  [risk register](docs/security/risk-register.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): RULES.md compliance, ADR before code, a fuzz harness for
every new input, a CERT exception row for every suppression, and the gate output in every PR.
Security problems go through [SECURITY.md](SECURITY.md), not public issues.
