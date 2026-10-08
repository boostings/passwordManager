# pm user guide

pm is a local password manager for one person on their own machines. It keeps logins, Wi-Fi
networks, SSH keys and per-project environment variables in one encrypted file, and it gives a
secret to another program only after you approve it. Nothing is stored on a server. There is no
account and no sync service.

This guide covers v1. For the full command list, see `pm help` or the
[README command table](../README.md#commands). The [platform matrix](platform-matrix.md) shows
what runs where. To report a security problem, see [SECURITY.md](../SECURITY.md).

## What pm protects, and what it does not

- **Protected:** the vault file at rest. It is encrypted with AES-256-GCM under a vault key that
  is wrapped twice: once under your passphrase (through Argon2id) and once under the recovery
  key.
  Changed or truncated files are detected and refused. Someone who copies your vault file or a
  backup learns nothing without your passphrase or recovery key.
- **Protected:** releases. A secret leaves the vault for a command, an ssh-agent, a browser page
  or another device only after you say yes: at a prompt, through a time-limited policy you
  created, or by unlocking the vault to run that one command (`ssh add`, `ssh export`,
  `env export`). Each release is written to a hash-chained audit log first.
- **Not protected:** a machine that is already compromised. Malware running as you, or as an
  administrator, while the vault is unlocked can read what pm can read
  ([threat model](security/threat-model.md), R-001). Java also cannot promise that every copy of
  a secret in memory is erased (R-003).
- **Not protected:** a secret once you have given it away. A shared password, an exported file,
  or a value passed to `pm env run` is out of pm's hands. Change the secret if you are unsure.

## Install

pm needs a JDK 21 to build. The release archives bring their own Java runtime.

**From source (macOS, Linux):**

```sh
scripts/install-pm          # links pm into ~/.local/bin and builds once
pm --version
```

`PM_JAVA_HOME` selects the JDK. The default is `/opt/homebrew/opt/openjdk@21`, falling back to
`$JAVA_HOME`.

**Release archive:** `./gradlew release` writes `pm-<version>-<os>-<arch>.tar.gz` and `.zip`, the
macOS `.dmg` and `.pkg`, an SBOM and `SHA256SUMS` to `modules/pm-cli/build/release/dist/`
([packaging](release/packaging.md)). Check the hashes before you install:

```sh
cd modules/pm-cli/build/release/dist && shasum -a 256 -c SHA256SUMS
```

v1 installers are **not signed or notarized**. macOS Gatekeeper warns about them, and the hash
manifest is the only integrity check.

pm reads passphrases only from a real terminal. In a pipe, a CI job or an IDE run window, every
command prints `interactive terminal required` and exits with 2, except `generate`, `help`,
`--help` and `--version`.

## First run

```sh
pm
```

On the first run pm asks for a new passphrase twice and creates the vault. pm does not refuse a
weak passphrase, so choose a long one: `pm generate --passphrase --words 6` makes one. It then prints the
**recovery key once**. Write the key down and keep it offline, away from the machine. It is the
only way back in if you forget the passphrase; nobody, the developers included, can recover a
vault without one of the two. Press Enter, and the app opens at the unlock screen.

The vault is a single file:

| OS | Default path |
| --- | --- |
| macOS | `~/Library/Application Support/pm/vault.pmv` |
| Linux | `~/.local/share/pm/vault.pmv` |
| Windows | `~\AppData\Roaming\pm\vault.pmv` |

`--vault <path>`, placed before the command word, uses another file. A leading `~` is refused
rather than expanded.

Next to the vault, pm keeps:
- `vault.pmv.bak.1` to `.bak.3`: the last three saved versions.
- `vault.pmv.lock`.
- `audit.log` and `audit.log.head`: the release log, made the first time something is released.

Every file is owner-only.

## The full-screen app

`pm` (or `pm tui`) opens the app. It locks itself after 5 minutes without input, and the header
counts down to that lock.

| Key | Does |
| --- | --- |
| type | filter the list |
| ↑ ↓, Enter | open an item's card (secrets stay masked) |
| Ctrl+N | new login |
| Ctrl+T | tools: generator, health report, ssh-agent actions on the selected SSH key, new Wi-Fi network, change passphrase |
| Ctrl+S | share the selected item with a paired device |
| Ctrl+D | devices: this device, paired devices, pairing |
| Ctrl+L | lock now |
| Esc | clear the search, or close a card or dialog |
| Ctrl+X | lock and quit |

An item's card has buttons (Tab moves between them, Enter presses one):

- **Reveal** shows a login's or Wi-Fi network's password for 15 seconds, then masks it again; so
  do Hide, Close and every lock. A password containing control or invisible characters is not
  shown.
- **Copy** puts the password on the clipboard and clears it after 30 seconds, when pm locks, or
  when you quit. If you copied something else in the meantime, pm leaves that alone.
  `PM_CLIPBOARD_CLEAR=<seconds>` (5 to 300) changes the 30 seconds. Copy works on macOS in v1; on
  Linux and Windows the card says the clipboard is not available, and Reveal still works.
  A clipboard manager can keep its own copy, and pm cannot clear the clipboard if it is killed.
- **Edit** (logins and Wi-Fi networks) changes the fields; leave the password empty to keep it.
- **Delete** asks first, as `pm rm` does.

While the app is unlocked it is also the place where requests from `pm env run` and the browser
extension are approved (see "Approvals" below).

## Logins and Wi-Fi networks

```sh
pm add-login                       # prompts for title, username, password, URLs, tags
pm wifi add HomeNet --security WPA3
pm list                            # id, type, title, last change; never a secret
pm search mail
pm show "Example mail"             # the password is shown as ********
pm show "Example mail" --reveal    # prints the password; the only command that does
pm edit "Example mail" --password  # asks for the new password twice
pm edit "Example mail" --generate --length 24
pm rm "Example mail"               # asks you to type y; --yes skips the question
```

`<item>` is a title or the id that `pm list` shows. Passwords are typed at a hidden prompt,
never on the command line.

`pm generate` prints a random password (or `--passphrase` words) and needs no vault. The secret
goes to stdout and its entropy to stderr, so `pm generate | pbcopy` copies only the secret.

`pm health` reports weak, reused and old passwords, offline. With `--breach`, after you type y,
it also checks them against the Pwned Passwords range API. Only the first 5 hex characters of
each password's SHA-1 hash are sent.

## Changing the passphrase, and the recovery key

```sh
pm passphrase               # current passphrase, then the new one twice
pm recover                  # lost passphrase: the recovery key, then a new passphrase twice
```

In the app, Ctrl+T then "Change passphrase" does the same; it accepts the current passphrase or
the recovery key. Your items and the recovery key stay the same. Earlier `.bak` files and
backups still open with the **old** passphrase. If the old passphrase may be known to someone, make a new backup and
then delete the old ones.

## Backups

```sh
pm backup create /Volumes/USB/pm-backups    # keeps the newest 10 there; --keep <n>
pm backup verify /Volumes/USB/pm-backups/pm-backup-<time>-000.pmbackup
pm restore <file>                           # refuses to replace a vault without --overwrite
pm restore <file> --overwrite               # the replaced vault is kept as <vault>.bak.1
```

A backup is encrypted like the vault. `backup verify` checks that a backup is intact, authentic
and fully readable, and writes nothing. A restored vault opens with the passphrase and recovery
key **it had when the backup was made**. Keep your backups somewhere other than the machine.

## Projects and environment variables

pm stores a project's `.env` values in the vault and hands them only to the one command you
approve, never to a file:

```sh
cd ~/code/app
pm project add app                     # this directory is the project "app"
pm env import .env                     # then delete the plaintext .env file
pm env import .env.staging --profile staging
pm env list --profile staging          # names only
pm env run -- npm start                # approve, then the command runs with the variables
pm env run --only DATABASE_URL -- ./migrate
```

The approval prompt shows the exact command and the variable names. If the app is open and
unlocked, the prompt appears there. Otherwise `pm env run` asks in the terminal, where you type
y. A refusal exits with 8, and nothing runs.

`pm env import` warns when the file sits in a git working tree and is not ignored.
`pm env export <file> --plaintext` writes a new owner-only `.env` file and never overwrites one.

## SSH keys

```sh
pm ssh import ~/.ssh/id_ed25519 --title "work laptop"   # Ed25519 or ECDSA P-256, unencrypted
pm ssh add "work laptop" --lifetime 8h --confirm        # into the running ssh-agent
pm ssh list
pm ssh remove "work laptop"        # or --all
pm ssh export "work laptop" ./id   # new owner-only file; never overwrites
```

After the import works, delete the plaintext key file. Releases to the agent and exports are
written to the audit log first. pm checks that `SSH_AUTH_SOCK` is a socket owned by you, in a
folder owned by you (or root) that no one else can write to. On macOS, the system's own launchd ssh-agent is accepted.

## Sharing with your other devices

Both devices must be on the same local network and running pm.

```sh
# device A                               # device B
pm pair --listen                         pm pair 192.168.1.20:<port shown on A>
# both screens show a 6-digit code: compare them, then type y on both sides
pm share "Example mail" --to laptop      pm receive 192.168.1.20:<port>
pm revoke <share-id>                     # closes an open share window early
pm devices                               # this device and the paired ones
pm devices remove laptop                 # unpair; lists what was offered to it
```

A share is offered once and is open for 10 minutes by default (`--ttl`, at most 24 hours). After
one delivery, or when the time is up, the window closes. Revoking cannot recall a copy that was
already received (R-005). When you unpair a device, change the secrets it was given.

`pm share <title> --browser` gives a one-time HTTPS link for a device that has no pm. The page
warns about pm's self-signed certificate, so compare the certificate fingerprint that pm prints
with the one the browser shows.

## Browser extension (Chrome, Chromium, Edge, Brave)

The extension fills, saves and generates logins on the exact site where you saved them. Every
fill and every save needs your yes in the open, unlocked pm app.

1. Open `chrome://extensions`, turn on Developer mode, and choose "Load unpacked" with the
   `extension/src` folder. Note the extension's ID.
2. `pm browser install --extension-id <that ID>`. This registers pm's native messaging host for
   this user and allows only that extension. `pm browser status` shows what is installed.
3. Keep `pm` open and unlocked. In the extension's popup, choose fill, save or generate, then
   approve the request in pm. The prompt shows the exact site origin.

The extension is not in the Chrome Web Store for v1. `pm browser install` writes manifests on
macOS and Linux; on Windows it prints the registry steps to do by hand. A login is offered only
to its exact origin, so `https://login.example.com` never receives a login saved for
`https://example.com`, and `http://` or another port does not match either. pm never fills into
a frame.

### Passkeys

**pm v1 does not create, store or use passkeys.** It does not act as a WebAuthn authenticator in
the browser, and the extension contains no WebAuthn code. Your browser's and operating system's
own passkeys, and hardware security keys, keep working exactly as before. pm does not interfere
with them ([ADR 0016](adr/0016-passkeys-crypto.md), v1 addendum).

## Approvals and the audit log

Every release asks a question that names who is asking, what they want and for how long:

- **Once:** one release.
- **This session:** the same requester and scope are released without asking again until pm
  locks.
- **For a time:** the same, for a time you choose, up to 24 hours, even across locks.
- **Deny.**

Session and timed answers are never offered for exports or shares. Prompts in the app ignore
keys for the first 500 ms, so a key pressed by accident cannot approve them. Locking pm cancels
every open prompt and every session answer.

The audit log is hash-chained. If it has been edited, cut short or forked, pm refuses to release
anything and says which entry is wrong; it does not repair the log on its own. See
[approval-model §7](security/approval-model.md) for recovery steps.

## When something goes wrong

| Message or exit code | What to do |
| --- | --- |
| 1, wrong passphrase or recovery key | Try again. Each attempt costs one full Argon2id derivation |
| 3, corrupt or tampered | Do not overwrite anything. Try the newest `vault.pmv.bak.N` with `--vault`, or `pm restore` a verified backup |
| 4, vault locked by another process | Close the other pm, or wait for it to finish |
| 7, not enough Java heap | A vault with 1 GiB Argon2 memory needs `PM_JAVA_OPTS=-Xmx1200m`. The vault is intact |
| 9, ssh-agent or breach service | Start an agent and check `SSH_AUTH_SOCK`, or retry the breach check later |
| 11, change made but not audited | The change was made. Do not repeat it; fix the audit log first |

The README lists every exit code. pm never prints a stack trace; "internal error" (exit 5) is a
bug, and you can report it as an ordinary issue unless it exposes a secret.
