# pm 1.0.0 release notes

pm 1.0.0 is the first release of pm, a local, offline password manager for one person on their
own machines. This file says what 1.0.0 contains, what it leaves out, and what a user must know
before trusting it with secrets. How to use it is in the [user guide](../user-guide.md).

## What is in 1.0.0

- **Vault:** one encrypted file (Argon2id, AES key wrap, AES-256-GCM), a recovery key shown
  once, `.bak` rotation, owner-only files, tamper detection, format migration, passphrase change
  and recovery, encrypted backups with `backup verify` and `restore`.
- **Items:** logins, Wi-Fi networks, SSH keys and per-project environment variables.
- **CLI (`pm`):** every command in the [README command table](../../README.md#commands), with
  `--help` on each, and `--version`.
- **Full-screen app:** unlock, live search, item cards with Reveal (masked again after 15 s),
  Copy with a clipboard clear (macOS), Edit and Delete, new login and Wi-Fi network, passphrase
  change, generator, health report, ssh-agent actions, devices, sharing, approvals, and an idle
  lock after 5 minutes.
- **Approvals:** `pm env run` and every browser-extension request need a yes in the open app (or
  a time-limited policy you created); shares and receives need a typed `y`; `ssh add`,
  `ssh export` and `env export` run only when you unlock the vault for that command. Every
  release is written first to a hash-chained audit log that stays intact under concurrent
  writers.
- **Tools:** password and passphrase generator, offline health report, and an optional breach
  check against the Pwned Passwords range API (k-anonymity, 5 hex characters sent).
- **SSH:** import of unencrypted Ed25519 and ECDSA P-256 keys, add to and remove from ssh-agent
  (including the macOS launchd agent), export to a new owner-only file.
- **LAN:** pairing over TLS 1.3 with Ed25519 certificates and a 6-digit code, one-time shares to
  a paired device or to a browser through a one-time HTTPS link, revocation, unpairing.
- **Browser extension** (Chrome, Chromium, Edge, Brave; loaded unpacked): fill, save and
  generate on the exact origin a login was saved for, each request approved in the open app.

## What is not in 1.0.0

- **No passkeys.** pm does not act as a WebAuthn authenticator and stores no passkeys. The
  browser's, the OS's and hardware keys' own passkeys keep working. The passkey code in the tree
  is unreachable, and ArchUnit rules keep it that way ([ADR 0016](../adr/0016-passkeys-crypto.md),
  v1 addendum).
- No OS keychain unlock, no FIDO2 unlock, no lock on system sleep (the idle lock still runs).
- No Firefox or Safari extension, and no Chrome Web Store listing.
- Copy in the app works only on macOS. On Linux and Windows, Reveal works and Copy says the
  clipboard is not available.
- No ssh-agent support on Windows (named pipes).
- No device discovery on the LAN: you type the other device's address.

## Before you trust it

- **Choose a strong passphrase.** pm does not rate or refuse a weak master passphrase; only an
  empty one is refused (R-013). Argon2id slows guessing, but a short passphrase on a stolen vault
  file or backup can still be brute-forced. Use a long passphrase, for example from
  `pm generate --passphrase --words 6`.
- **Unsigned.** The archives, the `.dmg` and the `.pkg` are not code-signed or notarized, and
  `SHA256SUMS` is not signed (R-008). Check the hashes; macOS Gatekeeper warns.
- **Platforms.** Only macOS (arm64) was exercised by hand. Windows and Linux are covered by the
  CI matrix, and their native installers were never built ([platform matrix](../platform-matrix.md)).
  The Linux and macOS CI gates pass. The Windows gate fails because the test suites assume POSIX,
  so Windows is built but not verified (R-014).
- **Internal review only.** Every security phase had an adversarial review by a team member who
  had not written it, but there has been no external audit. The LAN code comparison (SAS) did not
  get its planned external cryptographic review ([security review record](../security/security-review-record.md)).
- **Accepted risks** are in the [risk register](../security/risk-register.md). The ones a user
  meets: malware running as you can read what an unlocked pm can read (R-001); Java cannot
  promise to erase every copy of a secret in memory (R-003); a shared secret cannot be recalled
  (R-005); a same-user program can reach the browser relay socket, though every release still
  needs a yes (R-011); a copied password is readable by every program, and a clipboard manager
  can keep it until pm clears it (R-012).
- **No dependency vulnerability scan.** OWASP Dependency-Check is not wired, because it needs an
  NVD API key. Every dependency is pinned by checksum in `gradle/verification-metadata.xml`.
  Lanterna 3.1.3 is pinned by checksum only, because its signing key is on no public keyserver.

## Requirements

- To run a release archive: nothing else; it brings its own Java runtime.
- To build: JDK 21, and `semgrep` 1.176.0 and `gitleaks` 8.30.1 on `PATH` for the gate.
- A terminal of at least 80×24. pm refuses to read a passphrase without a real terminal.
- A vault created with 1 GiB of Argon2 memory needs `PM_JAVA_OPTS=-Xmx1200m` when run from source.

## Third-party components

- Bouncy Castle (`bcprov-jdk18on` 1.86), MIT-style Bouncy Castle licence.
- Lanterna 3.1.3, LGPL-3.0.
- The Public Suffix List, MPL-2.0, shipped unchanged with its notice
  (`modules/pm-browser/src/main/resources/pm/browser/webauthn/public_suffix_list.NOTICE`); it is
  read only by the passkey code, which v1 does not reach.

The SBOM (`pm-1.0.0.cdx.json`, written by `./gradlew release`) lists every shipped jar with its
SHA-256.

## Reporting a security problem

See [SECURITY.md](../../SECURITY.md). Do not open a public issue with details.
