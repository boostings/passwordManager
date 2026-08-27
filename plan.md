# passwordManager: A–Z Project Plan

## Project status

This is a planning document only. The repository is private, the working name is
`passwordManager`, and implementation has not started.

## A — Aim

Build a cross-platform Java TUI password manager for nontechnical users who prefer
terminal workflows and for AI agents that need controlled, auditable access to
secrets.

The defining workflow is secure environment-variable sharing between projects and
nearby devices. The product is local-first, with no cloud account or required
central service.

## B — Boundaries

### In scope

- One encrypted vault per user
- macOS, Windows, and Linux
- Full-screen keyboard-first TUI
- Login credentials
- Passkeys
- Wi-Fi credentials
- SSH keys
- Project environment variables
- Password generation and health checks
- Explicitly approved LAN sharing
- Browser-based receiving
- Browser extension integration
- Agent access with human approval
- Encrypted backups

### Out of scope initially

- Cloud synchronization
- Multi-user accounts
- Automatic public sharing
- Secret access without an approval policy
- Plaintext vault files
- Passwords or secrets in logs

These are boundaries for the initial product, not necessarily permanent limits.

## C — Core user journeys

### First vault

1. User launches the application.
2. A guided wizard creates the vault.
3. User creates a strong master passphrase.
4. User configures optional OS-keychain and hardware-key unlock methods.
5. The app generates a recovery key.
6. The user confirms that the recovery key was safely stored.
7. The app opens the dashboard with a short guided tutorial.

### Environment workflow

1. User registers a project by selecting its Git root or directory.
2. User creates profiles such as `development`, `staging`, and `production`.
3. User adds environment variables.
4. User runs a command without writing secrets to disk:

   ```text
   passwordManager env run my-project -- npm start
   ```

5. The TUI displays the command, project, profile, and requested scope.
6. The user approves or denies the request.
7. The child process receives variables in memory through its environment.

### LAN sharing

1. User selects a secret or project.
2. User starts a share and chooses a nearby paired device or browser recipient.
3. A short-lived pairing code or QR code is shown.
4. The recipient explicitly approves the pairing.
5. The sender explicitly approves the transfer.
6. The payload is encrypted end-to-end.
7. The recipient receives the secret or project.
8. The share expires after one use or its configured lifetime.
9. The sender can revoke future access and revoke the device.

### Browser workflow

The browser extension should support credential lookup, autofill, password
generation, saving credentials, and passkey operations where the target browser
supports the required WebAuthn integration.

## D — Data model

The vault should contain typed records rather than an unstructured password list.

### Login record

- Title
- Username
- Password
- Website URLs
- Notes
- Tags
- Created, updated, and last-used timestamps
- Password health metadata

### Passkey record

- Display name
- Relying-party ID
- Relying-party name
- User name and user handle
- Credential ID
- Credential private key material
- Signature counter
- Supported transports and algorithm metadata
- Creation and last-used timestamps

Passkeys must never be treated as ordinary password fields.

### Wi-Fi record

- Network name/SSID
- Security type
- Password
- Hidden-network flag
- Notes

### SSH-key record

- Key type
- Private key
- Public key
- Fingerprint
- Comment
- Associated hosts
- Optional passphrase reference
- Agent usage settings

### Project record

- Project name
- Canonical filesystem path
- Git repository identity when available
- Environment profiles
- Variable names and encrypted values
- Non-secret configuration values
- Sharing and approval policies

### Device and share records

Device identities, pairing status, expiration settings, and revocation metadata
should be stored with authenticated integrity. No secret value should be stored
outside the encrypted vault unless the user explicitly exports it.

## E — Encryption

Use established cryptographic libraries and Java security APIs. Do not implement
cryptographic primitives manually.

Recommended model:

1. Generate a random vault encryption key.
2. Encrypt vault contents with an authenticated cipher such as AES-256-GCM or
   ChaCha20-Poly1305.
3. Derive a key-encryption key from the master passphrase using Argon2id.
4. Store a separately encrypted key slot for each enabled unlock method.
5. Include the vault format version, KDF parameters, salts, and nonces in the
   authenticated vault envelope.
6. Keep all secret-bearing metadata inside the encrypted payload.

The exact Argon2id parameters should be selected through startup-time benchmarking
on supported hardware and reviewed before release.

The vault file must use authenticated encryption so tampering is detected before
records are opened.

## F — First-run experience

The first-run wizard should be approachable to a nontechnical user:

- Explain what the vault protects.
- Ask for a master passphrase with strength feedback.
- Offer OS-keychain unlock.
- Offer hardware-key setup when supported.
- Generate a recovery key and require confirmation.
- Explain clipboard clearing and automatic locking.
- Offer to import an existing `.env` file later.
- Show a small tutorial for Vault, Projects, Health, Devices, and Settings.

The user should be able to skip advanced integrations and return to setup later.

## G — Governance and repository practice

The GitHub repository remains private during development.

Recommended repository rules:

- Protect the `main` branch.
- Require passing tests before merging.
- Require review for cryptography, sharing, and browser changes.
- Treat the repository's `RULES.md` as the secure Java implementation baseline.
- Never commit real credentials, vault files, recovery keys, test secrets, or
  exported `.env` files.
- Keep sample data obviously fake.
- Add automated secret scanning and dependency checks.
- Record security decisions in an architecture decision log.

Do not add a public license until the project’s distribution decision is made.

## H — Hardware and unlock methods

Support multiple unlock methods for one vault through independent key slots.

### Initial unlock options

- Master passphrase
- OS keychain integration

### Hardware-key option

Use a standards-based FIDO2 mechanism such as a supported PRF or HMAC-secret
capability when available. If reliable cross-platform support is not possible, the
hardware key should act as an additional factor rather than pretending to be a
universal standalone decryption key.

The product must clearly show which unlock methods are configured and what fallback
is available.

## I — Integrations

Planned integrations include:

- OS keychains
- FIDO2 security keys
- Browser extension APIs
- Native browser messaging
- WebAuthn/passkey flows
- `ssh-agent`
- Git repository detection
- Online compromised-password services
- Public breach databases using privacy-preserving queries

Each integration should have a provider interface so platform-specific code does
not leak into vault or TUI logic.

## J — Java architecture

Use a modular Java application with a current supported Java LTS selected when
implementation begins.

Recommended layers:

```text
TUI and browser-facing commands
            |
Application services and approval workflows
            |
Vault, project, sharing, and health domain logic
            |
Crypto, storage, platform, and network adapters
```

Recommended components:

- Gradle for builds and dependency management
- Lanterna or an equivalent mature Java TUI library
- Java Cryptography Architecture for standard primitives
- An audited Argon2id implementation
- Structured serialization with a versioned schema
- JUnit and property-based testing
- `jpackage` for bundled-runtime installers

The TUI should remain independent from storage and cryptography so those systems
can be tested without terminal automation.

## K — Key lifecycle

Key lifecycle rules:

- Generate vault keys with a secure random source.
- Never derive the vault key directly from a password.
- Wrap the vault key separately for each unlock method.
- Never log keys, passphrases, recovery codes, or decrypted records.
- Rotate a wrapping key when an unlock method changes.
- Support removing a lost device or security key.
- Require the vault to be unlocked before adding or removing unlock methods.
- Make recovery-key regeneration a deliberate vault-key rotation operation, not a
  casual settings action.

Java memory clearing is best-effort. The design should minimize plaintext lifetime
and avoid unnecessary copies, while documenting that a fully compromised operating
system can inspect process memory.

## L — LAN protocol

LAN sharing should be peer-to-peer and require explicit approval.

### Pairing

- Generate a per-device identity key pair.
- Discover devices through local discovery where available.
- Provide manual pairing-code entry as a fallback.
- Display device name, platform, and identity fingerprint.
- Require approval on both devices.
- Store the resulting trust relationship inside the vault.

### Transfer

- Establish an authenticated encrypted session.
- Transfer only the selected secret or project.
- Use short-lived share identifiers.
- Require recipient confirmation before decryption.
- Support one-use and time-limited shares.
- Keep an audit record without recording secret values.

### Browser-only receiving

A browser recipient should receive a short-lived local HTTPS share page. The page
should hold decrypted content only in browser memory, offer a one-time view and an
optional encrypted package download, and expire automatically.

The sender must be warned that a recipient can copy a secret after receiving it;
revocation cannot erase an already copied value.

## M — Milestones

### M0: Product and security design

- Threat model
- Vault format
- Key hierarchy
- Approval model
- LAN protocol design
- Browser feasibility spike
- Supported-platform matrix

### M1: Local vault foundation

- Create, unlock, lock, and save a vault
- Master passphrase
- Recovery key
- Login, Wi-Fi, SSH, and project records
- TUI dashboard and search
- Automatic locking

### M2: Environment sharing priority

- Project registration
- Environment profiles
- `.env` import
- In-memory process injection
- Explicit `.env` export
- Agent request and TUI approval flow
- Git leakage warnings

### M3: LAN sharing

- Device identities
- Pairing and approval
- Individual secret sharing
- Project sharing
- Expiration and one-use shares
- Revocation and device management
- Browser-only receiving

### M4: Health and SSH workflows

- Password generation
- Weak, reused, old, and compromised checks
- Privacy-preserving online checks
- SSH-agent integration
- Explicit key export fallback

### M5: Browser extension

- Native messaging bridge
- Autofill
- Credential saving
- Browser password generation
- TUI approval integration

### M6: Passkeys

- Passkey enrollment
- Passkey authentication
- Vault-backed WebAuthn operations
- Browser support matrix
- Platform-specific limitations
- Hardware-backed alternatives

### M7: Release hardening

- Cross-platform packaging
- Migration support
- Backup and restore validation
- Security review
- Installer testing
- Documentation and support materials

## N — Nonfunctional requirements

### Security

- No plaintext vault storage
- No secret values in logs
- Fail closed on authentication or approval errors
- Detect vault tampering
- Explicit consent for all sharing

### Reliability

- Atomic writes
- Recovery from interrupted writes
- Safe backup rotation
- Clear corruption errors
- Versioned migrations

### Usability

- Fast launch
- Responsive TUI while searching and navigating
- Consistent shortcuts
- Clear locked/unlocked state
- Useful errors in plain language

### Privacy

- No telemetry by default
- No required account
- No central secret service
- Minimal network access
- Transparent online-check behavior

## O — Operations

The application should operate without a server for local use.

Operational components:

- TUI process
- Local approval broker
- Optional native browser-messaging host
- Optional LAN listener active only during sharing

The LAN listener should not run continuously unless explicitly enabled. It should
bind narrowly, use authenticated sessions, shut down after expiration, and produce
diagnostic information without secret contents.

Provide commands for safe diagnostics, such as checking installation, keychain
availability, browser bridge status, and paired-device status.

## P — Passkeys

Passkey support is the highest-risk integration and should follow a dedicated
feasibility milestone.

The vault-backed passkey design must address:

- WebAuthn registration
- WebAuthn authentication
- Credential private-key protection
- Relying-party identifiers
- User handles
- Signature counters
- Browser extension APIs
- Native messaging
- Platform authenticator conflicts
- Hardware-backed passkeys
- Credential backup and migration

The product must never claim universal passkey support until it is tested against
the documented browser and operating-system matrix. Unsupported browsers should
fail clearly and offer a safe fallback.

## Q — Quality strategy

### Unit tests

- Key derivation and wrapping
- Encryption and tamper detection
- Record serialization
- Vault locking
- Password generation
- Environment merging
- Expiration rules

### Property tests

- Serialize/decrypt/deserialize round trips
- Random record combinations
- Corrupted vault inputs
- Migration compatibility
- Environment profile precedence

### Integration tests

- Vault lifecycle
- OS keychain adapters
- Security-key adapters
- Agent approval broker
- LAN pairing and transfers
- Browser native messaging
- SSH-agent integration

### Security tests

- Malformed vault files
- Replay attempts
- Pairing-code reuse
- Expired shares
- Unauthorized device access
- Log and error redaction
- Clipboard clearing
- Temporary-file cleanup

### Manual tests

- Fresh install on all platforms
- Terminal resizing
- Slow and unusual terminals
- Locked-state navigation
- Keyboard-only workflows
- Browser extension behavior
- Recovery procedure

## R — Recovery and backup

The recovery key is the only supported recovery path if the master passphrase is
lost.

Recovery setup should:

- Generate high-entropy random material
- Display it once during setup
- Provide a printable or copyable representation with warnings
- Require confirmation before continuing
- Explain that the developers cannot recover the vault

Backups should be encrypted exports containing the vault and format metadata, never
plaintext records. Automatic backups should use a user-selected local directory and
retain a bounded number of previous versions.

Restore must create a new local vault copy first rather than overwriting the active
vault immediately.

## S — Sharing and approvals

All sensitive actions should use a common approval model.

Approval request fields:

- Requesting process or agent
- Device identity
- Requested operation
- Project or record scope
- Exact command when applicable
- Duration
- Whether secrets will be displayed, exported, or only injected

Approval options:

- Approve once
- Approve for the current session
- Approve for a narrowly scoped temporary policy
- Deny

The default should be approve-once and fail closed. A policy should never silently
expand from one project or variable to the entire vault.

## T — TUI design

The TUI should combine a dashboard with focused full-screen modes.

```text
Dashboard
├── Vault
├── Projects
├── Password Health
├── Devices
├── Shares
└── Settings
```

### Navigation

- Arrow keys and Enter for standard navigation
- Search available from every major screen
- Consistent Escape behavior
- Clear confirmation dialogs
- Shortcut hints visible in context
- Optional mouse support where useful

### Dashboard priorities

All major areas should have equal access, while the dashboard highlights:

- Vault lock state
- Pending approvals
- Project environment status
- Password-health summary
- Active shares
- Paired devices

Secret values should be masked by default and revealed only through deliberate
interaction.

## U — Updates and migrations

Use a versioned vault format from the first implementation.

Updates should:

- Verify package integrity
- Preserve vault compatibility
- Make a backup before migration
- Validate the migrated vault
- Allow rollback to the previous backup
- Explain changes in plain language

Automatic update checks should be opt-in or privacy-preserving. The app must remain
usable offline.

## V — Verification and release gates

No release should be considered complete based only on compiling successfully.

### Required gates

- Unit and integration tests pass
- Cross-platform build succeeds
- Vault corruption and recovery tests pass
- No secrets appear in logs or artifacts
- LAN pairing requires approval on both sides
- Expired shares cannot be opened
- Revoked devices cannot start new transfers
- Agent requests require the intended approval
- `.env` export is explicit and warning-protected
- Browser bridge failure is safe and understandable
- Security review has no unresolved critical or high-severity findings

Browser, hardware-key, and platform-provider behavior must be verified on real
supported environments rather than inferred from source code.

## W — Windows, macOS, and Linux

Use one shared domain and application layer with platform adapters for:

- OS keychains
- Secure credential storage
- Process and environment behavior
- File permissions
- Native messaging registration
- Installers
- Terminal behavior

Package with a bundled Java runtime so users do not need to install Java manually.
Use platform-native installers produced through a reproducible build process.

The exact supported Java LTS version should be selected when implementation begins
and kept consistent across development, CI, and release builds.

## X — Exceptions and failure modes

The application should fail safely and explain what happened.

Examples:

- Wrong passphrase: do not reveal whether the vault exists beyond necessary UI
  behavior.
- Corrupt vault: refuse to open and suggest restoring a backup.
- Lost device: revoke it from another trusted device or through recovery.
- Browser unavailable: offer manual encrypted-package transfer.
- Security key unsupported: explain the limitation and require another unlock
  method.
- LAN interrupted: do not partially apply a project or secret.
- Agent approval timeout: deny the request.
- Clipboard unavailable: keep the secret in the vault and explain the limitation.

## Y — Year-one roadmap

### Quarter 1

- Threat model and architecture
- Vault format
- Local vault
- TUI foundation
- Recovery flow

### Quarter 2

- Project environments
- In-memory `env run`
- Agent approval broker
- `.env` import/export
- Git leakage warnings

### Quarter 3

- Device pairing
- LAN secret and project sharing
- Browser-only receiving
- Expiration and revocation
- Password health
- SSH-agent support

### Quarter 4

- Browser extension
- Passkey feasibility and implementation
- Bundled-runtime installers
- Migration and backup hardening
- Security review
- Private beta release

## Z — Zero-state definition of done

The first complete product release is ready when a new user can:

1. Install the application without separately installing Java.
2. Create one encrypted vault.
3. Configure a master passphrase, recovery key, and optional alternate unlocks.
4. Register a project and add environment profiles.
5. Run a command with secrets injected without creating a file.
6. Receive and approve an agent request in the TUI.
7. Share a secret or project with another device on the same LAN.
8. Let a recipient receive a one-use share through a browser.
9. Expire or revoke the share and device.
10. Generate and assess passwords.
11. Check passwords against compromised-password services privately.
12. Use SSH keys through the supported agent integration.
13. Use browser password and passkey features on the documented support matrix.
14. Back up and restore the vault safely.
15. Lock the vault and verify that protected operations are denied.

The project should remain private while these gates are being established. No
production claims should be made until the behavior has been tested on all three
operating systems and the security review is complete.
