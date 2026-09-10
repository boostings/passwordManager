# passwordManager: End-to-End Project Plan with a Security-First SDLC

## Project status

This is a planning document only. The repository is private, the working name is
`passwordManager`, and implementation has not started.

This plan is written so that security is a required
activity in every phase of the software development life cycle (SDLC), not a
review at the end. It also makes `RULES.md` (the SEI CERT Oracle Coding Standard
for Java digest checked into this repository) a hard, enforced requirement for
every line of Java written for this project.

The document has three parts:

- **Part I — Product plan.** What we are building and why.
- **Part II — Secure SDLC.** Security requirements, activities, gates, and
  artifacts for every life-cycle phase.
- **Part III — RULES.md compliance program.** How the CERT rules are applied,
  enforced, verified, and audited.

---

# Part I — Product plan

## 1. Aim

Build a cross-platform Java TUI password manager for nontechnical users who prefer
terminal workflows and for AI agents that need controlled, auditable access to
secrets.

The defining workflow is secure environment-variable sharing between projects and
nearby devices. The product is local-first, with no cloud account or required
central service.

Security is a product feature, not an implementation detail. A user who trusts
this application with every credential they own must be able to verify, from
public artifacts, that the trust is justified.

## 2. Boundaries

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
Any change to a boundary requires a threat-model update (see Part II, Phase 2)
before implementation.

## 3. Core user journeys

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

### Abuse cases (required alongside every user journey)

Every user journey above has a matching abuse-case set maintained in
`docs/security/abuse-cases.md`. Examples that must be covered from M0:

- A malicious local process invokes `env run` and tries to harvest secrets
  without the user noticing the approval dialog.
- An attacker on the same LAN attempts to pair as a trusted device or replay a
  captured share.
- A malicious web page attempts to drive the browser extension to autofill into
  the wrong origin.
- A compromised `.env` file or vault backup is imported to trigger parser bugs.
- An AI agent requests a broader scope than the task requires and attempts to
  escalate an approve-once decision into a standing policy.

## 4. Data model

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

### Data classification

Every field in the data model is classified before implementation and the
classification is recorded in `docs/security/data-classification.md`:

| Class | Examples | Handling |
| --- | --- | --- |
| Secret | passwords, private keys, passkey keys, env values, recovery key, vault key | Never logged, never in exceptions, never in `toString()`, cleared best-effort after use, encrypted at rest always |
| Sensitive | usernames, URLs, SSIDs, project paths, device fingerprints | Encrypted at rest inside the vault, redacted from logs by default |
| Metadata | timestamps, record counts, format version, KDF parameters | May appear in the authenticated envelope header; never reveals secret content |

Classes map directly to CERT rules: `IDS15-J`, `FIO13-J`, `ERR01-J`, `SER03-J`,
`MSC03-J`, `OBJ07-J`.

## 5. Encryption

Use established cryptographic libraries and Java security APIs. Do not implement
cryptographic primitives manually.

Recommended model:

1. Generate a random vault encryption key (`MSC02-J`: `SecureRandom`, never
   `java.util.Random`).
2. Encrypt vault contents with an authenticated cipher such as AES-256-GCM or
   ChaCha20-Poly1305.
3. Derive a key-encryption key from the master passphrase using Argon2id.
4. Store a separately encrypted key slot for each enabled unlock method.
5. Include the vault format version, KDF parameters, salts, and nonces in the
   authenticated vault envelope.
6. Keep all secret-bearing metadata inside the encrypted payload.

Argon2id parameters are chosen once, at vault creation, by benchmarking the
creating machine for a target unlock time, and are stored in the authenticated
header so unlock uses exactly the stored parameters. Minimum floors are fixed in
the design (never below the OWASP Argon2id baseline) and only the "stronger"
direction is adjusted by benchmark. A "re-tune KDF" action lets the user raise
parameters later; that is a deliberate re-wrap of every key slot.

The vault file must use authenticated encryption so tampering is detected before
records are opened.

### Cryptographic engineering rules

- Nonces are never reused with the same key. The long-lived vault key is never
  used directly for bulk encryption. Every save derives a fresh per-save data key
  with HKDF from the vault key and a 256-bit random salt written into the
  envelope header, then uses a fixed nonce with that one-time key. This removes
  any dependence on persisted counters, which can repeat after a crash. As an
  alternative, XChaCha20-Poly1305 with a random 192-bit nonce is acceptable.
  Persisted nonce counters are prohibited.
- Authenticated additional data (AAD) covers the header so version and KDF
  parameters cannot be downgraded.
- Constant-time comparison for all MAC, tag, and code comparisons
  (`MessageDigest.isEqual`).
- Key material lives in `byte[]` or `char[]`, never `String` (`MSC03-J`,
  `STR03-J`), and is zeroed in `finally` blocks (`FIO04-J`, `ERR04-J`).
- All crypto goes through one `CryptoProvider` interface with one reviewed
  implementation. No other module calls `javax.crypto` directly. This is the
  only place a `Cipher` object is constructed.
- Algorithm and provider names are fixed constants, never read from user input,
  config, or environment (`ENV02-J`, `SEC02-J`).
- The vault format, key hierarchy, and every cryptographic decision are recorded
  as Architecture Decision Records (ADRs) in `docs/adr/` before code is written.

## 6. First-run experience

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

Security in first run:

- The vault file and its directory are created with owner-only permissions
  before any bytes are written (`FIO01-J`), never in a shared or temp directory
  (`FIO00-J`).
- The passphrase is read with echo disabled and never passes through a
  `String`.
- The recovery key is shown once; the display buffer is cleared on dismissal.
- Strength feedback runs locally. No network access happens during the wizard.

## 7. Governance and repository practice

The GitHub repository remains private during development.

Required repository rules:

- Protect the `main` branch: no direct pushes, linear history, signed commits.
- Require passing CI (build, tests, static analysis, dependency scan, secret
  scan) before merging.
- Require one approving review for all changes and two for changes under
  `crypto/`, `sharing/`, `browser/`, `approval/`, and `storage/` (see CODEOWNERS
  in Part II, Phase 8).
- Treat `RULES.md` as the secure Java implementation baseline. Compliance is a
  merge requirement, not advice (Part III).
- Never commit real credentials, vault files, recovery keys, test secrets, or
  exported `.env` files.
- Keep sample data obviously fake.
- Add automated secret scanning and dependency checks.
- Record security decisions in an architecture decision log.

Do not add a public license until the project's distribution decision is made.

## 8. Hardware and unlock methods

Support multiple unlock methods for one vault through independent key slots.

### Initial unlock options

- Master passphrase
- OS keychain integration

OS-keychain unlock is a convenience that weakens the model, and the threat model
and first-run wizard say so: on every platform, another process running as the
same user can generally read that keychain item (macOS ACL prompts and Linux
Secret Service prompts help but are bypassable; Windows DPAPI has no per-app
scope). Therefore:

- Keychain unlock is off by default and the wizard explains the trade-off.
- The keychain never holds the vault key, only a wrapping key for one key slot,
  so removing the keychain slot fully revokes it.
- Keychain unlock is bound to the installed application identity where the OS
  supports it (macOS code-signing requirement on the keychain item).
- Auto-lock timeouts are shorter by default when keychain unlock is enabled.
- The threat model records "local same-user malware with keychain unlock
  enabled" as an accepted, user-chosen risk.

### Hardware-key option

Use a standards-based FIDO2 mechanism such as a supported PRF or HMAC-secret
capability when available. If reliable cross-platform support is not possible, the
hardware key should act as an additional factor rather than pretending to be a
universal standalone decryption key.

The product must clearly show which unlock methods are configured and what fallback
is available.

Each unlock adapter is a separate module with its own threat-model section and
integration test on real hardware or a real OS keychain. An adapter failure is
fail-closed: the vault stays locked and the user is told which method failed.

## 9. Integrations

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

Each integration is a trust boundary. For each one the design records: who is on
the other side, what data crosses, in which direction, what authenticates the
peer, and what happens on failure. Native code, if any, is wrapped per
`JNI00-J` through `JNI04-J` and reviewed as crypto-tier code.

## 10. Java architecture

Use a modular Java application (JPMS modules) with a current supported Java LTS
selected when implementation begins.

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

- Gradle for builds and dependency management (with the Gradle wrapper pinned
  and checksum-verified)
- Lanterna or an equivalent mature Java TUI library
- Java Cryptography Architecture for standard primitives
- An audited Argon2id implementation
- Structured serialization with a versioned schema (a schema-driven binary or
  JSON format; **never** Java native serialization, per `SER12-J`)
- JUnit and property-based testing (jqwik)
- `jpackage` for bundled-runtime installers

The TUI should remain independent from storage and cryptography so those systems
can be tested without terminal automation.

### Module layout and security tiers

| Module | Tier | Notes |
| --- | --- | --- |
| `pm-crypto` | Tier 1 (critical) | Sole caller of JCA; sealed, no dependencies on other project modules |
| `pm-vault` | Tier 1 | Envelope format, key slots, records, migrations |
| `pm-storage` | Tier 1 | Atomic file I/O, permissions, backups |
| `pm-approval` | Tier 1 | Approval broker, policy evaluation, audit log |
| `pm-sharing` | Tier 1 | LAN protocol, pairing, device trust |
| `pm-browser` | Tier 1 | Native messaging host, extension protocol |
| `pm-platform-*` | Tier 2 | Keychain, FIDO2, ssh-agent, process adapters |
| `pm-domain` | Tier 2 | Projects, health, env merging |
| `pm-tui` | Tier 3 | Lanterna screens, no direct secret handling beyond display |
| `pm-cli` | Tier 3 | Command parsing, delegates to application services |

Tier 1 modules require two reviewers, 100% branch coverage of security-relevant
paths, property tests, and a dedicated threat-model section. JPMS `exports` are
minimal; Tier 1 internals are not exported (`OBJ01-J`, `SEC05-J`).

## 11. Key lifecycle

Key lifecycle rules:

- Generate vault keys with a secure random source.
- Never derive the vault key directly from a password.
- Wrap the vault key separately for each unlock method.
- Never log keys, passphrases, recovery codes, or decrypted records.
- Rotate a wrapping key when an unlock method changes.
- Support removing a lost device or security key.
- Revocation is local-first and cannot be pushed to a device that is offline or
  hostile. The design treats revocation as "this vault will no longer share with
  that device": the revoked identity is deleted from the trust list, and any
  future connection attempt fails at TLS pinning. Already-transferred secrets on
  the revoked device cannot be recalled; the UI says so and offers a
  "rotate affected secrets" checklist listing what was shared with that device
  (from the audit log).
- Require the vault to be unlocked before adding or removing unlock methods.
- Make recovery-key regeneration a deliberate vault-key rotation operation, not a
  casual settings action.

Java memory clearing is best-effort. The design should minimize plaintext lifetime
and avoid unnecessary copies, while documenting that a fully compromised operating
system can inspect process memory.

Additional lifecycle controls:

- A `SecretBytes` wrapper type owns all key and secret buffers. It is
  `AutoCloseable`, zeroes on close, refuses `clone()` and serialization
  (`OBJ07-J`, `SER03-J`), overrides `toString()` to a redacted constant, and
  throws if used after close (`OBJ14-J`).
- No finalizers anywhere (`MET12-J`). Cleanup is explicit via try-with-resources.
- Heap dumps are disabled in release builds and the JVM is launched with flags
  that prevent remote monitoring and debugging (`ENV05-J`, `ENV06-J`).

## 12. LAN protocol

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

Certificate trust for the browser page is handled explicitly, because a
self-signed local HTTPS certificate would otherwise produce a browser warning
that trains users to click through warnings:

- The share URL and a QR code encode the page address plus the certificate
  fingerprint. Because browsers cannot verify that fingerprint themselves, the
  page does not rely on TLS for confidentiality of the secret.
- The secret is encrypted on the sender with a one-time key carried only in the
  URL fragment (which never reaches the network). The page decrypts in browser
  memory with WebCrypto. TLS is still used, and the recipient is told to expect
  and how to check the fingerprint, but a middle-man who serves the page sees
  only ciphertext.
- Where a platform offers a trusted local certificate mechanism (for example a
  per-install CA the user opts into), the design may use it, but the fragment
  key remains the security boundary.

### Protocol security requirements

- Transport is TLS 1.3 only (`MSC00-J`) with mutual authentication using the
  per-device identity keys.
- Pairing does not use a PAKE. There is no audited, maintained Java PAKE
  implementation, and the project rule against hand-written cryptographic
  constructions applies to protocols as well as primitives. Instead, pairing
  uses the well-understood pattern of out-of-band fingerprint verification plus
  a short authentication string: each device shows a 6-digit code derived
  (HKDF) from the TLS exporter secret of the mutually authenticated session and
  both identity public keys. The user confirms the codes match on both screens.
  An attacker in the middle cannot produce matching codes. This uses only TLS
  and HKDF from the JDK.
- The identity key pair is Ed25519 via the JDK; the TLS certificate for each
  device is self-signed from that key and pinned by fingerprint after pairing.
- Every message is length-prefixed, size-bounded, and parsed by a strict schema
  before any logic runs (`MSC05-J`, `IDS01-J`, `IDS11-J`). Malformed input
  closes the session.
- Replay protection: per-session nonces and monotonic message counters; share
  identifiers are single-use server-side.
- The listener binds only to the selected interface, only for the share
  lifetime, and is shut down deterministically (`THI04-J`, `FIO14-J`).
- The protocol is fully specified in `docs/protocols/lan-share.md` with a
  state machine, and the implementation is fuzzed against that spec.
- The browser share page sets a strict Content Security Policy, no external
  resources, no persistent storage, and a self-destruct timer.

## 13. Milestones

Each milestone now carries **security exit criteria**. A milestone is not
complete until its criteria are met and recorded in `docs/security/milestone-
signoff.md`.

### M0: Product and security design

Deliverables:

- Threat model (STRIDE per trust boundary, attacker profiles, assets)
- Vault format specification and ADRs
- Key hierarchy and ADRs
- Approval model specification
- LAN protocol design
- Browser feasibility spike
- Supported-platform matrix
- Data classification table
- Abuse-case catalogue
- Security requirements baseline (Part II, Phase 1)
- CI pipeline skeleton with all security tooling wired (Part II, Phase 6)

Security exit criteria:

- Threat model reviewed and signed off.
- Every Tier 1 module has a threat-model section.
- CI fails a deliberately-planted CERT violation, a planted secret, and a
  planted vulnerable dependency (pipeline proven, not assumed).

### M1: Local vault foundation

Deliverables:

- Create, unlock, lock, and save a vault
- Master passphrase
- Recovery key
- Login, Wi-Fi, SSH, and project records
- TUI dashboard and search
- Automatic locking

Security exit criteria:

- Tamper tests: flipping any byte of a vault file is detected before any record
  is parsed.
- Property tests: encrypt/decrypt round trip, corrupted input never yields a
  partial record.
- Atomic write test: killing the process mid-save never corrupts the vault.
- File permission test on all three OSes.
- No project code stores a secret in a `String` beyond the unavoidable
  boundary cases listed in the coding standard (verified by static rule and
  review, Part III).
- Wrong-passphrase handling is constant-time by construction: the KDF always
  runs to completion and tag comparison uses `MessageDigest.isEqual`. This is
  verified by code review and a static check, not by a CI timing measurement,
  because timing measurements on shared CI runners are unreliable. A manual
  timing measurement is part of the M7 pentest checklist.

### M2: Environment sharing priority

Deliverables:

- Project registration
- Environment profiles
- `.env` import
- In-memory process injection
- Explicit `.env` export
- Agent request and TUI approval flow
- Git leakage warnings

Security exit criteria:

- `env run` never writes to disk: verified with filesystem tracing in CI.
- The child process is launched via `ProcessBuilder` with an argument list,
  never a shell string (`IDS07-J`); the command shown in the approval dialog is
  byte-identical to what is executed.
- The approval broker's local IPC is authenticated per platform, and PID is
  never the identity because PIDs are reused:
  - macOS and Linux: Unix domain socket in an owner-only directory (mode 0700)
    with `SO_PEERCRED`/`LOCAL_PEERCRED` UID check, plus a per-session random
    token issued to the launching shell and presented on connect.
  - Windows: named pipe with a DACL restricted to the current user SID and
    `PIPE_REJECT_REMOTE_CLIENTS`, plus the same per-session token.
  - The requesting command is identified by what the broker itself launches
    (for `env run` the broker is the parent), not by a caller-supplied path.
  An unauthenticated request is rejected and logged.
- Approval timeout denies (`fail closed`), verified by test.
- `.env` parser fuzzed for 24 CPU-hours with no crash or hang.
- Scope escalation tests: an approve-once decision cannot be reused.

### M3: LAN sharing

Deliverables:

- Device identities
- Pairing and approval
- Individual secret sharing
- Project sharing
- Expiration and one-use shares
- Revocation and device management
- Browser-only receiving

Security exit criteria:

- Protocol fuzzed against the state machine; malformed messages never reach
  domain code.
- Replay, pairing-code reuse, expired share, and revoked device tests all fail
  closed.
- Listener lifetime test: no open port after share expiry.
- Browser page passes a CSP audit and holds no data after expiry.
- External review of the pairing PAKE construction.

### M4: Health and SSH workflows

Deliverables:

- Password generation
- Weak, reused, old, and compromised checks
- Privacy-preserving online checks
- SSH-agent integration
- Explicit key export fallback

Security exit criteria:

- Generator uses `SecureRandom` and passes statistical tests (`MSC02-J`).
- Online checks use k-anonymity range queries only; network capture in test
  shows no full hash leaves the machine.
- ssh-agent socket handling passes the CERT FIO rules and never exposes private
  key bytes to the TUI layer.

### M5: Browser extension

Deliverables:

- Native messaging bridge
- Autofill
- Credential saving
- Browser password generation
- TUI approval integration

Security exit criteria:

- Origin binding: autofill only to exact registered origins; tested against
  subdomain, scheme, and port confusion.
- Native messaging host validates the calling extension ID and message schema.
- Extension has a minimal permission manifest reviewed and recorded.
- Every credential release requires TUI approval or an explicit session policy.

### M6: Passkeys

Deliverables:

- Passkey enrollment
- Passkey authentication
- Vault-backed WebAuthn operations
- Browser support matrix
- Platform-specific limitations
- Hardware-backed alternatives

Security exit criteria:

- Signature counters are monotonic and persisted atomically.
- RP ID validation tested against the WebAuthn spec test vectors.
- Private keys never leave `pm-crypto`; signing is performed inside it.
- Documented, tested support matrix; unsupported browsers fail clearly.

### M7: Release hardening

Deliverables:

- Cross-platform packaging
- Migration support
- Backup and restore validation
- Security review
- Installer testing
- Documentation and support materials

Security exit criteria:

- Independent security review (internal red team or external firm) with no
  open critical or high findings.
- Reproducible JAR and runtime-image hashes verified on two independent
  machines; installer contents verified against those hashes.
- Signed installers on all platforms; SBOM published with each release.
- Vulnerability disclosure policy and `SECURITY.md` in place.
- Migration rollback tested from every prior format version.

## 14. Nonfunctional requirements

### Security

- No plaintext vault storage
- No secret values in logs
- Fail closed on authentication or approval errors
- Detect vault tampering
- Explicit consent for all sharing
- Constant-time authentication comparisons
- No network access unless a feature that requires it is actively in use
- All Java code compliant with `RULES.md` (Part III)

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

## 15. Operations

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

The application has a local, append-only, tamper-evident audit log (hash
chained) of approvals, unlocks, shares, and device changes. It never contains
secret values (`FIO13-J`, `IDS03-J`). The user can view and export it.

## 16. Passkeys

Passkey support is the highest-risk integration and is explicitly conditional.
Mainstream browsers do not expose a sanctioned API for a third-party extension
to act as a WebAuthn authenticator; the known approaches (content-script
overriding of `navigator.credentials`, or a virtual authenticator via debugging
protocols) are fragile, detectable by relying parties, and can break with any
browser release. Therefore:

- The M6 feasibility spike happens in Quarter 3, not Quarter 4, and has a
  written go/no-go decision.
- The "go" path is limited to browsers and platforms with a supported
  mechanism at that time (for example a platform credential-provider API on
  the OS side, or an officially supported browser extension API if one exists).
- The "no-go" path ships passkey **storage and backup** (records, import and
  export in a documented format) and hardware-backed passkeys on a security
  key, without vault-backed WebAuthn signing in the browser. The release notes
  state this plainly.
- The year-one roadmap and definition of done are written so that the no-go
  path is still a complete release.

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

## 17. Quality strategy

Detailed in Part II, Phase 7. Summary:

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

## 18. Recovery and backup

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

Backup archives are authenticated, and restore validates the whole archive before
extracting anything. Archive entries are path-checked to prevent traversal
(`IDS04-J`, `FIO16-J`).

## 19. Sharing and approvals

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

Approval-broker rules:

- The broker is the single enforcement point (`MET03-J`: security-check
  methods are `private` or `final`; the broker class is `final`).
- Policy evaluation is pure and unit-tested with a decision table.
- Requests are immutable value objects, defensively copied on entry
  (`OBJ06-J`).
- Every decision is written to the audit log before the secret is released.

## 20. TUI design

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

TUI security rules: revealed secrets are re-masked on a timer and on focus loss;
the clipboard is cleared after a configurable timeout; terminal screen buffers
holding revealed secrets are overwritten on screen change; the TUI receives
`SecretBytes` handles and never copies them into `String`.

## 21. Updates and migrations

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

Update packages are signed; the verifying public key is pinned in the binary.
Migrations refuse to downgrade the vault format version unless explicitly forced
by the user with a backup already taken.

## 22. Verification and release gates

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
- Zero open `RULES.md` violations at any severity in Tier 1 modules and zero
  L1/L2 violations anywhere (Part III)
- SBOM generated and no known-exploitable vulnerabilities in dependencies
- Reproducible JAR and runtime-image hashes match across two builders;
  installer contents match those hashes

Browser, hardware-key, and platform-provider behavior must be verified on real
supported environments rather than inferred from source code.

## 23. Windows, macOS, and Linux

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

Platform adapters have platform-specific security tests (ACLs on Windows, POSIX
mode bits on macOS and Linux, keychain ACL scoping on macOS, Secret Service
scoping on Linux, DPAPI scoping on Windows).

## 24. Exceptions and failure modes

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

Exception-handling rules (from `ERR00-J` to `ERR09-J`): exceptions never carry
secret or sensitive data in their messages; a user-facing error is a
translated, redacted message with an error code; the full internal cause is
never printed to the terminal; the vault is never left partially written on
failure (`ERR03-J`).

## 25. Year-one roadmap

### Quarter 1

- Threat model and architecture
- Security requirements baseline and CI security pipeline
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
- First internal security review (vault + approvals)

### Quarter 3

- Device pairing
- LAN secret and project sharing
- Browser-only receiving
- Expiration and revocation
- Password health
- SSH-agent support
- External review of the LAN protocol
- Passkey feasibility spike and go/no-go decision

### Quarter 4

- Browser extension
- Passkey implementation on the approved path, or storage-only fallback
- Bundled-runtime installers
- Migration and backup hardening
- Full security review and penetration test
- Private beta release

## 26. Definition of done

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
13. Use browser password features on the documented support matrix, and use
    passkey features to the extent the M6 go/no-go decision permits.
14. Back up and restore the vault safely.
15. Lock the vault and verify that protected operations are denied.

And when the project can demonstrate:

16. A signed, reproducible release with an SBOM.
17. A security review report with no open critical or high findings.
18. A clean `RULES.md` compliance report for the release commit.
19. A published vulnerability disclosure process.

The project should remain private while these gates are being established. No
production claims should be made until the behavior has been tested on all three
operating systems and the security review is complete.

---

# Part II — Secure SDLC

Security activities are mandatory in each phase. Every phase has **inputs**,
**required activities**, **artifacts**, and an **exit gate**. Nothing moves to
the next phase until the gate is met. Phases repeat per milestone; they are not
a one-time waterfall.

## Phase 0 — Governance and training

Inputs: this plan, `RULES.md`.

Required activities:

- Name a security owner for the project (initially the sole maintainer). The
  owner signs off milestone security exit criteria.
- Every contributor (human or AI agent) reads `RULES.md` and the threat model
  before their first change. AI agents receive `RULES.md` in their context on
  every task that produces Java.
- Adopt a risk register (`docs/security/risk-register.md`) with owner,
  likelihood, impact, mitigation, and status per risk.
- Define the severity scale used everywhere (Critical, High, Medium, Low) and
  the SLA per severity for fixes: Critical 24h, High 7d, Medium next milestone,
  Low backlog.
- Establish the ADR process: any decision touching crypto, storage format,
  protocols, approvals, or trust boundaries requires an ADR before code.

Artifacts: `SECURITY.md`, `CONTRIBUTING.md` (with the RULES.md mandate),
`docs/adr/0001-record-architecture-decisions.md`, risk register.

Exit gate: artifacts exist; CODEOWNERS and branch protection are live.

## Phase 1 — Security requirements

Inputs: Part I, abuse cases.

Required activities:

- Write the security requirements baseline (`docs/security/requirements.md`)
  as numbered, testable statements (SR-001 …). Each requirement names the test
  or check that proves it.
- Map each requirement to the OWASP ASVS level 2 controls that apply to a
  local desktop application, and to the CERT families in `RULES.md`.
- Classify all data (Part I, section 4).
- Define the trust boundaries: user ↔ TUI, TUI ↔ approval broker, broker ↔
  requesting process, app ↔ filesystem, app ↔ OS keychain, app ↔ hardware key,
  app ↔ LAN peer, app ↔ browser extension, app ↔ online breach service.
- Write abuse cases per user journey.

Artifacts: requirements baseline, data classification, trust-boundary diagram,
abuse-case catalogue.

Exit gate: every user journey has at least one security requirement and one
abuse case; every requirement has a named verification.

## Phase 2 — Threat modeling

Inputs: Phase 1 artifacts, architecture (Part I, section 10).

Required activities:

- STRIDE analysis per trust boundary, recorded in `docs/security/threat-model.md`.
- Attacker profiles: local unprivileged process, local privileged process
  (documented as out of scope but acknowledged), LAN attacker, malicious web
  page, malicious browser extension, malicious AI agent, lost or stolen device,
  malicious vault or backup file.
- Attack trees for the three crown-jewel goals: read the vault key, obtain a
  secret without approval, and impersonate a paired device.
- Each identified threat gets an ID, a mitigation, a CERT rule reference where
  one applies, and a test ID.
- Threat model is re-reviewed at the start of every milestone and whenever a
  boundary in Part I, section 2 changes.

Artifacts: threat model, attack trees, threat-to-test traceability matrix.

Exit gate: no threat is unmitigated without a documented, accepted risk in the
risk register.

## Phase 3 — Secure design

Inputs: threat model.

Required activities:

- Design principles applied and checked in review: least privilege, fail
  closed, complete mediation (the approval broker), defense in depth, secure
  defaults, minimal attack surface, separation of concerns by module tier.
- Write ADRs for: vault envelope format, key hierarchy, Argon2id floors, cipher
  choice, nonce strategy, serialization format, LAN protocol and PAKE, approval
  policy language, audit log format, IPC authentication, update signing.
- Interface contracts for every Tier 1 module; secrets cross interfaces only as
  `SecretBytes`.
- Design review checklist (`docs/security/design-review-checklist.md`) run by a
  second person or an independent review agent before implementation of any
  Tier 1 module.
- Crypto designs are compared against current NIST, IETF, and OWASP guidance
  and the comparison is recorded in the ADR.

Artifacts: ADRs, interface specs, protocol state machines, completed design
review checklists.

Exit gate: design review passed for the module about to be built.

## Phase 4 — Secure implementation

Inputs: ADRs, `RULES.md`.

Required activities:

- **All Java code MUST comply with `RULES.md`.** See Part III for the
  enforcement mechanism. Non-compliant code does not merge.
- Follow the project coding conventions in `docs/engineering/coding-standards.md`,
  which are a strict superset of `RULES.md` with project-specific additions:
  - `SecretBytes` for all secrets. Project code that assigns a secret to a
    `String` fails the `cert.MSC03-J.secret-in-string` Semgrep check. Two
    boundary cases are unavoidable because third-party APIs return or accept
    `String`: TUI input widgets and some platform adapters (keychain, native
    messaging JSON). At those boundaries the `String` is converted to
    `SecretBytes` immediately, the boundary is annotated `@SecretBoundary`, and
    the plaintext lifetime is documented. The TUI uses a custom masked-input
    widget that reads key events into a `char[]` where the library allows it.
  - No Java native serialization anywhere (`ObjectInputStream` is banned).
  - No `Runtime.exec(String)`; only `ProcessBuilder` with `List<String>`.
  - No reflection on project classes; no `setAccessible(true)`.
  - No `System.exit()` outside the single `Main` entry point (`ERR09-J`).
  - No `Thread.stop`, `ThreadGroup`, or finalizers.
  - All I/O through `pm-storage`; all crypto through `pm-crypto`.
  - Logging only through the project logger, which applies redaction filters
    and refuses `SecretBytes` and any type annotated `@Sensitive`.
  - Paths canonicalized before any check (`FIO16-J`).
  - Environment variables and config values are untrusted input (`ENV02-J`).
- Small, focused commits; each commit compiles and passes tests.
- Pair or AI-assisted review during implementation of Tier 1 code; the reviewer
  cites the CERT rules considered.
- Every new external input (file, socket, IPC message, env var, CLI arg) gets a
  parser with size limits and a fuzz harness in the same PR.

Artifacts: code, tests, fuzz harnesses, updated ADRs where implementation
diverged from design.

Exit gate: CI green including all Part III checks.

## Phase 5 — Supply-chain security

Inputs: `build.gradle.kts`, dependency list.

Required activities:

- Pin every dependency to an exact version and verify checksums and signatures
  through Gradle dependency verification (`gradle/verification-metadata.xml`).
- Use a dependency allowlist; adding a dependency requires an ADR-lite note in
  the PR stating why, its maintenance status, and its transitive footprint.
- Prefer JDK-provided functionality; keep Tier 1 modules to zero third-party
  runtime dependencies except the audited Argon2id and TLS library.
- Automated vulnerability scanning (OWASP Dependency-Check or equivalent) on
  every PR and nightly; Critical/High findings block merge.
- Generate a CycloneDX SBOM on every build; publish it with releases.
- Renovate or Dependabot for updates, with security updates prioritized.
- Pin GitHub Actions to commit SHAs; use least-privilege workflow tokens.
- Build toolchain (JDK, Gradle wrapper) pinned and checksum-verified.
- Reproducible builds, scoped to what is achievable: the application JARs and
  the `jlink` runtime image are byte-identical across builders and verified in
  CI on two runners. Platform installers (DMG, MSI, DEB/RPM) and signatures are
  **not** expected to be byte-identical because signing and notarization embed
  timestamps and tickets. For installers, CI instead verifies that the
  installer's extracted contents match the reproducible image hash and that the
  signature is valid.

Artifacts: verification metadata, SBOM, dependency allowlist, scan reports.

Exit gate: no unverified dependency; scan clean at Critical/High.

## Phase 6 — Secure build and CI

Required pipeline stages (all required to pass on every PR):

1. Compile with `-Werror`, `-Xlint:all`, and the Error Prone compiler plugin.
2. Static analysis: SpotBugs with Find Security Bugs, PMD with the project CERT
   ruleset, Error Prone with the project CERT checks, and Semgrep with the
   project CERT rule pack (Part III).
3. Secret scanning (gitleaks) over the diff and full history on `main`.
4. Unit and property tests with coverage; Tier 1 modules require 100% branch
   coverage on security-relevant packages, 90% elsewhere.
5. Integration tests on a matrix of macOS, Windows, and Linux runners.
6. Dependency vulnerability scan and SBOM generation.
7. Fuzzing smoke run (short) on every PR; long runs nightly (Jazzer).
8. Log-redaction test: run the integration suite with a canary secret and grep
   all captured output and artifacts for it; any hit fails the build.
9. `RULES.md` compliance report generation (Part III) with a zero-violation
   requirement.
10. Reproducible-build check (JARs and runtime image) on release branches.

CI security: no secrets in CI beyond the release signing key held in an
environment with required reviewers; PRs from forks run without secrets;
workflow permissions default to read-only.

Exit gate: pipeline is proven by planted failures (Part I, M0).

## Phase 7 — Security testing and verification

Inputs: threat-to-test matrix.

Required activities:

- Every threat ID has an automated test or a documented manual test procedure.
- Property-based tests (jqwik) for envelope encoding, record serialization,
  env-profile merging, expiration logic, and policy evaluation.
- Fuzzing (Jazzer) for: vault envelope parser, record deserializer, `.env`
  parser, LAN message parser, native-messaging JSON parser, backup archive
  reader. Corpus is checked in and grows from crashes found.
- Negative security tests as first-class test suites: tamper, replay, reuse,
  expiry, revocation, scope escalation, path traversal, oversized input, slow
  loris on the LAN listener, malformed native messages.
- Concurrency tests for the approval broker and vault lock using jcstress or
  stress loops (`VNA`, `LCK`, `THI`, `TPS` families).
- Timing: constant-time behavior is enforced structurally (always-complete
  KDF, `MessageDigest.isEqual`, no early-exit comparisons) and checked by a
  Semgrep rule banning `Arrays.equals`/`equals` on key, tag, or code byte
  arrays. Manual timing measurement on dedicated hardware is in the M7 pentest
  checklist; it is not a CI gate.
- Memory hygiene tests: after `close()`, `SecretBytes` buffers are zero; heap
  dump in a test JVM contains no canary secret after lock.
- Platform tests on real OSes for permissions, keychains, and hardware keys.
- Manual penetration test checklist per milestone
  (`docs/security/pentest-checklist.md`), executed and recorded.
- External review at M3 (LAN protocol) and M7 (full).

Artifacts: test suites, fuzz corpora, pentest records, external review reports.

Exit gate: milestone security exit criteria (Part I, section 13) all green.

## Phase 8 — Code review

Required activities:

- CODEOWNERS routes Tier 1 paths to two reviewers.
- The review template (`.github/PULL_REQUEST_TEMPLATE.md`) requires the author
  to list: trust boundaries touched, CERT rules considered, new inputs and
  their fuzz harness, secrets handled and how they are cleared, and threat IDs
  addressed.
- Reviewers use the security review checklist
  (`docs/security/code-review-checklist.md`), organized by CERT family, and
  record which items were checked.
- AI-assisted review (Codex, read-only) runs on every Tier 1 PR with `RULES.md`
  as context and posts findings; a human resolves every finding before merge.
- Any review comment that identifies a CERT violation is a blocking change
  request, not a suggestion.

Exit gate: approvals recorded; all blocking comments resolved; CI green.

## Phase 9 — Release

Required activities:

- Release checklist (`docs/release/checklist.md`) run and archived per release.
- Full test matrix, long fuzz run, and dependency scan on the release commit.
- `RULES.md` compliance report attached to the release.
- Security review sign-off for the milestone.
- Installers built reproducibly, signed (Apple notarization, Windows
  Authenticode, Linux detached signatures), and hashes published.
- SBOM and release notes with a "Security" section listing fixed
  vulnerabilities by ID.
- Release signing keys held offline or in a hardware token; a key-rotation
  procedure documented.

Exit gate: all Part I, section 22 gates green; signed artifacts published.

## Phase 10 — Deployment and distribution

Required activities:

- Distribution channels documented; each publishes the same signed artifacts
  and hashes.
- Installer hardening: owner-only permissions on created directories, no
  world-writable paths, no bundled debug tooling (`ENV06-J`), JVM launched with
  monitoring and remote debugging disabled (`ENV05-J`).
- Native-messaging host registration writes only the documented manifest and
  binds it to the exact extension ID.
- Update mechanism verifies signatures with a pinned key before applying.

Exit gate: fresh-install verification on all three OSes from the published
artifacts, with a permissions and open-ports audit recorded.

## Phase 11 — Operations, monitoring, and incident response

Required activities:

- Local tamper-evident audit log (Part I, section 15) with a user-facing viewer.
- Diagnostics command produces a redacted bundle the user can share for support.
- `SECURITY.md` with a private disclosure channel, response SLAs (acknowledge
  48h, triage 7d), and safe-harbor language.
- Incident response runbook (`docs/security/incident-response.md`): triage,
  severity assignment, fix, regression test, coordinated disclosure, advisory
  publication, post-incident review with threat-model update.
- Security advisories published with CVE requests where applicable.
- Monitor advisories for all dependencies and the JDK; the SLA in Phase 0
  applies.

Exit gate: runbook exercised once with a tabletop drill before beta.

## Phase 12 — Maintenance and end of life

Required activities:

- Quarterly: dependency refresh, threat-model review, re-run of the full
  pentest checklist, `RULES.md` re-baseline against the upstream CERT index.
- Annually: external security review.
- Vault format changes always ship with migration, backup, and rollback tests.
- Deprecation policy: unlock methods and integrations are removed only with a
  migration path and one release of overlap.
- End-of-life plan: users can always export an encrypted, documented-format
  backup and the format specification is published so vaults remain readable.

Exit gate: the quarterly review record exists and is current.

## SDLC phase-to-artifact summary

| Phase | Key artifacts | Gate owner |
| --- | --- | --- |
| 0 Governance | SECURITY.md, CONTRIBUTING.md, risk register, ADR process | Security owner |
| 1 Requirements | requirements baseline, data classification, abuse cases | Security owner |
| 2 Threat model | threat model, attack trees, traceability matrix | Security owner |
| 3 Design | ADRs, interface specs, design review checklists | Reviewer |
| 4 Implementation | code, tests, fuzz harnesses | CI + reviewer |
| 5 Supply chain | verification metadata, SBOM, scan reports | CI |
| 6 Build/CI | pipeline, planted-failure proof | CI |
| 7 Testing | security test suites, fuzz corpora, pentest records | Security owner |
| 8 Review | PR template, checklists, AI review findings | Reviewers |
| 9 Release | release checklist, signed artifacts, compliance report | Security owner |
| 10 Deployment | install audit on three OSes | Security owner |
| 11 Operations | audit log, IR runbook, advisories | Security owner |
| 12 Maintenance | quarterly review record | Security owner |

---

# Part III — RULES.md compliance program

## Mandate

**Every Java source file in this repository MUST adhere to `RULES.md`.** This is
a merge requirement enforced by tooling and review, applies to production code,
test code, build scripts written in Java, and generated code that is checked in,
and applies equally to code written by humans and by AI agents.

`RULES.md` digests 177 rules across 19 families (Rule 00 IDS through Rule 49
MSC). Rules whose source pages are marked deprecated, stubbed, or under
construction are still honored in spirit per their enforcement cue, but are not
treated as complete normative specifications, as `RULES.md` itself notes.

Several rules assume the Java Security Manager (`SEC04-J`, `SER04-J`,
`SER08-J`, `ENV03-J`, and parts of `SEC00-J`/`SEC01-J`/`SEC07-J`). The Security
Manager is deprecated for removal since JDK 17 and is disabled by default from
JDK 18; the project will not use it. Those rules are classified **Not
applicable (superseded)** in the applicability table, with the compensating
control recorded: JPMS strong encapsulation, no dynamic class loading, no
custom class loaders, and the module-tier boundaries enforced by ArchUnit. An
ArchUnit test asserts that `java.lang.SecurityManager`, `AccessController`, and
custom `ClassLoader` subclasses do not appear in project code.

## Applicability review

Not every rule applies to every module. During M0 the team produces
`docs/security/cert-applicability.md`: a table of all 177 rule IDs with one of
three statuses and a justification:

- **Enforced** — an automated check exists (linter rule, compiler check,
  Semgrep pattern, or architecture test) and the rule is in the review
  checklist.
- **Review-only** — no reliable automated check; the rule is in the review
  checklist and reviewers must attest to it for affected code.
- **Not applicable** — the construct cannot occur in this codebase (for
  example `FIO15-J` and `MSC08-J`/`MSC11-J` concern servlets; `MSC09-J`/
  `MSC10-J` concern OAuth). Not-applicable status is backed by an architecture
  test that fails if the construct appears (for example, a test asserting no
  `javax.servlet` import).

The default status is Enforced. Moving a rule to Review-only or Not applicable
requires a justification and reviewer approval.

## Priority rules for this codebase

The following rules are the most consequential for a password manager and are
called out as **non-negotiable** with dedicated automated checks from M0:

| Rule | Why it matters here | Automated check |
| --- | --- | --- |
| `MSC02-J` Generate strong random numbers | Keys, nonces, salts, pairing codes, generated passwords | Ban `java.util.Random`, `Math.random`; only `SecureRandom` via `pm-crypto` |
| `MSC03-J` Never hard code sensitive information | Test fixtures, sample vaults | gitleaks + Semgrep on string literals with high entropy |
| `SER12-J` Prevent deserialization of untrusted data | Vault, backups, LAN, IPC all deserialize | Ban `ObjectInputStream`, `Serializable` on project classes |
| `SER03-J` Do not serialize unencrypted sensitive data | Any secret leaving memory | `@Sensitive` types fail if they reach a serializer |
| `IDS15-J` / `FIO13-J` / `IDS03-J` No sensitive data across trust boundaries or in logs | Logs, errors, diagnostics | Logger rejects `SecretBytes`; canary-secret grep in CI |
| `ERR01-J` Exceptions must not expose sensitive information | Terminal error output | Exception messages built only from error codes; test asserts no secret in any thrown message |
| `IDS07-J` Sanitize data passed to `Runtime.exec()` | `env run` launches user commands | Ban `Runtime.exec`; `ProcessBuilder` only with `List<String>` |
| `FIO00-J` / `FIO01-J` Files in shared directories; permissions | Vault, backups, sockets | `pm-storage` sets permissions before write; test on all OSes |
| `FIO16-J` Canonicalize path names before validating | Project paths, backup restore, `.env` import | All paths pass through `SafePath` |
| `FIO03-J` / `FIO14-J` Temp files and termination cleanup | Never leave a plaintext temp file | Ban `File.createTempFile`; shutdown hook tests |
| `MSC00-J` Use `SSLSocket` rather than `Socket` | LAN protocol | Ban raw `Socket`/`ServerSocket` outside `pm-sharing` TLS wrapper |
| `ENV02-J` Do not trust environment variables | Config, `env run` merging | All `System.getenv` reads go through a validating accessor |
| `ENV05-J` / `ENV06-J` No remote monitoring or debug entry points | Release builds | jpackage launcher flags audited; no JMX; no debug commands |
| `MET03-J` Security checks must be `private` or `final` | Approval broker | Architecture test: broker and policy classes are `final` |
| `OBJ07-J` Sensitive classes must not be copied | `SecretBytes`, key material | `clone()` throws; not `Serializable`; test |
| `OBJ14-J` Do not use a freed object | `SecretBytes` after close | Use-after-close throws; test |
| `MET12-J` Do not use finalizers | Predictable secret clearing | Ban `finalize()` |
| `ERR09-J` Untrusted code must not terminate the JVM | IPC and extension messages | Ban `System.exit` outside `Main` |
| `LCK00-J`–`LCK11-J` Locking | Vault lock state, approval broker | Private final lock objects; PMD/Error Prone checks; jcstress |
| `THI04-J` / `TPS02-J` Blocking threads can be terminated | LAN listener, broker | Interruptible tasks; listener shutdown test |
| `MSC05-J` Do not exhaust heap space | Network and file input | All parsers size-bounded; fuzz |
| `STR03-J` / `FIO11-J` Encoding | Secrets are bytes, not strings | `SecretBytes` API has no `String` conversion; charset always explicit |
| `SEC05-J` Do not use reflection to increase accessibility | Keep Tier 1 sealed | Ban `setAccessible`; JPMS strong encapsulation |

## Enforcement mechanism

Layered so that no single tool is the only line of defense:

1. **Compiler.** `-Werror -Xlint:all`, Error Prone with a project check set
   mapped to CERT rules (for example `EXP00-J` via `CheckReturnValue`,
   `MET08-J`/`MET09-J` via `EqualsHashCode`, `VNA` family via
   `GuardedBy`).
2. **Static analysis.** PMD with a custom ruleset named by CERT ID; SpotBugs +
   Find Security Bugs; Semgrep with a project rule pack where each rule's `id`
   is the CERT ID it enforces (e.g. `cert.MSC02-J.weak-random`). The rule pack
   lives in `tools/cert-rules/` and is versioned with the code.
3. **Architecture tests.** ArchUnit tests in `pm-arch-tests` assert module
   boundaries: only `pm-crypto` imports `javax.crypto`; only `pm-storage`
   imports `java.nio.file`; nothing imports `java.io.ObjectInputStream`; Tier 1
   security classes are `final`; no class outside `pm-crypto` references
   `SecureRandom` directly.
4. **Runtime guards.** `SecretBytes`, the redacting logger, `SafePath`, and the
   validating env accessor make the safe path the only path.
5. **Review.** Checklist by CERT family; PR template requires rule citations;
   AI review with `RULES.md` in context.
6. **Compliance report.** A Gradle task `certReport` aggregates results from
   steps 1–3 into `build/reports/cert-compliance.md` listing every rule ID,
   its status, and any findings. CI publishes it as an artifact and fails on
   any finding for Enforced rules. The report for each release commit is
   archived under `docs/security/compliance/`.

## Handling exceptions

A genuine, justified deviation from a rule (expected to be rare) requires:

- A `@SuppressWarnings("cert:RULE-ID")` annotation at the narrowest scope with a
  `// CERT-EXCEPTION: <reason>` comment on the same construct.
- An entry in `docs/security/cert-exceptions.md` with rule ID, file and line,
  reason, compensating control, reviewer, and expiry date.
- Approval by two reviewers, one of whom is the security owner.
- Exceptions in Tier 1 modules require an ADR.

CI fails if a suppression exists without a matching ledger entry, or if a
ledger entry has expired.

## Keeping RULES.md current

`RULES.md` was captured from the upstream CERT index on 2026-08-27. Quarterly
(Phase 12), the upstream index is re-checked; any new, changed, or retired rule
is reflected in `RULES.md`, the applicability table, and the rule pack in the
same PR.

## Instructions for AI agents working in this repository

- Read `RULES.md` in full before writing or modifying any Java.
- For every Java change, state in the PR description or task summary which
  CERT rules were considered and how the change complies.
- Never introduce a suppression without following the exception process.
- Prefer the project's guarded APIs (`SecretBytes`, `SafePath`, the redacting
  logger, `pm-crypto`) over raw JDK calls; if a guarded API is missing for a
  need, add it in `pm-crypto` or `pm-storage` rather than bypassing the
  boundary.
- Run the full gate (`./gradlew check certReport`) and report its real output
  before declaring any task complete.

---

## Appendix A — Repository layout (target)

```text
passwordManager/
├── RULES.md                          # CERT Java baseline (normative)
├── plan.md                           # this document
├── SECURITY.md
├── CONTRIBUTING.md
├── CODEOWNERS
├── build.gradle.kts, settings.gradle.kts, gradle/verification-metadata.xml
├── tools/cert-rules/                 # Semgrep/PMD/Error Prone rule packs by CERT ID
├── docs/
│   ├── adr/
│   ├── protocols/lan-share.md
│   ├── engineering/coding-standards.md
│   ├── release/checklist.md
│   └── security/
│       ├── requirements.md
│       ├── data-classification.md
│       ├── abuse-cases.md
│       ├── threat-model.md
│       ├── risk-register.md
│       ├── cert-applicability.md
│       ├── cert-exceptions.md
│       ├── compliance/               # archived certReport output per release
│       ├── design-review-checklist.md
│       ├── code-review-checklist.md
│       ├── pentest-checklist.md
│       ├── incident-response.md
│       └── milestone-signoff.md
└── modules/
    ├── pm-crypto/  pm-vault/  pm-storage/  pm-approval/  pm-sharing/  pm-browser/
    ├── pm-platform-macos/  pm-platform-windows/  pm-platform-linux/
    ├── pm-domain/  pm-tui/  pm-cli/  pm-arch-tests/  pm-fuzz/
```

## Appendix B — Open decisions to close in M0

- Java LTS version.
- Argon2id parameter floors and the benchmark policy.
- AES-256-GCM versus ChaCha20-Poly1305 for the vault payload.
- Serialization format (schema-driven binary versus JSON with a strict schema).
- PAKE choice for LAN pairing.
- Whether hardware keys are a standalone unlock or a second factor.
- TUI library.
- Licence and distribution model (deferred until the distribution decision).
- External reviewer selection for M3 and M7.
