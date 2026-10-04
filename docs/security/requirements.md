# Security Requirements Baseline

Numbered, testable statements. Each has a verification (test ID prefix `T-`,
defined in Phase 3 traceability; `R` = review checklist item; `CI` = pipeline
check). ASVS references are to OWASP ASVS 4.0 chapters applicable to a local
desktop application.

## Vault and cryptography (SR-0xx)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-010 | Master passphrase is stretched with Argon2id at or above the floors in ADR 0007; parameters are stored in the authenticated header | T-KDF-01 | V2.4 | MSC02-J |
| SR-011 | The passphrase strength meter runs locally and blocks passphrases under the minimum estimated entropy | T-UI-01 | V2.1 | — |
| SR-012 | The vault key is random (CSPRNG) and is never derived from a passphrase | T-KEY-01 | V6.2 | MSC02-J |
| SR-013 | Every unlock method wraps the vault key in an independent slot; removing a slot revokes only that method | T-KEY-02 | V6.2 | — |
| SR-014 | Bulk encryption uses AES-256-GCM with a per-save HKDF-derived data key (or XChaCha20-Poly1305); no persisted nonce counters | T-ENC-01, R | V6.2 | — |
| SR-015 | Header fields are covered by AAD; version and KDF parameters cannot be altered without detection | T-ENC-02 | V6.2 | — |
| SR-016 | All MAC/tag/code comparisons are constant-time (`MessageDigest.isEqual`) | CI (Semgrep), R | V6.2 | — |
| SR-017 | Only `pm-crypto` references `javax.crypto`, `java.security`, `SecureRandom` | CI (ArchUnit) | V1.6 | MSC02-J |
| SR-018 | Algorithm and provider names are compile-time constants | CI (Semgrep), R | V6.2 | ENV02-J, SEC02-J |
| SR-020 | Any single-byte modification of a vault file is detected before any record is deserialized | T-TAMPER-01 | V6.2 | — |
| SR-021 | The vault parser is size-bounded and fuzzed; malformed input never yields a partial record | T-FUZZ-VAULT | V5.1 | MSC05-J, IDS11-J |
| SR-030 | The recovery key is shown once, requires explicit confirmation, and the display buffer is cleared on dismissal | T-UI-02 | V2.5 | — |
| SR-040 | Vault directory and file are created with owner-only permissions before any bytes are written, never in a shared or temp directory | T-FS-01 (3 OSes) | V12.3 | FIO00-J, FIO01-J |
| SR-041 | Vault writes are atomic (write temp in same directory, fsync, rename); a crash at any point leaves the previous vault intact | T-FS-02 | V12.3 | FIO02-J |
| SR-050 | OS-keychain unlock is off by default; enabling it shows the same-user-malware warning; the keychain holds only a slot wrapping key | T-UI-03, R | V2.10 | — |
| SR-051 | Wrong passphrase/tag failures take the same code path length as success (KDF completes, constant-time compare); no early return reveals vault existence beyond the file's presence | R, M7 manual timing | V2.2 | — |

## Approval broker and environments (SR-1xx)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-100 | Every secret release to a process goes through the approval broker; there is no other code path | CI (ArchUnit), R | V4.1 | MET03-J |
| SR-101 | Broker IPC authenticates the peer by OS user identity (peer credentials / pipe DACL) plus a per-session token; PID is never used as identity | T-IPC-01 (3 OSes) | V4.2 | SEC02-J |
| SR-102 | The command displayed in the approval dialog is the exact argv executed; the broker launches the child itself with `ProcessBuilder(List)` | T-ENV-01 | V5.3 | IDS07-J |
| SR-103 | Requests name an explicit scope (project, profile, variable set); the UI shows it; a policy cannot cover more than one project | T-POLICY-01 | V4.1 | — |
| SR-104 | Approve-once decisions are single-use and bound to a request nonce; replay is denied | T-POLICY-02 | V4.2 | — |
| SR-105 | `.env` import parser is size-bounded and fuzzed | T-FUZZ-ENV | V5.1 | MSC05-J |
| SR-106 | `env run` writes no secret to disk; verified by filesystem tracing in CI | T-ENV-02 | V8.1 | FIO03-J |
| SR-107 | Users are warned that child processes may propagate environment variables further; this is a documented limitation | R, docs | — | — |
| SR-108 | Broker socket lives in an owner-only directory with a random name; symlink targets are refused | T-IPC-02 | V12.3 | FIO00-J, FIO16-J |
| SR-109 | Approval dialogs ignore input for a short grace period after appearing and require a deliberate key (not Enter alone) to approve | T-UI-04 | — | — |
| SR-110 | `.env` export warns, requires confirmation, and refuses git-tracked paths unless overridden | T-ENV-03 | — | — |
| SR-111 | Approval timeout (default 60 s) denies | T-POLICY-03 | V4.1 | — |
| SR-112 | Every approval decision is appended to the audit log before the secret is released | T-AUDIT-01 | V7.1 | — |

## LAN sharing (SR-2xx)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-200 | Discovery results are advisory only; trust is established solely by the pairing ceremony | T-LAN-01 | V9.2 | — |
| SR-201 | Pairing uses mutual TLS 1.3 with self-signed certs from per-device Ed25519 identity keys and a short authentication string derived via HKDF from the TLS exporter secret and both public keys; both users confirm the SAS | T-LAN-02, external review | V9.2 | MSC00-J |
| SR-202 | Each session has fresh keys; messages carry a per-session sequence number; replay is rejected | T-LAN-03 | V9.2 | — |
| SR-203 | Pairing attempts are rate-limited (3 failures then 60 s lockout, exponential) and the SAS is never transmitted | T-LAN-04 | V2.2 | — |
| SR-204 | Share IDs are single-use and time-limited; the sender enforces both server-side | T-LAN-05 | V3.3 | — |
| SR-205 | Revoking a device deletes its pinned identity; subsequent TLS handshakes fail | T-LAN-06 | V9.2 | — |
| SR-206 | All protocol messages are length-prefixed with a hard maximum (1 MiB) and schema-validated before dispatch; the parser is fuzzed | T-FUZZ-LAN | V5.1 | MSC05-J, IDS11-J |
| SR-207 | The listener binds only to the chosen interface, only for the share lifetime, and is proven closed after expiry | T-LAN-07 | V9.1 | THI04-J, FIO14-J |
| SR-208 | A received project or secret is applied atomically after full verification, or not at all | T-LAN-08 | — | ERR03-J |
| SR-209 | Browser-only shares encrypt with a one-time key carried only in the URL fragment; the server never sees plaintext or the key | T-WEB-01 | V6.2 | — |
| SR-210 | The browser share page sets `Cache-Control: no-store`, a strict CSP with no external resources, uses no persistent storage, and self-destructs on expiry | T-WEB-02 | V14.4 | — |

## Browser extension (SR-3xx)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-300 | Autofill only when the page origin (scheme + host + port) exactly matches a stored URL origin; subdomains require explicit record opt-in | T-EXT-01 | V5.1 | — |
| SR-301 | The native messaging host manifest allowlists exactly the project extension ID(s); messages from other origins are rejected | T-EXT-02 | V4.2 | — |
| SR-302 | Every credential release to the extension requires TUI approval or an explicit session policy scoped to one origin | T-EXT-03 | V4.1 | — |
| SR-303 | Native messaging JSON is size-bounded (Chrome limit 1 MiB) and schema-validated; the parser is fuzzed | T-FUZZ-NM | V5.1 | MSC05-J |
| SR-304 | Autofill happens only on explicit user action in the extension UI, never automatically on page load | T-EXT-04 | — | — |
| SR-305 | Native messaging requests are one JSON object whose member names are exactly the set for its `type`, each of the listed type and range; the caller's extension origin is checked against the host's own allowlist before stdin is read (ADR 0014 §3, §4) | T-EXT-05, T-EXT-02 | V5.1 | IDS00-J, MSC05-J |
| SR-306 | Origins are canonicalised before any comparison: scheme and host lowercased (ASCII only), hosts accepted only as ASCII/A-label (`xn--`) LDH names with no IDNA mapping (non-ASCII refused), default port elided; userinfo, trailing dots, IPv6 and non-canonical IPv4 literals are refused (ADR 0014 §5) | T-EXT-01 | V5.1 | IDS01-J |
| SR-307 | Fill, save and generate each submit one broker request scoped to one canonical origin and one action (fills: one login, named in the prompt); generate stores the new login before releasing the password; a password reaches the bridge only through a single-use `Grant` it cannot construct (ADR 0014 §6) | T-EXT-03 | V4.1 | MET03-J |
| SR-308 | The extension requests only `nativeMessaging`, `activeTab` and `scripting`, has no host permissions and no content scripts, loads no remote code and runs under a `script-src 'self'` CSP (extension-permissions.md) | T-EXT-06 | V14.2 | — |
| SR-309 | The page fill runs only in the top-level frame and only when `location.origin` equals the origin the host approved, and writes only into enabled, writable fields that are rendered, visible, not transparent and of non-zero size; otherwise nothing is written (ADR 0014 §7) | T-EXT-04 | V5.1 | — |

## Passkeys (SR-4xx)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-400 | RP ID validation follows the WebAuthn spec (effective domain rules); tested against spec vectors | T-PK-01 | V2.8 | — |
| SR-401 | Signature counters are persisted atomically before the assertion is returned | T-PK-02 | V2.8 | — |
| SR-402 | Passkey private keys never leave `pm-crypto`; signing happens inside it | CI (ArchUnit `onlyVaultDomainAndBrowserReachPasskeys`, `onlyTheVaultReachesPasskeyStorage`; see SR-080) | V6.2 | — |

## SSH keys and agent, M4 (SR-060 to SR-064)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-060 | SSH private key bytes are parsed, sent to the agent and exported only in `pm.crypto.ssh`; the API takes `SecretBytes` and never returns private bytes except through the explicit export; only `pm.cli` may use the package (qualified export `exports pm.crypto.ssh to pm.cli`); key bytes are written to channels only from zero-filled pm-owned direct buffers | Compiler (qualified export), CI (ArchUnit `onlyTheCliReachesSshKeys`, `noCryptoFacadeOverSshKeys`), `SshKeyTest` | V6.2 | MSC03-J, FIO13-J |
| SR-061 | The agent socket path is refused unless absolute, its canonical parent is not group- or world-writable, and the socket itself (not followed through a link) is a socket owned by the current user; after connecting, the peer (`SO_PEERCRED`) must run as the current user | `SshAgentClientTest` | V12.3 | FIO00-J, FIO15-J, FIO16-J |
| SR-062 | Key files and agent replies are parsed with every `uint32` length bounded before use (agent message at most 256 KiB, at most 1,024 identities); malformed, oversized, truncated or trailing input is refused with an error code | `SshKeyTest`, `SshAgentClientTest` | V5.1 | IDS00-J, NUM00-J, MSC05-J |
| SR-063 | The export fallback writes the OpenSSH private key file with `CREATE_NEW`, `NOFOLLOW_LINKS` and mode `0600` set at creation; an existing target is never overwritten; a partial file is deleted if writing fails | `SshKeyExportTest` | V12.3 | FIO01-J, FIO16-J |
| SR-064 | Encrypted `openssh-key-v1` files are refused with `ENCRYPTED_KEY`; no partial decryption or key derivation is attempted | `SshKeyTest` | V6.2 | ERR01-J |

## Cross-cutting (SR-5xx to SR-8xx)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-500 | The logger refuses `SecretBytes` and `@Sensitive` types; a canary secret run through the full integration suite never appears in any output or artifact | T-LOG-01 (CI grep) | V7.1 | FIO13-J, IDS03-J |
| SR-501 | Exceptions carry error codes only; messages are built from a fixed catalogue; no exception includes a secret, path, or record content | T-ERR-01, CI (Semgrep) | V7.4 | ERR01-J |
| SR-502 | Release JVM launches with heap dumps, JMX, and remote debugging disabled; no debug commands exist in release builds | T-PKG-01, R | V14.3 | ENV05-J, ENV06-J |
| SR-503 | Clipboard copies are cleared after a configurable timeout (default 30 s) where the platform allows | T-UI-05 | — | — |
| SR-504 | Auto-lock after inactivity (default 5 min; 2 min when keychain unlock is enabled) and on system sleep/lock where detectable | T-UI-06 | V3.3 | — |
| SR-505 | All secret buffers are `SecretBytes`; zeroed on close; use-after-close throws; not cloneable or serializable | T-MEM-01 | V6.2 | OBJ07-J, OBJ14-J, SER03-J |
| SR-506 | No finalizers, no `Thread.stop`, no `System.exit` outside `Main`, no reflection into project classes | CI (Semgrep/ArchUnit) | V1.14 | MET12-J, THI05-J, ERR09-J, SEC05-J |
| SR-507 | No Java native serialization; `ObjectInputStream` is absent from the codebase | CI (ArchUnit) | V5.5 | SER12-J |
| SR-600 | Every dependency is pinned and checksum/signature-verified; Critical/High vulnerabilities block merge; an SBOM ships with every release | CI | V14.2 | — |
| SR-601 | Installers are signed per platform; JARs and runtime image are reproducible across two builders; installer contents match | CI (release) | V14.2 | ENV01-J |
| SR-602 | Updates are signature-verified against a pinned key before application | T-UPD-01 | V14.2 | — |
| SR-700 | Backup restore validates the whole archive first and rejects any entry whose canonical path escapes the target | T-BKP-01 | V12.3 | IDS04-J, FIO16-J |
| SR-701 | Format-version downgrade is refused unless explicitly forced with a fresh backup | T-MIG-01 | — | — |
| SR-702 | A format migration runs only after the old file authenticates; it keeps an owner-only rollback copy until the migrated file verifies on re-open, and on any failure leaves the original file in place (M7, ADR 0015) | T-MIG-01 | V12.3 | FIO02-J, ERR03-J |
| SR-703 | Backups contain only the encrypted vault plus a header (time, format version, content hash) authenticated by an HMAC under a key derived from the VK; backup files are owner-only and written by atomic rename; rotation keeps N and deletes only the oldest backups (M7, ADR 0015) | T-BKP-01 | V6.4 | FIO01-J, FIO02-J |
| SR-704 | Restore authenticates and fully decodes the backup before writing, refuses to replace an existing vault without explicit confirmation, keeps the replaced vault, and never leaves a partial file (M7, ADR 0015) | T-BKP-01 | V12.3 | FIO02-J, ERR03-J |
| SR-800 | Secret scanning runs on every PR and on full history; sample data is obviously fake | CI | V14.2 | MSC03-J |
| SR-801 | No JMX, JDWP, or debug entry points in release artifacts | T-PKG-01 | V14.3 | ENV05-J, ENV06-J |
| SR-900 | All Java complies with `RULES.md`; `certReport` shows zero findings for Enforced rules | CI | V1.1 | all |

## Generation and health (SR-06x, M4)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-070 | Generated passwords and passphrases draw randomness only from `pm.crypto.Csprng` in production (`RandomSource.secure()`); every index is drawn by rejection sampling, never by modulo reduction, so output is uniform over the policy's valid set (ADR 0012) | `UniformTest`, `PasswordGeneratorTest`, `PassphraseGeneratorTest` (chi-square on a fixed-seed DRBG; SecureRandom smoke) | V6.3 | MSC02-J |
| SR-071 | A password policy's "at least one of each class" rule is met by discarding whole candidates, and the reported entropy is log2 of the exact count of valid outputs (inclusion-exclusion); passphrases report 13 bits per word | `PasswordGeneratorTest.entropyIsTheExactCountOfValidPasswords`, `.aCandidateMissingAClassIsDiscardedWhole` | V2.1 | MSC02-J |
| SR-072 | Generator output is returned in `SecretChars`, never built in a `String` or a growing buffer; discarded candidates are zero-filled | R, `PasswordGeneratorTest.resultIsOwnedAndZeroedOnClose` | V6.2 | MSC03-J |
| SR-073 | The bundled wordlist is verified on load (8,192 distinct, sorted, `[a-z]{4,5}` words); a corrupt list fails loudly instead of silently lowering entropy | `PassphraseGeneratorTest.wordlistValidationRejectsCorruptLists` | — | IDS00-J |
| SR-074 | The breach check sends only the first 5 hex characters of the password's SHA-1 (`GET <base>range/<PREFIX>`, `Add-Padding: true`, no body, query or cookies); the remaining 35 are matched locally in constant time and zero-filled (k-anonymity, ADR 0012 §8) | `BreachClientTest` (T-HEALTH-01: fake loopback server records every request) | V8.3 | MSC00-J |
| SR-075 | Weak-password detection uses offline heuristics only, over Unicode code points: pool entropy; repeats; alphabet, digit and keyboard row/column runs; whole-password repeated units; common-list entries as whole password or substring, ignoring case and with substitutions undone; length. A whole common-list match is always `VERY_WEAK`, and a patterned password is never `STRONG`. No password `String` is built for the lookup | `StrengthMeterTest` | V2.1 | IDS00-J |
| SR-076 | Reuse detection compares per-call keyed HMAC-SHA-256 tags with `ConstantTime.equals`; no map of plaintext or unkeyed hashes exists, and key and tags are zero-filled before return | `ReuseAndAgeTest`, R | V6.2 | MSC03-J |
| SR-077 | Password age is measured from the record's update time against an injected `Clock`; future timestamps count as age 0 | `ReuseAndAgeTest`, `HealthCheckTest` | — | — |
| SR-078 | Network for the breach check is off unless explicitly invoked: `HealthCheck` is offline; `BreachClient` accepts only https (http on loopback for tests) without user info, query or fragment, never follows redirects, enforces one deadline over connect, headers and the whole body, and parses responses strictly (empty body is `MALFORMED`) with a 1 MiB cap | `BreachClientTest.offlineHealthCheckNeverTouchesTheNetwork`, `.baseUriValidation`, `.failuresCarryCodesOnly`, `.strictRangeParsing`, `.oneDeadlineCoversHeadersAndTheWholeBody` | V12.6 | MSC00-J, IDS01-J |

## Passkey keys, M6 (SR-080 to SR-084)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-080 | Passkey private keys are generated, loaded and used for signing only in `pm.crypto.passkey`; the P-256 scalar is held in a `SecretBytes` owned by `PasskeyKey` and leaves only as the storage form the vault encrypts at rest, through `pm.crypto.passkey.storage.PasskeyStorage`; `pm.crypto.passkey` is exported only to `pm.vault`, `pm.domain` and `pm.browser`, and `pm.crypto.passkey.storage` only to `pm.vault`, so the modules that sign cannot extract the scalar (qualified exports, ADR 0016; implements SR-402) | Compiler (qualified exports; planted `pm.browser` call refused at M6.1), CI (ArchUnit `onlyVaultDomainAndBrowserReachPasskeys`, `onlyTheVaultReachesPasskeyStorage`), `PasskeyKeyTest.secretsAreZeroedOnClose`, `.toStringNeverShowsKeyMaterial`, `PasskeyStorageTest`, `PasskeyAccessTest`, R | V6.2 | MSC03-J, OBJ01-J |
| SR-081 | A passkey scalar is drawn from `Csprng` by rejection sampling into [1, n-1]; a stored key is loaded only if it is exactly `0x01 \|\| d(32) \|\| 0x04 \|\| X(32) \|\| Y(32)`, d is in [1, n-1], the point decodes on P-256 with coordinates below p, and d·G equals the stored point (constant-time compare); anything else is `BAD_INPUT` | `PasskeyKeyTest.invalidStorageFormsAreRefused`, `.generationRejectsOutOfRangeCandidates`, `.generatedKeysAreDistinctAndRoundTripThroughStorage` | V6.2 | MSC02-J, IDS00-J |
| SR-082 | Assertion signatures are WebAuthn ES256 (alg -7): ECDSA P-256 with SHA-256 over `authenticatorData \|\| clientDataHash` (37 B to 16 KiB, exactly 32 B), ASN.1 DER `Ecdsa-Sig-Value`, nonce per RFC 6979 (HMAC-SHA-256); the verify helper accepts only canonical DER with r, s in [1, n-1] | `PasskeyKeyTest.rfc6979VectorsAreReproducedExactly` (RFC 6979 A.2.5), `.assertionSignatureIsDerOverAuthenticatorDataAndClientDataHash` (JDK SunEC verifier), `Es256Test` | V6.2 | IDS00-J |
| SR-083 | The credential public key is encoded as the CTAP2 canonical COSE_Key `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` (77 bytes, keys in order 1, 3, -1, -2, -3); decoding accepts only that exact layout with a point on the curve | `CoseKeyTest.encodingIsExactForAFixedKey`, `.anythingButTheCanonicalLayoutIsRefused` | V6.2 | IDS00-J |
| SR-084 | Credential IDs are 32 random bytes from `Csprng` | `PasskeyKeyTest.credentialIdsAreRandom32Bytes` | V6.3 | MSC02-J |

## Packaging and release (SR-71x, M7.3)

| ID | Requirement | Verification | ASVS | CERT |
| --- | --- | --- | --- | --- |
| SR-710 | The release runtime is a jlink image of only the JDK modules reached by the application's `requires` clauses (static ones included, since Lanterna needs `java.desktop` at run time) plus modules loaded only by service binding or reflection (`jdk.crypto.ec`, `jdk.unsupported`), stripped of debug data, headers and man pages; the build fails if it contains `jdk.jdwp.agent`, `jdk.management.agent`, `java.management`, `java.management.rmi`, `jdk.attach`, `java.instrument`, `jdk.jdi`, `jdk.jshell`, `jdk.jcmd` or `jdk.jstatd` (refines SR-801) | T-PKG-01 (`jlinkImage` self-check), `releaseSmoke` (TUI alive 30 s under a pty from the archive and app-image launchers) | V14.1 | ENV05-J, ENV06-J |
| SR-711 | The runtime image carries `-XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -XX:-CreateCoredumpOnCrash` in its jimage (`jlink --add-options`) and in the jpackage launcher config (`--java-options`) as defaults; the archive launcher clears `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS` and `CLASSPATH` and reads no JVM option from the environment except `PM_MAX_HEAP` (64m to 64g); `pm.cli.Main` exits 2 before any other work when `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` or `JDK_JAVA_OPTIONS` is non-empty. That refusal is detection, not prevention: the JVM has already applied the options (residual risk, docs/release/packaging.md) (refines SR-502) | T-PKG-01 (`jlinkImage` reads `-XX:+PrintFlagsFinal`), `MainJvmOptionsTest`, `EnvTest`, `releaseSmoke` (app-image with `JAVA_TOOL_OPTIONS` exits 2), R of `tools/packaging/launcher/` | V14.3 | ENV05-J, ENV06-J |
| SR-712 | Release archives (tar.gz, zip) are byte-reproducible: fixed entry timestamps, sorted entries, owner 0/0, permissions normalised to 0755/0644; the application jars and the jlink runtime inside them are byte-identical across clean builds with the same commit and JDK build | T-PKG-04 (`tools/packaging/repro-check.sh`, two clean builds; second machine: user-run) | V14.2 | ENV01-J |
| SR-713 | Every release ships a CycloneDX 1.5 JSON SBOM listing each runtime module jar with group, name, version, purl and SHA-256, the jlink runtime (JDK version, linked module list and the SHA-256 of its `lib/modules`) and the dependency graph, and a `SHA256SUMS` manifest (sorted `sha256sum -c` format) over every artifact including the SBOM; the build re-verifies the manifest and the jpackage app-image and dmg payload (runtime `lib/modules`, `release`, every jar) against the reproducible image | T-PKG-02, T-PKG-03 (`releaseMetadataCheck` in `check`), `verifyReleaseHashes`, `releaseSmoke` | V14.2 | — |
| SR-714 | Signing is a release-time hook driven only by environment variables (`PM_MAC_SIGN_IDENTITY`, `PM_NOTARY_PROFILE`, `PM_WIN_SIGN_CERT_SHA1`, `PM_GPG_KEY`); no key, certificate, password or profile is stored in the repository or the build, and a missing variable skips that step with a logged message instead of failing silently or signing with something else | R of `tools/packaging/release.gradle.kts`, gitleaks | V14.2 | MSC03-J |
