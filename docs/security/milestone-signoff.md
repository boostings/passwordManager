# Milestone Security Sign-off

## M0 — Product and security design

### Pipeline proof by planted failures (plan.md §13 M0 exit criteria)

Run locally on 2026-09-10 (macOS, JDK 21.0.12.1, Gradle 9.7.1, gitleaks 8.30.1,
Semgrep 1.176.0). Each plant was reverted immediately; none was committed.

| # | Plant | Detector(s) that fired | Result |
| --- | --- | --- | --- |
| 1 | `new java.util.Random()` in `pm-domain` (MSC02-J) | SpotBugs/FindSecBugs `PREDICTABLE_RANDOM` failed `spotbugsMain` (build exit 1); Semgrep `cert.MSC02-J.weak-random` independently reported 1 finding (exit 1) | **Caught** |
| 2 | Staged file containing a `ghp_` GitHub token pattern | `gitleaks git --staged`: "leaks found: 1" (exit 1); `gitleaks dir` on the file: "leaks found: 1" | **Caught** |
| 3 | `commons-collections:3.2.1` (CVE-2015-6420) added to `pm-domain` without verification metadata | Gradle dependency verification: "4 artifacts failed verification" (build exit 1) | **Caught** |

Note on plant 2: a first attempt using the AWS documentation example key
`AKIAIOSFODNN7EXAMPLE` was **not** flagged because gitleaks allowlists the
well-known example values. Recorded here so nobody mistakes that for a scanner
gap; realistic fixtures must be used in future proofs.

Note on plant 3: this proves the *unverified dependency* gate. A CVE-based
gate (OWASP Dependency-Check) is wired in CI as a non-blocking step until an
NVD API key is provisioned (user-only blocker, see docs/plans/M0.md). Until then, the
allowlist + verification metadata is the supply-chain control.

### Exit criteria status

| Criterion | Status | Evidence |
| --- | --- | --- |
| Threat model reviewed and signed off | Pending team review | `docs/security/threat-model.md` (Proposed) |
| Every Tier 1 module has a threat-model section | Done | TB-3/4 (crypto, storage), TB-5 (approval), TB-8/9 (sharing), TB-10/11 (browser) |
| CI fails a planted CERT violation, secret, and vulnerable dependency | Done (local) | table above; `build/planted/*.log` |
| `./gradlew check certReport` green | Done | 0 findings, 10 ArchUnit rules pass |
| ADRs 0002–0010 | Written, status Proposed | `docs/adr/` |
| CERT applicability table | Done | `docs/security/cert-applicability.md`: 177/177 (72 Enforced, 73 Review-only, 32 NA) |

Sign-off: ☐ security owner ☐ second reviewer (names per CODEOWNERS)

### Outstanding items carried into M1

- Team ratification of ADRs 0002–0010 (all Proposed) and the threat model.
- Replace placeholder handles in `CODEOWNERS`; enable branch protection with required checks `gate (ubuntu-22.04)`, `gate (macos-14)`, `gate (windows-2022)`, and two reviews on Tier 1 paths.
- Provision an NVD API key as a repository secret and make `dependencyCheckAggregate` blocking.
- Confirm JDK 21 exposes TLS exporter keying material (ADR 0010 open item) — spike at M3 start.
- Push to GitHub and observe the first real CI run on all three OS runners; local proof only so far.

## M1 gate correction (2026-10-02)

The M0 sign-off reported "PMD 0 findings", but PMD was not analyzing any files. Two rule
references in `tools/cert-rules/pmd-cert.xml` (`EmptyControlStatement`, `BadComparison`) do not
exist in PMD 7 under those paths, and the PMD run logged "No files to analyze" while the build
still passed. Semgrep's built-in ignore list also skipped every `src/test` directory.

Fixed: rule references corrected (`codestyle.xml/EmptyControlStatement`,
`errorprone.xml/ComparisonWithNaN`); deprecated `AvoidLosingExceptionInformation` replaced by
`UselessPureMethodCall`; root `.semgrepignore` added so tests are scanned. Proof: a planted
`if (x > 5)` in pm-crypto now fails `pmdMain` with `AvoidLiteralsInIfCondition`; the first
real PMD run found one genuine violation (`AvoidFieldNameMatchingMethodName` in
`CryptoException`), which is fixed; `semgrep --verbose` lists no files skipped by `.semgrepignore`.

## M1 — Local vault foundation

Evidence run: CI run 37138093559 on commit 80e0895, which holds all M1 code and passed `gate` on
ubuntu-22.04, macos-14 and windows-2022 plus `dependency vulnerabilities (SR-600)`. Commits after
80e0895 change only documentation and the CI trigger. Result lines below are copied from the
Gradle test reports in that run's `reports-<os>` artifacts, in the form
`<os>: N tests, F failures, S skipped`. The CERT compliance report in all three artifacts reads
`**Result: 0 findings.**` with `Semgrep cert pack 0`. Each lane signs its own section in a commit
`M1.4 <lane>: sign off <lane> exit criteria`.

### A

Owner: Lane A, pm-crypto, security owner (@boostings).

| Exit criterion | Proving test | Result (run 37138093559) |
| --- | --- | --- |
| Encrypt/decrypt round trip (crypto layer) | `AeadTest.openInvertsSeal` (jqwik property, 200 tries) plus `flippingAnyCiphertextBitFailsAuth` and `flippingAnyAadBitFailsAuth` | `AeadTest` ubuntu-22.04: 11 tests, 0 failures, 0 skipped<br>`AeadTest` macos-14: 11 tests, 0 failures, 0 skipped<br>`AeadTest` windows-2022: 11 tests, 0 failures, 0 skipped |
| Tags and secrets compared in constant time | `ConstantTimeReviewTest` (`noShortCircuitCompareOfSecretsOutsideCrypto`, `messageDigestIsEqualOnlyInsidePmCrypto`, a planted-compare detector check); `pm.crypto.ConstantTimeTest`; Semgrep `cert.CT-compare.non-constant-time` | `ConstantTimeReviewTest` ubuntu-22.04: 4 tests, 0 failures, 0 skipped<br>`ConstantTimeReviewTest` macos-14: 4 tests, 0 failures, 0 skipped<br>`ConstantTimeReviewTest` windows-2022: 4 tests, 0 failures, 0 skipped<br>`pm.crypto.ConstantTimeTest` ubuntu-22.04: 4 tests, 0 failures, 0 skipped<br>`pm.crypto.ConstantTimeTest` macos-14: 4 tests, 0 failures, 0 skipped<br>`pm.crypto.ConstantTimeTest` windows-2022: 4 tests, 0 failures, 0 skipped<br>Semgrep cert pack 0 on all 3 OSes |
| No secret in a String outside `@SecretBoundary` (pm-crypto share) | Semgrep `cert.MSC03-J.secret-in-string` | Semgrep cert pack 0 on all 3 OSes |

Notes:
- The sprint table names `AeadProperties`, but no class by that name exists. The round-trip
  property lives in `AeadTest.openInvertsSeal`, which is the test cited here.
- CERT exceptions: CE-001..CE-005 were re-checked against the code, and CE-006 was added for an
  `ArrayRecordComponent` suppression that had no ledger row. All six are signed off in
  `docs/security/cert-exceptions.md`. `plan.md` "Project status" records M1.
- M0 carry-over "first real CI run on all three OS runners" is closed: run 37136437530 was the
  first green run. CI is manual-only (`workflow_dispatch`) from 2026-10-03.
- Open, not blocking M1: `pm.vault.envelope.Bytes.sameContents` hand-rolls a constant-time loop
  (correct, but it should call `pm.crypto.ConstantTime.equals`); ADR 0004 has no ArchUnit rule that keeps
  the VK out of direct GCM use, and T-ENC-01 is an example test, not a property. Tracked for M2.

Signed off: Lane A (@boostings), security owner.

### B

Owner: Lane B, pm-storage (@Ra1ny1).

| Exit criterion | Proving test | Result (run 37138093559) |
| --- | --- | --- |
| Killing mid-save never corrupts (step-injected; real kill test in M7) | `AtomicWriteCrashTest.failedReplacementLeavesExactlyAnOldOrNewVault`, `stagingFileIsPrivateBeforeAnyBytesAreWritten` (parameterised over every `VaultFileStore.Step`) | `AtomicWriteCrashTest` ubuntu-22.04: 10 tests, 0 failures, 0 skipped<br>`AtomicWriteCrashTest` macos-14: 10 tests, 0 failures, 0 skipped<br>`AtomicWriteCrashTest` windows-2022: 10 tests, 0 failures, 0 skipped |
| File permissions on all 3 OSes | `OwnerOnlyTest`, `VaultPermissionsTest` on the CI matrix | `OwnerOnlyTest` ubuntu-22.04: 5 tests, 0 failures, 2 skipped<br>`OwnerOnlyTest` macos-14: 5 tests, 0 failures, 2 skipped<br>`OwnerOnlyTest` windows-2022: 5 tests, 0 failures, 1 skipped<br>`VaultPermissionsTest` ubuntu-22.04: 1 tests, 0 failures, 0 skipped<br>`VaultPermissionsTest` macos-14: 1 tests, 0 failures, 0 skipped<br>`VaultPermissionsTest` windows-2022: 1 tests, 0 failures, 0 skipped |
| No secret in a String outside `@SecretBoundary` (pm-storage share) | Semgrep `cert.MSC03-J.secret-in-string` | Semgrep cert pack 0 on all 3 OSes |

Notes:
- The `OwnerOnlyTest` skips are by design: the two ACL tests run only where the file system
  supports ACLs (Windows) and the POSIX-mode test runs only on POSIX (Linux, macOS). Every OS ran
  the platform-specific checks that apply to it, and `restrictsFilesAndDirectories` ran everywhere.

Signed off: Lane B (@Ra1ny1).

### C

Owner: Lane C, pm-vault envelope and service (@bzgoering).

| Exit criterion | Proving test | Result (run 37138093559) |
| --- | --- | --- |
| Byte flip detected before any record is parsed | `TamperTest.everySingleByteFlipFailsBeforeAnyRecordIsParsed`, `sampledFlipsFailThroughFullPassphraseUnlock` | `TamperTest` ubuntu-22.04: 3 tests, 0 failures, 0 skipped<br>`TamperTest` macos-14: 3 tests, 0 failures, 0 skipped<br>`TamperTest` windows-2022: 3 tests, 0 failures, 0 skipped |
| KDF always completes | `SlotCryptoWorkFactorTest.wrongPassphraseRunsArgon2idOnceWithTheHeaderParamsLikeTheRightOne`, `wrongPassphraseIsNotMeasurablyFasterThanTheRightOne`, `outOfRangeHeaderNeverReachesArgon2id` | `SlotCryptoWorkFactorTest` ubuntu-22.04: 6 tests, 0 failures, 0 skipped<br>`SlotCryptoWorkFactorTest` macos-14: 6 tests, 0 failures, 0 skipped<br>`SlotCryptoWorkFactorTest` windows-2022: 6 tests, 0 failures, 0 skipped |
| Create/unlock/lock/save, passphrase, recovery key | `VaultServiceTest` (`createThenUnlockWithPassphraseThenWithRecoveryKey`, `closeLocksAndIsIdempotent`, `saveSeqIncreasesOnEverySave`, `wrongPassphraseIsWrongCredential`, recovery-key cases) | `VaultServiceTest` ubuntu-22.04: 21 tests, 0 failures, 0 skipped<br>`VaultServiceTest` macos-14: 21 tests, 0 failures, 0 skipped<br>`VaultServiceTest` windows-2022: 21 tests, 0 failures, 0 skipped |
| No secret in a String outside `@SecretBoundary` (pm-vault share) | Semgrep `cert.MSC03-J.secret-in-string` | Semgrep cert pack 0 on all 3 OSes |

Notes:
- Fixed during sign-off: an Argon2 run larger than the free heap was reported as `CORRUPT`. It is
  now `INSUFFICIENT_MEMORY` on both create and unlock (CLI exit 7). Proved by
  `createNeedingMoreArgon2MemoryThanTheHeapIsInsufficientMemory` and
  `unlockOfHeaderNeedingMoreArgon2MemoryThanTheHeapIsInsufficientMemory`, which fail with
  `expected: <INSUFFICIENT_MEMORY> but was: <CORRUPT>` without the fix and pass in this run.

Signed off: Lane C (@bzgoering).

### D

Owner: Lane D, pm-vault CBOR and records (@M0hayan).

| Exit criterion | Proving test | Result (run 37138093559) |
| --- | --- | --- |
| Corrupted input never gives a partial record | `RecordCodecTest.truncationNeverPartial`, `singleBitFlipNeverYieldsAShorterList` (jqwik properties) | `RecordCodecTest` ubuntu-22.04: 24 tests, 0 failures, 0 skipped<br>`RecordCodecTest` macos-14: 24 tests, 0 failures, 0 skipped<br>`RecordCodecTest` windows-2022: 24 tests, 0 failures, 0 skipped |
| Login/Wi-Fi/SSH/Project records | `RecordCodecTest.roundTripsOneRecordOfEachType` plus per-type validation tests | `RecordCodecTest` ubuntu-22.04: 24 tests, 0 failures, 0 skipped<br>`RecordCodecTest` macos-14: 24 tests, 0 failures, 0 skipped<br>`RecordCodecTest` windows-2022: 24 tests, 0 failures, 0 skipped |
| Decoders survive hostile input | Jazzer fuzz targets (regression mode in the gate); long runs in `docs/security/fuzz/M1-fuzz-runs.md`: 19,445,362 / 13,976,479 / 17,807,331 executions, 0 crashes | `CborReaderFuzzTest` ubuntu-22.04: 7 tests, 0 failures, 0 skipped<br>`CborReaderFuzzTest` macos-14: 7 tests, 0 failures, 0 skipped<br>`CborReaderFuzzTest` windows-2022: 7 tests, 0 failures, 0 skipped<br>`RecordCodecFuzzTest` ubuntu-22.04: 9 tests, 0 failures, 0 skipped<br>`RecordCodecFuzzTest` macos-14: 9 tests, 0 failures, 0 skipped<br>`RecordCodecFuzzTest` windows-2022: 9 tests, 0 failures, 0 skipped<br>`EnvelopeFuzzTest` ubuntu-22.04: 8 tests, 0 failures, 0 skipped<br>`EnvelopeFuzzTest` macos-14: 8 tests, 0 failures, 0 skipped<br>`EnvelopeFuzzTest` windows-2022: 8 tests, 0 failures, 0 skipped |
| No secret in a String outside `@SecretBoundary` (pm-vault records share) | Semgrep `cert.MSC03-J.secret-in-string` | Semgrep cert pack 0 on all 3 OSes |

Signed off: Lane D (@M0hayan).

### E

Owner: Lane E, pm-cli and pm-tui (@Jstacs78).

| Exit criterion | Proving test | Result (run 37138093559) |
| --- | --- | --- |
| TUI dashboard and search | `DashboardTest` (`rightPassphraseShowsDashboard`, `tableListsRecordsWithoutSecrets`, `typingInSearchFiltersRows`, `searchWithNoMatchShowsEmptyTable`) | `DashboardTest` ubuntu-22.04: 28 tests, 0 failures, 0 skipped<br>`DashboardTest` macos-14: 28 tests, 0 failures, 0 skipped<br>`DashboardTest` windows-2022: 28 tests, 0 failures, 0 skipped |
| Auto-lock | `IdleLockTest` (`firesAtTimeout`, `touchAtFourMinutesDefersLockToNine`, `closePreventsFiring`) | `IdleLockTest` ubuntu-22.04: 13 tests, 0 failures, 0 skipped<br>`IdleLockTest` macos-14: 13 tests, 0 failures, 0 skipped<br>`IdleLockTest` windows-2022: 13 tests, 0 failures, 0 skipped |
| End-to-end CLI create/unlock/add/list | `EndToEndTest`; transcript `docs/security/transcripts/M1-e2e-cli.txt` | `EndToEndTest` ubuntu-22.04: 1 tests, 0 failures, 0 skipped<br>`EndToEndTest` macos-14: 1 tests, 0 failures, 0 skipped<br>`EndToEndTest` windows-2022: 1 tests, 0 failures, 0 skipped |
| No secret on CLI output | `CanaryTest` | `CanaryTest` ubuntu-22.04: 13 tests, 0 failures, 0 skipped<br>`CanaryTest` macos-14: 13 tests, 0 failures, 0 skipped<br>`CanaryTest` windows-2022: 13 tests, 0 failures, 0 skipped |
| No secret in a String outside `@SecretBoundary` (pm-cli/pm-tui share) | Semgrep `cert.MSC03-J.secret-in-string` | Semgrep cert pack 0 on all 3 OSes |

CI `gate` was green on all three OSes for the evidence run, and the final manual run is
recorded with tag `m1` below.

Signed off: Lane E (@Jstacs78).

## M2 — Environment sharing

Evidence: local runs on 2026-10-03 at commit M2.7 (this section's commit). M1 used a CI run as
evidence; for M2 the manual CI workflow has **not** been dispatched yet, because that needs the
branch pushed and nothing is pushed without the owner's approval. Until then the rows below rest
on these local runs:

- Full gate on macOS 27.0 arm64, JDK 21.0.12.1:
  `./gradlew --rerun-tasks check certReport gitleaksScan`. Result: `BUILD SUCCESSFUL`,
  `**Result: 0 findings.**`, gitleaks "no leaks found", 804 tests from committed sources, 0 failures.
- Linux filesystem trace in Docker (eclipse-temurin:21-jdk, Ubuntu, linux/aarch64) with
  `tools/ci/env-run-trace.sh`: `env-run-trace: PASS`.

| Exit criterion (plan.md §13 M2) | Proving test | Local result |
| --- | --- | --- |
| `env run` never writes to disk, verified with filesystem tracing | `EnvRunNoDiskWriteTest`: real file vault; every file under home, repository and vault fingerprinted before and after; only `audit.log` and `audit.log.head` change; no file holds the value. `tools/ci/env-run-trace.sh` runs the test under `strace -ff` and checks every create, write, rename and link by the test JVM and its children between the test's markers (CI Linux job step added) | `EnvRunNoDiskWriteTest` macOS: 1 test, 0 failures, 0 skipped. Linux strace: `40 syscalls from 39 threads/processes in 0.184 s; 6 successful writes checked; 2 execve in window`, `PASS, only the audit log, its head and the vault lock were written`. Planted check: a synthetic `openat(... "/tmp/leaked.env", O_WRONLY\|O_CREAT ...)` added to a copy of that trace gives `FAIL ... /tmp/leaked.env`, exit 1 |
| Child launched via `ProcessBuilder` with an argument list, never a shell; the command shown is the command run | `EnvRunnerTest.argvShownIsArgvExecutedWithoutShellExpansion` (`$(...)`, backticks, `;`, `*` arrive literally); `EnvCommandsTest.standaloneRunShowsTheExactArgvAndRunsItAfterY`; `ApprovalDialogTest.promptShowsRequesterScopeAndEveryArgvElementOnItsOwnLine`; ArchUnit `onlyTheEnvRunnerSpawnsProcesses` and Semgrep `cert.IDS07-J.processbuilder-outside-approval`, both narrowed to `pm.approval.run.EnvRunner` | `EnvRunnerTest` 5/0/0, `EnvCommandsTest` 16/0/0, `ApprovalDialogTest` 7/0/0, `ModuleBoundaryTest` 10/0/0 (tests/failures/skipped). Planted `new ProcessBuilder("true")` in `pm.approval.PlantedSpawn` failed `onlyTheEnvRunnerSpawnsProcesses` ("violated (1 times)"), then removed |
| Broker IPC authenticated per platform; PID never the identity; unauthenticated requests rejected and logged | `BrokerIpcTest` (`wrongTokenIsDeniedAndAudited`, `oversizedFrameIsRejectedBeforeReadingAndAudited`, `peerRunningAsAnotherUserIsDenied`, `stolenOldTokenIsUselessAfterRotation`, `unsafeRunDirectoriesAreRefused`, `linkedTokenFileIsRefused`); `SocketApprovalHostTest` | `BrokerIpcTest` 11/0/0, `SocketApprovalHostTest` 2/0/0 |
| Approval timeout denies (fail closed) | `ApprovalBrokerTest.unansweredPromptTimesOutAsDeny`; `ApprovalDialogTest.anUnansweredPromptIsDeniedAfterTheTimeout`, `lockingDeniesTheWaitingPromptAndClosesIt` | `ApprovalBrokerTest` 16/0/0, `ApprovalDialogTest` 7/0/0 |
| `.env` parser fuzzed for 24 CPU-hours with no crash or hang | `DotEnvFuzzTest` (Jazzer; regression mode in the gate replays the committed seeds) | **Open, owner's to schedule.** A 30-minute local campaign is recorded in `docs/security/fuzz/M2-fuzz-runs.md`. Gate: `DotEnvFuzzTest` 8/0/0 |
| Scope escalation: an approve-once decision cannot be reused | `ApprovalBrokerTest.approveOnceCannotBeReused`, `row3ReplayedOrStaleRequestsAreRefused`, `injectRequestsMustShowWhatRuns` | `ApprovalBrokerTest` 16/0/0 |

Deviations from plan.md, accepted at this sign-off:

- **Windows transport.** plan.md names a named pipe with a user-SID DACL. ADR 0009 Amendment 1
  (M2.4) uses the same Unix domain socket on Windows 10 1803+ in an owner-only-ACL directory,
  because the JDK has no named-pipe server API. Windows has no peer credentials in the JDK, so
  the session token and the directory ACL are the controls there. approval-model §5 was
  corrected at M2.7 to match; it still described the M0 named-pipe draft.
- **"The broker is the parent of the child."** The runner executes in the `pm env run` process
  after the TUI-hosted broker releases the approved values over the authenticated socket
  (approval-model §6). The request's identity is the token plus peer uid, and the argv that runs
  is the argv in the approved request, checked by `EnvRunner` (`NOT_APPROVED` otherwise).
- **Approval-dialog rendering.** The dialog renders argv elements through `DisplaySafe`, which
  replaces control characters, so the screen is byte-identical to what runs only for printable
  text. Arguments longer than 72 columns, or more than 12 arguments, are shortened with a red
  "shortened for display" warning.

CERT exceptions: the M2 sweep is recorded at the top of `docs/security/cert-exceptions.md`. CE-002
was extended, CE-007 was signed off, and CE-008..CE-010 were added. Every suppression in the tree
maps to one row.

Open, not blocking M2:
- The 24 CPU-hour `.env` campaign (owner's to schedule on a long-running machine).
- Dispatching the manual CI workflow on all three OSes, which includes the new Linux strace step.
  This needs the branch pushed.
- M1 carry-overs still open: `pm.vault.envelope.Bytes.sameContents` should call
  `pm.crypto.ConstantTime.equals`; there is no ArchUnit rule keeping the VK out of direct GCM use.

Signed off: Lane A (@boostings), security owner.

## M3 — LAN sharing (protocol layer, M3.1–M3.5)

**Scope.** This sign-off covers the protocol layer: device identity and pairing crypto (M3.1), the
wire format (M3.2), the pairing ceremony (M3.3), share windows and their sessions (M3.4), and
browser-only receiving (M3.5). It does not cover the CLI/TUI exposure of these features (M3.6:
`devices`, `pair`, `share`, `receive`, `revoke`, and removing a revoked device's pinned key from the
vault, SR-205/SR-208). That was reviewed at its own integration, recorded under "M3.6 CLI/TUI
integration" below; TM-30 (discovery) and TM-37 (apply) are Implemented (M3.6) there.

Evidence: local runs on 2026-10-03 (fuzz campaign) and 2026-10-04 (planted-bug checks and the gate) at commit M3.7 (this section's commit). As with M2, the manual
CI workflow has **not** been dispatched, because nothing is pushed without the owner's approval.

- Full gate on macOS 27.0 arm64, JDK 21.0.12.1:
  `./gradlew --rerun-tasks check certReport gitleaksScan`. Result: `BUILD SUCCESSFUL`, `**Result: 0 findings.**`,
  gitleaks "no leaks found", 1336 tests from committed sources, 0 failures or errors.
- pm-sharing branch coverage stays at 100 %: `:modules:pm-sharing:jacocoTestCoverageVerification`
  ran in the gate and passed. M3.7 changed no pm-sharing main code.
- Fuzz campaign over the four new harnesses: 40 minutes, 19,348,851 executions, 0 crashes. Details
  are in `docs/security/fuzz/M3-fuzz-runs.md`.

| Exit criterion (plan.md §13 M3) | Proving test | Local result |
| --- | --- | --- |
| Protocol fuzzed against the state machine; malformed messages never reach domain code | `LanCodecFuzzTest` (framing and codec: only documented errors, every accepted field within the CDDL bounds restated in the harness, one spelling per message; oversized frame headers refused before any body byte is read); `PairingSessionFuzzTest` (both roles, crafted and out-of-order messages: `DONE` only with an opened commitment, the right MAC recomputed with `pm.crypto.Pairing`, and a human confirmation); `ShareSessionFuzzTest` (crafted, replayed, dropped and renumbered messages, clock moves, revocations: the receiver's applier only ever sees the exact payload of a live, unrevoked window for that device, at most once for one-use); `WebRouteFuzzTest` (routing and request-head parsing: raw and assembled heads fed to `requestLine` and `route` directly; the seeds are also replayed over real loopback TLS). Each harness replays its seeds in the gate, and a seed test checks each seed ends in its labelled state, so the accepting branches of every oracle run | 40 min campaign, 19,348,851 executions, 0 crashes, 0 oracle violations (M3-fuzz-runs.md). Gate: `LanCodecFuzzTest` 25/0/0, `PairingSessionFuzzTest` 9/0/0, `ShareSessionFuzzTest` 7/0/0, `WebRouteFuzzTest` 8/0/0 (tests/failures/skipped) |
| Replay, pairing-code reuse, expired share and revoked device all fail closed | Replay: `ShareSessionTest.theSameShareOfferedAgainIsAReplay`, `ShareServerTest.aReusableShareReceivedTwiceIsAReplayOnTheSecondTime`, `SequenceAndOctetsTest`. Pairing reuse: fresh nonces per run (`PairingSessionTest.theRealNonceSourceGivesDistinctDigitsPerRun`), a commitment that opens only with its key and nonce (`PairingTest.aCommitmentOpensOnlyWithItsKeyAndNonce`), lockout (`LockoutTest`, `PairerTest.failuresAreCountedAndTheThirdLocksPairing`). Expiry: `ShareSessionTest.anOfferThatHasExpiredByTheReceiversClockIsRefused`, `theSenderEnforcesExpiryAndRevocationAtTheAccept`. Revoked device: `SharesTest.revokingAShareOrItsDeviceClosesTheWindow`, `ShareServerTest.aRevokedOrUntrustedOrUnofferedDeviceFailsTheHandshake` | `ShareSessionTest` 11/0/0, `ShareServerTest` 9/0/0, `SharesTest` 7/0/0, `SequenceAndOctetsTest` 4/0/0, `PairingSessionTest` 13/0/0, `PairingTest` 8/0/0, `LockoutTest` 2/0/0, `PairerTest` 8/0/0 |
| Listener lifetime: no open port after share expiry | `ShareServerTest.theListenerClosesWhenTheLastWindowExpires`, `aOneUseShareIsDeliveredThenTheListenerClosesAndFreesThePort`; `WebServerTest.theListenerClosesAtExpiryWithoutDelivering`, `pageUntilTheDataIsFetchedOnceThenThePortIsClosed`, `closeStopsTheListenerAndFreesThePort`, `aSlowClientIsCutOffAtTheConnectionDeadline` | `ShareServerTest` 9/0/0, `WebServerTest` 9/0/0 |
| Browser page passes a CSP audit and holds no data after expiry | `WebPageTest` (the CSP hash matches the only script; no storage APIs or markup sinks); `WebServerTest.afterExpiryOrCloseEverythingIsGone` (410 for everything after expiry and close); `NodePageTest` (the real inline script decrypts under Node WebCrypto); a headless Chrome check by hand at M3.5 | `WebPageTest` 2/0/0, `WebServerTest` 9/0/0, `NodePageTest` 1/0/0. The browser's own history database keeps the key; see residual risk below |
| External review of the pairing and SAS construction | None; this is a review, not a test | **Open, user-only.** Listed in docs/plans/M2-M7.md. Must happen before v1 ships |

Design changes accepted at this sign-off:

- **ADR 0010 Amendment 1 (M3.1): commit-then-reveal SAS, no TLS exporter.** As first written, the
  SAS came from values each side contributed without committing to them first. A machine in the
  middle could therefore grind its own contribution offline, about 10^6 tries, until both victims
  saw the same 6 digits. Now the initiator commits to `n_I` under its key before it sees `n_R`, so
  each victim's digits contain a random value the attacker had to fix in advance. Each attempt
  succeeds with probability 10^-6, and the lockout caps attempts. JDK 21 has no RFC 8446 exporter
  (`javap javax.net.ssl.ExtendedSSLSession` shows none), so the SAS binds both certificate keys
  through HKDF `info` instead of an exporter. The 20-bit reduction bias was also corrected to
  64 bits mod 10^6. `PairingSessionTest.aRelayingAttackerLeavesTheVictimsWithDifferentDigits` and
  `aForwardedConfirmationFromTheOtherLegDoesNotVerify` show the relay failing.
- **ADR 0010 Amendment 2 (M3.5): browser-only receiving.** No browser accepts an Ed25519 server
  certificate. Each browser share therefore gets a throwaway ECDSA P-256 identity
  (`pm.crypto.WebIdentity`). It is valid only for the share window, names the listener IP, and is
  never stored. The CSP gains `connect-src 'self'` so the page can fetch its ciphertext. The
  one-message key uses a zero nonce through `Aead.sealWithFreshKey`.

M3.5 adversarial-review fixes (all in M3.5, regression-tested in `WebServerTest`; the routing ones,
strict version and page-before-data, are also fuzzed by `WebRouteFuzzTest`):

- **Trickling client.** A client sending one byte at a time kept the listener open past expiry and
  was then served the ciphertext. A 5 s per-connection watchdog now closes it
  (`aSlowClientIsCutOffAtTheConnectionDeadline`).
- **In-flight revocation.** `close()` did not stop a request already being read. It now cuts it off
  (`closeCutsOffARequestInFlight`).
- **Page burning by link previews.** The page was served once, so a chat app's link preview, or one
  `curl`, locked the real recipient out. The page is now served until the ciphertext is fetched,
  and only `/d/<id>` is one-time (`pageUntilTheDataIsFetchedOnceThenThePortIsClosed`).
- **Strict HTTP version.** Only `HTTP/1.0` and `HTTP/1.1` request lines are accepted
  (`routeRefusesMalformedRequestsAndOtherMethods`).
- **History database, documented residual risk.** `history.replaceState` clears the fragment from
  the address bar, but Chrome has already written the full URL, key included, to its History
  database, and it may sync. No page script can remove it. The key opens only this share's
  ciphertext, which is served once and never after expiry. The TUI (M3.6) must tell the sender to
  keep windows short and suggest a private window. The other residual risk stays as well: a
  network attacker answering the first request (ADR 0010 §7). The recipient's only defence is the
  certificate fingerprint, and paired-device sharing remains the default.

The fuzz campaign found no defect, and no pm-sharing main code changed in M3.7. An adversarial
review then planted a missing field-length check and a loosened frame bound, and the first harness
missed both. The oracles were strengthened and each planted bug is now caught; see "Oracle checks
after the adversarial review" in M3-fuzz-runs.md. Traceability status meaning was changed
explicitly at the same time: "Implemented" means the local gate, not CI (traceability.md, top).

CERT exceptions: no suppression was added in M3.7, so CE-040..CE-044 are unused. The M3 rows added
earlier (CE-011..CE-013) are unchanged.

Open, not blocking the M3 protocol layer:
- **External review of the pairing/SAS construction (ADR 0010 Amendment 1). User-only; required
  before v1 ships.**
- Longer fuzz runs: the campaign was 10 minutes per harness. `WebRouteFuzzTest` runs at about
  600 exec/s because each input binds a listener socket. The accept loop and TLS path are
  exercised only by the seed replay over TLS and by `WebServerTest`, not fuzzed.
- Dispatching the manual CI workflow (needs the branch pushed). The M2 carry-overs are unchanged.

Signed off: Lane A (@boostings), security owner, for the protocol layer M3.1–M3.5.

### M3.6 CLI/TUI integration (closed)

Closed in the M3.6 commit (lane E): `pm devices`, `pair`, `share`, `receive`, `revoke` and the TUI
Devices screen and Share dialog, with the device identity and trust list as vault records (SR-090),
pinned-key removal (SR-205), apply only after full verification (SR-208) and the Amendment 2 sender
warnings (SR-092). TM-30 and TM-37 are Implemented (M3.6), tagged T-LAN-01, T-LAN-02, T-LAN-08 on
`LanEndToEndTest`, `LanScreensTest` and `LanHelpersTest`; TM-34's SR-205 half is Implemented (M3.6).
Evidence: the full local gate on the M3.6 commit (`./gradlew check certReport gitleaksScan`).

Review fixes made before merge (each regression-tested):
- **SR-205 (high): a removed device could still receive from a window already open in another
  process.** Removal now writes an owner-only marker first, in a directory next to the vault's real
  path (re-review: not in the run directory, which follows `XDG_RUNTIME_DIR` and so could differ
  between the remover and the sender); every window re-checks it at TLS accept and before
  `SHARE_DATA` and revokes itself (SR-095;
  `LanEndToEndTest.removingADeviceInAnotherProcessClosesAWindowAlreadyOpenToIt`,
  `LanEndToEndTest.removalReachesAWindowOpenedUnderAnotherRunDirectory`,
  `SharesTest.aDeviceNoLongerAdmittedGetsNoDataEvenAfterTheOffer`).
- **SR-203 (medium): the lockout reset with every `pm pair`.** It is now kept in an owner-only
  run-directory file, a stored lock is capped at 1 h ahead, an unreadable one locks (SR-096;
  `LanEndToEndTest.thePairingLockoutHoldsForTheNextPairInvocation`, `LockoutTest`). Re-review: a
  concurrent pairing could overwrite the stored lock with its stale clean state; every write is now
  a read-merge-write under an exclusive file lock, and a file that is unreadable or not owner-only
  locks for 1 h (`LanEndToEndTest.aConcurrentPairingNeverWeakensThePersistedLockout`,
  `LanHelpersTest.thePairingLockoutIsMergedAcrossProcessesAndFailsClosed`). Deleting the file is a
  same-user residual (lan-share.md §8.1).
- **TUI question hijack (medium).** Questions are queued and each answer reaches only the question
  on screen; new steps and Remove wait (`LanScreensTest.anAnswerOnlyReachesTheQuestionOnScreenAndASecondOneWaits`).
- **Low:** `--bind` refuses wildcards and non-local addresses; the receive replay guard is kept in
  the vault and saved with the item (SR-097); the payload must match the accepted offer's kind and
  summary (SR-098); the TUI share records nothing for a device removed since the list was shown;
  CE-035 narrowed from class level to method level; exit code 10 documented in the README.

CERT exceptions CE-035..CE-039 (M3.6) remain Proposed, awaiting the security owner's sign-off.
The external SAS review and the CI dispatch above stay open.
