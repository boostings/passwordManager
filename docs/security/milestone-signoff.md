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

## M4 — Health and SSH workflows (M4.1–M4.5)

**Scope.** This section covers:
- password and passphrase generation (M4.1, Lane C);
- offline health checks and the opt-in breach client (M4.2, Lane C);
- the ssh-agent client and the `openssh-key-v1` parser and export (M4.3, Lane A);
- their CLI and TUI exposure (M4.4, Lane E);
- this security exit (M4.5, Lane A): three new Jazzer harnesses, the ledger and traceability
  sweeps, and this section.

Evidence: local runs on 2026-10-05 at commit M4.5 (this section's commit, amended at the M4.5
review). As with M2 and M3, the
manual CI workflow has **not** been dispatched, because nothing is pushed without the owner's
approval.

- Full gate on macOS 27.0 arm64, JDK 21.0.12.1:
  `./gradlew --rerun-tasks check certReport gitleaksScan`. Result: `BUILD SUCCESSFUL`,
  `**Result: 0 findings.**`, gitleaks "no leaks found", 1565 tests from committed sources,
  0 failures or errors, 8 skipped.
- Fuzz campaign over the three rebuilt harnesses: 15 minutes (5 per harness), 5,216,945
  executions, 0 crashes. All 9 bugs the review planted in main code were caught in 2-minute runs,
  also with the seeds that trip them withheld, and each was reverted. The OpenSshKey 5 minutes
  ran before the gate's static-analysis fixes to that harness (no oracle changed); its repeat on
  the final harness was cut to about 100 s awake by a closed lid (510,132 executions, 0 crashes).
  Details are in `docs/security/fuzz/M4-fuzz-runs.md`.

Test counts below are tests/failures/skipped from this gate run's JUnit reports.

| Lane, phase | Exit criterion (plan.md §13 M4, plus the phase's acceptance line) | Proving test | Local result |
| --- | --- | --- | --- |
| C, M4.1 | The generator uses `SecureRandom` and passes statistical tests (MSC02-J) | Production randomness is `pm.crypto.Csprng`, the codebase's only `SecureRandom` (`RandomSource.secure()`; ArchUnit `onlyCryptoUsesJca` keeps every other JCA use in pm-crypto). `UniformTest` covers rejection sampling with no modulo reduction. `PasswordGeneratorTest.chiSquareUniformPerPosition`, `.chiSquareUniformWithinEachClass` and `PassphraseGeneratorTest.chiSquareUniformOverWords` run on a fixed-seed DRBG. `PasswordGeneratorTest.chiSquareDetectsModuloBias` is the planted-bias control: the test fails a modulo-reduced generator. `PassphraseGeneratorTest.secureRandomSmoke` draws from the real source | `UniformTest` 6/0/0, `PasswordGeneratorTest` 11/0/0, `PassphraseGeneratorTest` 7/0/0, `ModuleBoundaryTest` 16/0/0 |
| C, M4.2 | Online checks use k-anonymity range queries only, and network capture in test shows no full hash leaves the machine | T-HEALTH-01 `BreachClientTest.serverSeesOnlyAFiveCharacterPrefixAndCountIsMatchedLocally`: a recording loopback server sees every request's method, path and headers, and only `/range/<5 hex>` arrives. Also `.offlineHealthCheckNeverTouchesTheNetwork`, `.baseUriValidation`, `.strictRangeParsing` and `.oneDeadlineCoversHeadersAndTheWholeBody` | `BreachClientTest` 9/0/0 |
| A, M4.3 | ssh-agent socket handling passes the CERT FIO rules and never exposes private key bytes to the TUI layer | FIO: `SshAgentClientTest` covers relative and root paths, group- or world-writable directories, links, regular files, another user's socket, and the listening process checked after connect (`SO_PEERCRED`). Key bytes: the qualified export `exports pm.crypto.ssh to pm.cli` (CE-021; a planted `pm.tui` reference failed to compile at M4.3) and ArchUnit `onlyTheCliReachesSshKeys` and `noCryptoFacadeOverSshKeys`. The parser and export are covered by `SshKeyTest` and `SshKeyExportTest` | `SshAgentClientTest` 24/0/0, `SshKeyTest` 18/0/0, `SshKeyExportTest` 4/0/0, `ModuleBoundaryTest` 16/0/0 |
| E, M4.4 | CLI tests for `generate`, `health` and `ssh add/remove/export`. The breach check stays opt-in, and a stalled agent cannot freeze the TUI | `GenerateCommandTest`; `HealthCommandTest` (no client without `--breach` and an exact `y`; one prefix per distinct password); `SshCommandsTest`; `ToolsTest` (TUI agent calls run off the GUI thread, and lock tears the dialog down) | `GenerateCommandTest` 8/0/0, `HealthCommandTest` 10/0/0, `SshCommandsTest` 18/0/0, `ToolsTest` 9/0/0 |
| A, M4.5 | Hostile key files, agent replies and range responses are refused with documented codes only, within bounds, with no crash or hang | T-FUZZ-SSH `OpenSshKeyFuzzTest`, `AgentReplyFuzzTest`; T-FUZZ-BREACH `BreachRangeFuzzTest`. The oracles are independent: an exact expected code from a header model, an armour grammar, harness-side spec limits, a round trip, a differential reference parser, allocation tied to the limits. Each harness has deterministic at-limit and one-past-limit tests, and all 9 bugs planted by the review were caught | 5 min per harness: 1,170,913 + 3,969,400 + 76,632 executions, 0 crashes. Review plants: all 9 caught in 2-minute runs; with their tripping seeds withheld, by mutation alone after 18 to 95,356 executions. Gate: `OpenSshKeyFuzzTest` 21/0/0, `AgentReplyFuzzTest` 21/0/0, `BreachRangeFuzzTest` 11/0/0 |

Review findings fixed during M4, as recorded in each phase's result in docs/plans/M2-M7.md and
its commit. They were not re-derived at M4.5; the regression tests named for them are in the gate:

- **M4.1:** the adversarial review re-ran the chi-square at 10^6 draws, and it passed. Offensive
  words were screened out of the bundled list (ADR 0012).
- **M4.2:** 5 defects fixed. The strength meter now works on code points and detects repeats,
  keyboard runs and common substrings; one deadline covers connect, headers and the whole body;
  an empty body is `MALFORMED`.
- **M4.3:** 7 defects fixed. These include a constraint lifetime above 2^31−1 that crashed
  OpenSSH's agent (now capped), zero-filled direct buffers for key bytes, and the
  `SO_PEERCRED` check after connect. The client was checked against OpenSSH 10.3's `ssh-agent`
  by hand at M4.3. That check was **not** repeated at M4.5.
- **M4.4:** 1 HIGH, 1 MEDIUM and 6 LOW fixed. The HIGH: a stalled agent froze the TUI's lock,
  because agent calls ran on the GUI thread. Agent calls now run on `CliSshActions`' daemon
  executor (CE-046), and each request, from its first byte written to its last reply byte read,
  has a 10 s deadline (`SshAgentClient.DEFAULT_TIMEOUT`). The connect before it has none (see the
  residual risks below).
  The MEDIUM: agent-supplied key types and comments could inject terminal escapes; they are now
  sanitised in the client and in `Cli.displaySafe`.
- **M4.5:** the first sign-off said the campaign found no defect and changed no main code. The
  adversarial review then planted 9 bugs, and the 2-minute runs missed 4 (an armour trailer
  check, the encrypted-key code, the 1,024-identity cap and the 256 KiB frame cap). The harnesses
  were rebuilt (an armour grammar oracle, exact header codes, near-limit frame modes, an
  allocation ceiling tied to the frame limit, the production 1 MiB breach cap). The armour
  grammar oracle then found 2 real defects in `OpenSshFormat`, and the review found a third in
  `SshAgentClient`; all **3 real defects** are fixed with regression tests:
  - `OpenSshFormat` accepted unpadded base64 and base64 with non-zero unused bits (the JDK
    decoder is lax; OpenSSH's `b64_pton` refuses both), so a key had several encodings. Now the
    decoded binary is re-encoded and must match (`SshKeyTest.refusesLaxBase64AndAnEndLineThatDoesNotStartALine`).
  - `OpenSshFormat` accepted an END line that did not start a line (same test).
  - `SshAgentClient.list` took a FAILURE reply with trailing bytes as `AGENT_REFUSED`; every other
    request needs a one-byte FAILURE. Now `BAD_REPLY` (`SshAgentClientTest.malformedIdentityListsAreRejected`).
  One harness false positive was also fixed: the allocation bound fired under Jazzer's
  instrumentation on a 32 KiB input that passed without it. See M4-fuzz-runs.md.

Residual risks accepted at this sign-off:

- **Blocking Unix-socket connect.** The 10 s deadline covers each request from its first byte
  written to its last byte read. It does not cover `connect`. A local connect completes or fails
  at once unless the listener's backlog is full, and the JDK has no connect timeout for Unix
  domain sockets. A same-user process that fills the agent's backlog (or holds the checked socket
  and never accepts) can still stall `pm ssh` in the CLI until the user interrupts it. In the TUI
  the call runs off the GUI thread, so lock keeps working, but the worker thread, and the
  private-key buffer handed to it, stay held until the connect returns.
- **Private-key copy outlives a lock until the call returns.** During an agent `add`, the parsed
  `SshKey`, a pm-owned direct buffer and the kernel socket buffer hold the private key. A lock
  (idle timer or `lock`) mid-call does not cut the call short: those copies live until `add`
  returns, at most the 10 s request deadline after connecting, and are then zero-filled (the
  kernel's copy until the agent reads it). ADR 0013 Consequences records both residuals.
- **FIFO swap at open (key import).** The import opens the file once with `O_NOFOLLOW` and checks,
  around that open, that it is a regular file with an unchanged (device, inode). But a FIFO
  swapped in just before the open blocks inside `open` itself, before any check can run. The JDK
  exposes no `O_NONBLOCK` open. This needs a same-user attacker with write access to the key's
  directory.
- **Unwipeable key copies in the parser.** `KeyCheck` validates a P-256 private scalar through
  `BigInteger` and JCA key objects. They hold copies of the private key that cannot be zeroed. They
  are dropped as soon as the probe finishes, but stay in the heap until it is collected (`KeyCheck`;
  ADR 0013, which records this ADR 0008 residual risk). The key's own bytes stay in
  `SecretBytes` and pm-owned zero-filled buffers.
- **Generator entropy claims.** The reported entropy, about 130.9 bits by default and 13 bits per
  passphrase word, is exact for a uniform source. The chi-square tests prove the sampling is
  uniform given uniform input, on a fixed-seed DRBG. They cannot test the platform's
  `SecureRandom` itself, so the claim rests on the JDK's default provider.
  `PassphraseGeneratorTest.secureRandomSmoke` only checks that 500 passphrases from the real
  source are well-formed and distinct.
- **Breach k-anonymity limits.** Sending a 5-hex (20-bit) SHA-1 prefix hides the password among
  the range's suffixes, but it is not secrecy:
  - The range service learns the user's IP address, timing and which prefixes were asked.
  - Prefixes repeated across runs can be linked.
  - A prefix narrows the password to its range for anyone with the dictionary.
  - `Add-Padding: true` hides the response size, not the request.
  The check is opt-in per run (`--breach` plus an exact `y`), names the prefix in the
  confirmation, and sends one request per distinct password.
- **Fuzz depth.** The campaign was 5 minutes per harness, which is smoke-level. Not fuzzed: socket
  path and owner checks, the breach client's HTTP layer, and request encoding (all covered by
  unit tests). One gap is known in the agent oracles: a raised frame limit is caught by a complete
  frame over 256 KiB (differential) or a header over about 520 KiB (allocation), but a header
  between those sizes followed by a truncated body gives `BAD_REPLY` on both sides and fits under
  the allocation ceiling.

Documentation drift fixed at the M4.5 review: ADR 0013 said "a hung agent blocks the calling
command (no read timeout on Unix domain sockets in the JDK)", which predates the M4.4 request
deadline. It now states the deadline and the two residuals above, and its armour grammar matches
the strict parser.

CERT exceptions: the M4 sweep is recorded at the top of `docs/security/cert-exceptions.md`. Every
M4 suppression maps to a row. CE-015, CE-016, CE-045 and CE-046 were signed off at this exit, and
CE-020 and CE-021 were already signed at M4.3. M4.5 adds no suppression.

Traceability: the TM-61/SR-017 row was corrected from Planned to Implemented. T-FUZZ-SSH and
T-FUZZ-BREACH rows were added, and T-HEALTH-01 is now a JUnit `@Tag` on `BreachClientTest`. A
spot-check of every M4 traceability row and every SR-06x/SR-07x requirement found that all 110
named test classes, methods and ArchUnit rules exist.

Open, user-only, not blocking M4:
- **Dispatching the manual CI workflow** on all three OSes. This needs the branch pushed.
- **Longer fuzz campaigns** (24 CPU-hours, as for M2's `.env` parser) on a long-running machine.
  The command is in M4-fuzz-runs.md.
- **Manual interop on a real OpenSSH install** before v1: `pm ssh add` into the system
  `ssh-agent`, `ssh -T` with that identity, and import of keys written by `ssh-keygen` (Ed25519
  and ECDSA P-256, with and without a passphrase). The last such check was at M4.3, against
  OpenSSH 10.3.
- The M2 and M3 carry-overs are unchanged.

Signed off: Lane A (Jimmy), security owner, for M4.1–M4.5.

## M5 — Browser extension (M5.1–M5.5)

**Scope.** This sign-off covers the native messaging host (M5.1: framing, JSON, schema, caller
check), the bridge (M5.2: exact origins, broker-gated fill, save and generate), the MV3 extension
(M5.3: manifest, popup, background, top-frame fill) and the security exit (M5.5: two fuzz harnesses,
the permission review, this section). **M5.4** (`pm browser install`, the
browser-started host relaying approvals to the running TUI over an owner-only socket, and the TUI
prompt) was merged afterwards (5441e21) and is signed off in "M5.4 addendum" at the end of this
section.

Evidence: local runs on 2026-10-05 and 2026-10-06 at the M5.5 commit (this section's commit). The
manual CI workflow has **not** been dispatched; nothing is pushed without the owner's approval.

- Full gate on macOS 27.0 arm64, JDK 21.0.12.1:
  `./gradlew --no-daemon --rerun-tasks check certReport gitleaksScan`. Result: gate exit=0, `BUILD SUCCESSFUL in 1m 53s` (`111 actionable tasks: 111 executed`), cert report `**Result: 0 findings.**`, gitleaks `no leaks found` (history and staged), 1,663 JUnit tests with 0 failures and 0 errors, and the extension `node --test` run with 42 pass and 0 fail.
- Fuzz campaign over the two harnesses, as committed: 10 minutes (5 per harness, whole class),
  1,446,654 executions (NativeHost 322,355, Origin 1,124,299) and 0 crashes, on 2026-10-06.
  - Earlier runs on 2026-10-05 also ran clean, 2,258,140 executions in all. They are not counted
    above, because the harnesses changed after them:
    - NativeHost run 1 used the first harness, which measured allocation once with no warm-up.
    - NativeHost run 2 used the second harness, which re-ran an input on a breach.
    - The Origin run came before the default-port pairs, the seeds and the canonical-text check.
  - The host machine was shared with other builds, so the final NativeHost run made fewer
    executions than run 1.
  - Details are in `docs/security/fuzz/M5-fuzz-runs.md`.
- Planted bugs: eight, one per kind. The kinds were a frame limit, the caller allowlist, a
  duplicate JSON name, an extra request member, a lone surrogate, a Unicode host label, the port
  grammar and the `fill` origin binding.
  - **Fuzzing with every seed withheld caught six**, in 0.25 s to 224 s.
  - **Fuzzing missed two**: the duplicate name and the extra member. The duplicate name was
    caught in 140 s when only its own seed was withheld. With the same seed withheld, the extra
    member was caught in one run (297 s) and missed in another.
  - **The gate fails on all eight as committed**, through the seeds and deterministic tests.

  Each plant was reverted, and `git status --porcelain modules/pm-browser/src/main` was empty
  afterwards and before the gate.
- Review plants (fix round). The review's driver was re-run on the committed harnesses: 2 minutes of
  fuzzing with every seed withheld, then the gate, then the pm-browser tests (M5-fuzz-runs.md,
  "Review plants on the committed harness"):
  - **D and Dx are caught by fuzzing and fail the gate.** D is a buffer sized from the frame header
    that is grown once and then kept. Dx makes the same allocation on every call.
    - Fuzzing found D in 0.382 s and Dx in 0.261 s.
    - Both fail `aHostileHeaderAllocatesLessThanTheCeiling`, and Dx also fails
      `anOversizedHeaderIsRefusedBeforeAnyBodyByteIsRead`.
    - Before the fixes, D passed both fuzzing and the gate, and Dx passed the gate.
  - **NONE (nothing planted) gave no finding in 707,384 executions**, so the warm-up removed the
    round-1 false positive.
  - **B4 fails the gate** on 4 tests: the default-port seeds and pairs, which now compare the
    canonical text. B4 drops port 80 or 443 under either scheme from that text. Fuzzing from an
    empty corpus missed it.
  - **Fuzzing alone catches none of B1, B2 and B3**, the limit off-by-ones. B2 and B3 fail
    `limitsHoldAtAndJustPastTheirValues`. B1 passes the whole pm-fuzz gate and fails only
    `OriginTest` (residual below).
  - Plants 1 and 2, re-run on the committed harness, are still caught by fuzzing and by the gate.

| Exit criterion (plan.md §13 M5) | Proving test or record | Local result |
| --- | --- | --- |
| Origin binding: autofill only to exact registered origins; tested against subdomain, scheme and port confusion | `OriginTest` (`subdomainsAndParentsAreDifferentOrigins`, `schemeAndPortMustMatch`, `ipLiteralsMustBeCanonicalDottedQuads`, `punycodeLookalikesAreDistinctFromTheirTargets`, `unicodeHostsAreRefusedNotMapped`, `confusingOrUnsupportedOriginsAreRefused`); `BridgeTest` (`lookupReturnsMetadataForExactlyThatOrigin`, `confusableOriginsMatchNothingAndPromptNothing`); `OriginFuzzTest` (T-FUZZ-ORIGIN): `Origin.parse`/`ofUrl` against the independent ADR 0014 §5 oracle `OriginOracle` on every page origin and stored URL, lookup and fill through the production `Bridge` handler, and 42 fixed subdomain, parent, scheme, port (including an explicit 80 or 443 under the other scheme), userinfo, trailing-dot, IPv4-form, punycode and Cyrillic pairs (`subdomainSchemePortAndLookalikeConfusionIsRefused`), with the canonical text compared as well as the triple, because approvals are keyed on it; in the extension, `bridge.test.js` "an origin the host did not approve is never injected" and `fill.test.js` "refuses any other origin", "refuses inside a frame even of the same origin" | Pass (gate): `OriginTest` 59, `BridgeTest` 17, `OriginFuzzTest` 14 (seed replay), extension node tests 42; 0 failures, 0 errors |
| Native messaging host validates the calling extension ID and the message schema | `ExtensionAllowlistTest`, `NativeHostTest.aRefusedCallerIsNotReadFromOrAnswered`, `MessagesTest`, `NativeFramesTest`, `JsonTextTest`; `NativeHostFuzzTest` (T-FUZZ-NM) through `NativeHost.run` only: an independent caller oracle (a refused caller reads 0 stdin bytes, writes nothing, creates no handler and exits 2) and an independent RFC 3629 / RFC 8259 / ADR 0014 §3 model (`JsonOracle`) of every reply, exact error code, delivered request and byte read, with headers at, just under and just past 1 MiB | Pass (gate): `ExtensionAllowlistTest` 5, `NativeHostTest` 10, `MessagesTest` 8, `NativeFramesTest` 6, `JsonTextTest` 11, `NativeHostFuzzTest` 23 (seed replay); 0 failures, 0 errors |
| Extension has a minimal permission manifest, reviewed and recorded | `extension/test/manifest.test.js` (T-EXT-06) locks the permissions, keys and CSP; the review is `docs/security/extension-permission-review.md` (each permission, what is absent and why, CSP, `externally_connectable` (`{"ids": []}`), `web_accessible_resources`, `minimum_chrome_version`, checked against the manifest by SHA-256) | `node --test test/manifest.test.js`: 8 pass, 0 fail; review accepted with no open item (its one suggestion, `"externally_connectable": {"ids": []}`, was applied at M5.5 and re-reviewed) |
| Every credential release requires TUI approval or an explicit session policy | `BridgeTest` (`fillReleasesThePasswordOnlyAfterTheUserApproves`, `aDenyingBrokerReleasesNothing`, `aLockedVaultReleasesNothingAndShowsNoPrompt`, `aSessionPolicyCoversOneExtensionOneOriginOneActionAndOneLogin`, `generateStoresTheNewLoginBeforeReleasingIt`, `aGrantForAnotherRequestOrAnUsedGrantIsRefused`); `OriginFuzzTest` over a real `ApprovalBroker` (deny, once, session): no password or save without a prompt answered yes or a session policy for the same extension, origin and profile, nothing when locked or denied. The cross-process half (the browser-started host asking the running TUI) is M5.4: SR-113, T-EXT-08, see "M5.4 addendum" | Pass (gate): `BridgeTest` 17, `OriginFuzzTest` 14; 0 failures, 0 errors. Bridge-level release gate: proven. TUI relay: proven at the M5.4 addendum |

CERT exceptions: the M5 sweep (cert-exceptions.md, "M5 review") found only CE-025's two
annotations in M5 code. **CE-025 is signed off** (2026-10-05). M5.5 adds no suppression, so
CE-075..CE-079 are unused. CE-065/CE-066 (M5.4) are signed off in the M5.4 addendum.

Where ADR 0014 is silent, the harnesses restate the host's own rule and say so (M5-fuzz-runs.md,
"Rules the harnesses restate"). Two of them are findings for the record, not defects:

- `Messages` treats only U+0000–U+001F and U+007F as control characters, so C1 controls
  (U+0080–U+009F) are accepted in a saved username and stored as given. The prompt text replaces
  C0, DEL and C1 alike (`Bridge.shown` uses `Character.isISOControl`;
  `promptTextIsBoundedAndFreeOfControlCharacters`, and `OriginFuzzTest` checks every prompt against
  its own rendering rule), so a C1 character never reaches the approval prompt raw. Display
  hygiene, not a bypass.
- ADR 0014 §5 says "printable ASCII" for origin text; the host excludes space as well (U+0021–U+007E).
  The stricter reading is kept.

Residual risks accepted at this sign-off:

- **A same-user process can talk to the host.** Chrome passes the caller origin as an argument, and
  the host checks it against its allowlist, but any process running as the user can start the host
  with a forged argument (or simply read the same allowlist file). The caller check (ADR 0014 §4)
  stops a foreign extension through Chrome (TM-51), not a local process. The control is the
  approval gate: nothing is released without a prompt answered in pm or a session policy the user
  created (ADR 0014 §6).
- **MV3 service-worker lifetime is inferred, not measured.** If Chrome stops the background while pm
  waits for approval, the popup reports the request as interrupted and nothing is filled later
  (`bridge.test.js`, fakes only). How long Chrome keeps the worker alive during a native message is
  taken from Chrome's documentation.
- **Windows install is manual.** `pm browser install` (M5.4) writes manifests on macOS and Linux
  only; Windows needs the registry key set by hand (extension-permissions.md, "Native host
  registration").
- **No real-Chrome measurement.** Every extension test runs under Node with fakes for `chrome.*`
  and the DOM. The Chrome behaviours the review relies on are listed as INFERRED in
  extension-permission-review.md.
- **Fuzzing depends on seeds and fixed edges for five defect classes.** With every seed withheld,
  the harnesses reached none of these within the budget:
  - a repeated JSON name or an extra request member (planted bugs 3 and 4, five minutes). The
    oracle checks both; what fails is reaching them, because an accepted extra member adds no new
    coverage. The committed seeds (`decode-errors.bin`) and `limitsHoldAtAndJustPastTheirValues`
    catch both on every gate run.
  - **any of the three limit off-by-ones the review planted** (B1–B3, two minutes; M5-fuzz-runs.md,
    "Limits that fuzzing did not reach"). Fuzzing alone catches none of them. JSON depth (B2) and
    the generated length (B3) are guarded by `NativeHostFuzzTest.limitsHoldAtAndJustPastTheirValues`
    and by `JsonTextTest` and `MessagesTest`. **The 256-character origin limit (B1) is guarded only
    by `OriginTest.overlongTextAndLabelsAreRefused` in pm-browser**; no fuzz harness test fails on
    it.

  Removing those seeds or tests would lose that protection.
- **Filled values are in the page's DOM** (TM-54, accepted at M5.3): the page's own scripts can read
  a filled password.

User-only items (not done; need the owner):

- **Dispatch the manual CI workflow** for M5 (needs the branch pushed).
- **Real-browser manual test:** install the unpacked extension and the host in a real Chrome
  (121+), then fill, save and generate on a test site, and check that subdomain, scheme and port
  variants and an iframe get nothing. This also confirms the INFERRED Chrome behaviours in the
  permission review.
- **Chrome Web Store review** of the listing and the permission justification.

Signed off: Lane A (Jimmy), security owner, for M5.1–M5.3 and the M5.5 exit work. M5.4 is
signed off in the addendum below.

### M5.4 addendum (2026-10-07)

M5.4 merged as 5441e21 after a re-verify round on main. The re-verify fixed three CLI defects
before the merge (an allowlist write failure after the manifest changed now says the manifest
changed, `BRIDGE_ALLOWLIST_NOT_WRITTEN`; clearing the allowlist past a manifest pm cannot read says
so, `BRIDGE_ALLOWLIST_CLEARED_UNREAD`; uninstall removes every copy of a repeated origin), each
with a test in `BrowserCommandsTest`.

Evidence: local gate on main with M5.4 staged, 2026-10-07:
`./gradlew check certReport gitleaksScan`, `BUILD SUCCESSFUL in 1m 36s`, cert report
`**Result: 0 findings.**`, gitleaks `no leaks found`.

| ID | What it covers | Proving tests | Local result |
| --- | --- | --- | --- |
| SR-113, T-EXT-08 | Browser requests approved only in the running, unlocked TUI over an owner-only socket; no TUI means `DENIED_LOCKED`; allowlist rechecked when the answer arrives and before the reply is written; one release per approval; host disconnect cancels the prompt | `BrowserRelayTest`, `BrowserApprovalTest`, `BrowserHostTest`, `PasskeyFreeHostTest`, `BrokerIpcTest`, `SocketApprovalHostTest` (traceability.md, TM-52/TM-54 row) | Pass (gate): `BrowserRelayTest` 28, `BrowserApprovalTest` 19, `BrowserHostTest` 5; 0 failures, 0 errors |
| SR-114, T-EXT-07 | `pm browser install/uninstall/status`: exact native host manifest, `0600`, per-user folders only, symlink, foreign-owner, group-writable and foreign-manifest refusals, each browser's manifest its own record | `BrowserCommandsTest` (traceability.md, TM-51 row) | Pass (gate): `BrowserCommandsTest` 33; 0 failures, 0 errors |
| CE-065, CE-066 | `DoNotUseThreads` and `CloseResource` suppressions on `pm.tui.BrowserRelay` and its helpers | Re-read against the code at the merge: one accept thread, at most 4 connection threads plus a close watcher, vault access only through `invokeAndWait`; every channel closed in `finally` or by `close` | Accepted |

Residuals found by the re-verify probes, all failing closed, accepted:

- An approval that the relay overrules (the host goes away, or the extension is taken off the
  allowlist while the prompt waits) can leave the broker's `ALLOWED_ONCE` entry followed by the
  relay's refusal; when the relay's own deadline fires first (`DENIED_TIMEOUT`) no second entry
  is written. Nothing is released in any of these cases.
- A login saved by an approved `save` stays saved if the extension is taken off the allowlist
  before the reply is written; the reply is `DENIED_AUTH` and audited as such.
- `AuditLog.append` fails on an interrupted thread, so a request interrupted at that point is
  answered as unaudited (nothing released).
- Any same-user process can connect to the relay socket (R-011); the y/n prompt names the claimed,
  unverified host instance (SR-100).

Signed off: Lane A (Jimmy), security owner, for M5.4.

## M6 — Passkeys (M6.1–M6.5)

**Decision.** v1 ships without passkeys (ADR 0016, "Addendum (2026-10-06, M6.5, Lane A): v1 ships
without passkeys"). On 2026-10-05 the owner dropped every unbuilt feature; M6.4 (the extension half
of WebAuthn) was not built, so pm neither creates nor uses passkeys in the browser, and no command,
screen or file format lets a user make one. The M6.1–M6.3 code (keys and signing in
`pm.crypto.passkey`, the vault-owned `PasskeyRecord` and counter, `pm.browser.webauthn`) stays in
the tree with its tests and is unreachable from production code, which two ArchUnit rules enforce.

Evidence: local gate on main with M6.5 staged, 2026-10-07:
`./gradlew check certReport gitleaksScan`, `BUILD SUCCESSFUL`, cert report `**Result: 0 findings.**`,
gitleaks `no leaks found`. The manual CI workflow is dispatched once at the final checkpoint.

| Exit criterion (plan.md §13 M6) | Proving test or record | Local result |
| --- | --- | --- |
| Signature counters are monotonic and persisted atomically | `PasskeyCounterTest` (counter saved before signing, burnt values, `COUNTER_EXHAUSTED` at 2^32-1, another thread's remove waits for the signature), `PasskeyVaultOwnershipTest` (restore raises counters to max(backup + 2^20, overwritten + 1), restoring twice never reuses a counter, a passkey backup over a vault without passkeys), `WebauthnBridgeTest.countersStrictlyIncreaseAndARestoreCannotLowerThem` | Pass (gate): `PasskeyCounterTest` 10, `PasskeyVaultOwnershipTest` 22, `WebauthnBridgeTest` 19; 0 failures |
| RP ID validation tested against the WebAuthn spec test vectors | `WebAuthnVectorsTest` (L3 §16.2 byte-exact, §16.2/16.4/16.5/16.6 signatures), `RpIdTest`, `PublicSuffixListTest`, `PslUnavailableHostTest`, `AuthenticatorDataTest` | Pass (gate): 8, 9, 5, 1 and 4 tests; 0 failures |
| Private keys never leave `pm-crypto`; signing is performed inside it | `PasskeyKeyTest`, `Es256Test`, `CoseKeyTest`, `PasskeyStorageTest`, `PasskeyAccessTest`; `PasskeyOutsideModuleTest` (javac and ArchUnit proofs that no code outside pm-vault builds or reads a passkey record) | Pass (gate): 10, 6, 4, 2, 1 and 6 tests; 0 failures |
| Documented, tested support matrix; unsupported browsers fail clearly | ADR 0016 v1 addendum (support matrix), `docs/platform-matrix.md` ("Not in v1"); `PasskeyFreeHostTest.passkeyRequestsGetTheUnknownTypeReplyByteForByte`, `.decodingWithoutPasskeysRefusesThemLikeAnUnknownTypeAndKeepsEverythingElse`, `BrowserRelayTest.passkeyRequestsAreNeitherRelayedNorServed`: every browser gets the plain unknown-type reply | Pass (gate): `PasskeyFreeHostTest` 2, `BrowserRelayTest` 28; 0 failures |
| v1 has no path that makes or uses a passkey (SR-142) | `ModuleBoundaryTest.noProductionCodeWiresBrowserPasskeys`, `.onlyTheBrowserPortCreatesOrSignsPasskeys` | Pass (gate), `ModuleBoundaryTest` 18. Planted on 2026-10-07: a class in `pm.browser.host` that names `VaultPasskeys` and calls `Vault.createPasskey` fails both rules (`:modules:pm-arch-tests:test`, 2 of 18 failed); plant removed, `git status --porcelain modules/pm-browser/src/main` empty |
| No user-facing text claims passkeys (SR-143) | Review of the platform matrix and ADR 0016 here; README, user guide and release notes at M7.4 and M7.11 | Platform matrix done; the rest is checked at M7.11 |

Residual risks accepted at this sign-off:

- **Unused passkey code ships.** M6.1–M6.3 are in the release but unreachable; a later change
  that wires `VaultPasskeys` must remove the two ArchUnit rules in the same change and needs a new
  browser-path security review (ADR 0016, "Bringing passkeys back later").
- **A vault could hold a passkey only if written by a build that wires the port.** The CLI and the
  TUI show such a row read-only; v1 cannot create one.
- **"Browser and OS passkeys keep working" is inferred.** The extension has no WebAuthn code, so it
  cannot interfere, but no real-browser test exists (see the M5 user-only items).

Signed off: Lane A (Jimmy), security owner, for M6.

## M7 — Release hardening (M7.1–M7.12)

**Scope.** Format migration (M7.1), backup and restore (M7.2), packaging (M7.3), SECURITY.md,
disclosure policy and the security review record (M7.4), passphrase change (M7.6), CLI and TUI
completeness (M7.7, M7.8), the launchd ssh-agent (M7.9), Tier-1 coverage (M7.10), launch docs and
version 1.0.0 (M7.11) and the audit log under concurrent writers (M7.12). Each phase's result is in
`docs/plans/M2-M7.md`; the reviews and their findings are in `security-review-record.md`.

Evidence: local gate on main over this section's working tree, 2026-10-08:
`./gradlew --rerun-tasks check certReport gitleaksScan`, `BUILD SUCCESSFUL in 1m 41s`, cert report
`**Result: 0 findings.**`, gitleaks `no leaks found`. Test results from that run: pm-crypto 258, pm-vault 508, pm-storage 114 (8 Windows-only tests skipped on macOS by
assumption), pm-approval 79, pm-sharing 89, pm-browser 176, pm-domain 76, pm-tui 161, pm-cli 377,
pm-arch-tests 27, pm-fuzz 176, pm-platform-macos 6, extension 41; 0 failures. The CI matrix
is dispatched once after the push (manual CI); its result is in `docs/plans/M2-M7.md`.

| Exit criterion (plan.md §13 M7) | Proving test or record | Result |
| --- | --- | --- |
| Independent security review with no open critical or high findings | `security-review-record.md`: every phase reviewed adversarially by a team member who did not write it; every HIGH found (M3.7, M4.4, M7.3) fixed with a test | **Partly met.** Internal review only; no external firm. No review finding is open. R-013 (no master-passphrase strength rule, SR-011 never built, found at M7.11) is an open risk with High impact |
| Reproducible JAR and runtime-image hashes on two machines; installer contents verified | `tools/packaging/repro-check.sh` (T-PKG-04): two clean builds identical on one machine; `releaseSmoke`: app-image and mounted dmg payloads match the image | **Partly met.** One machine only; the second-builder run is user-only (`repro-check.sh <SHA256SUMS>`). pkg, deb, rpm and msi payloads are not compared |
| Signed installers on all platforms; SBOM with each release | `releaseMetadataCheck` (T-PKG-02/03): CycloneDX SBOM with every jar's purl and SHA-256 | **SBOM met; signing not met.** No signing credentials exist (packaging.md). Installers are unsigned (R-008); Windows and Linux installers were never built |
| Vulnerability disclosure policy and SECURITY.md | `SECURITY.md`, `docs/security/disclosure-policy.md` (M7.4) | **Met**, with a fallback: GitHub private vulnerability reporting is off on the public repository, so SECURITY.md asks for a contact-request issue |
| Migration rollback tested from every prior format version | `MigrationTest` (every prior version in the test registry migrates; failures at each step roll back; rollback copy owner-only), `GoldenFixtureTest.everyVersionTheBuildReadsHasAPinnedFixture`, `MigrationRegistryTest.productionReadsOnlyTheCurrentVersion` | **Met for the mechanism.** Format 1 is the only released version, so production has no prior version to migrate; the chain is proved with synthetic versions |

CERT exceptions: the M7.5 sweep (cert-exceptions.md, "M7 review") matched every suppression in the
tree to a row; CE-035, CE-036, CE-037, CE-087 and CE-088 were re-read against main and signed off;
CE-089 was added for three M7.10 test suppressions; two dead `checkstyle:ParameterNumber`
suppressions were removed. No row awaits sign-off.

Traceability: every row once marked Planned now names its tests or says Not in v1 (M7.11), and a
script check found that every `Class.method` the file cites exists (112 names; the 5 that are not
methods are ArchUnit rule fields).

Residual risks accepted at this sign-off (risk-register.md):

- **R-008, unsigned releases.** `SHA256SUMS` is the only integrity check, and it is not signed.
- **R-012, clipboard.** A copied password is readable by same-user programs and clipboard managers
  until it is cleared.
- **R-013, master-passphrase strength.** Open, not accepted: the owner decides whether SR-011 is
  built before the 1.0.0 tag. Release notes and the user guide tell users to choose a long passphrase.
- **Not built in v1:** keychain unlock (SR-050), signed updates (SR-602), lock on sleep, Windows
  ssh-agent, Copy on Linux and Windows, the SR-051 manual timing measurement.
- **Process gaps** (security-review-record.md): no branch protection, private vulnerability
  reporting off, manual CI, no external SAS review, no real-browser test, no dependency
  vulnerability scan.

Signed off: Lane A (Jimmy), security owner, for M7, with the criteria above marked Partly met or
not met.
