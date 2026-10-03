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

### C

### D

### E
