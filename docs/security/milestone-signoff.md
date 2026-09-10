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
