# Internal security review record (v1)

This file records the security review behind v1: who reviewed what, how, what was found, and
what remains open. Each milestone's detailed evidence is in
[milestone-signoff.md](milestone-signoff.md); this file summarises it and states the gaps. All
reviews were **internal**, done by the team, and no external audit has taken place.

## Method

Every phase on the security path went through the same five steps:

1. **Design first.** An ADR (docs/adr/0003 to 0016) and requirement rows (SR-nnn in
   [requirements.md](requirements.md)) were written before the code. The threat model,
   [attack trees](attack-trees.md) and [abuse cases](abuse-cases.md) were updated with them.
2. **The gate, on every commit:** `./gradlew check certReport gitleaksScan`. It runs:
   - compilation with `-Xlint:all -Werror`;
   - Error Prone;
   - SpotBugs with FindSecBugs;
   - PMD;
   - the project's Semgrep CERT rules (`tools/cert-rules`), report required to show "0 findings";
   - gitleaks over history and staged files;
   - ArchUnit module and secret-flow rules (`pm-arch-tests`);
   - the fuzz harnesses' seed replay (`pm-fuzz`);
   - the extension's `node --test` suite;
   - 100% branch coverage for the six Tier-1 modules (M7.10).

   Every suppression is a CERT exception row in [cert-exceptions.md](cert-exceptions.md),
   signed off by the security owner.
3. **Adversarial review.** After a phase was built, a reviewer who had not written it tried to
   break it. The reviewer worked from the ADR and the code, not from the author's tests. Every
   finding was fixed with a test that failed before the fix, or documented as a residual risk.
   Re-verify rounds ran until no new finding appeared.
4. **Planted bugs.** At each security exit (M0, M2.7, M3.7, M4.5, M5.5, M6.5), defects were
   planted in the real code to prove that the gate, the fuzzers or a named test catch them. Each
   plant was reverted, and the tree was shown clean.
5. **Sign-off.** The security owner signed each milestone against plan.md §13's exit criteria.
   Each criterion is mapped to the tests that prove it, and residual risks are listed.

## Reviews and findings

Findings are counted as the plan records them in `docs/plans/M2-M7.md` (Result lines). "Fixed"
means fixed with a test.

| Phase | Subject | Findings | Outcome |
| --- | --- | --- | --- |
| M1 | Vault foundation (crypto, storage, envelope, records, CLI/TUI) | Lane reviews and gate correction (milestone-signoff.md, "M1 gate correction") | Signed off per lane, CI run 37138093559 |
| M2.1–M2.7 | `.env` parsing, approval broker, audit log, IPC, `env run` | Fixed during the phases; `.env` fuzz harness; no-disk-write test | M2 signed off 2026-10-03 |
| M3.5 | Browser-only receiving page | 4 defects fixed; history-database residual documented | Fixed |
| M3.7 | LAN protocol security exit | 1 HIGH (no bounds oracle in the fuzz harness), 3 MEDIUM, 3 LOW | All fixed; M3 signed off |
| M4.1 | Generator | 10^6-draw chi-square passed; offensive words screened out | No defect |
| M4.2 | Health and breach client | 5 defects | Fixed |
| M4.3 | ssh-agent client and key parsing | 7 defects, including a lifetime value that crashed the agent | Fixed; checked against OpenSSH 10.3 |
| M4.4 | CLI/TUI ssh and health | 1 HIGH (a stalled agent froze the TUI lock), 1 MEDIUM (escape-sequence injection from the agent), 6 LOW | Fixed; 10 s agent deadline |
| M5.1 | Native messaging host | 300k-message fuzz clean; 1 defect | Fixed |
| M5.2 | Origin binding and fill | IDNA2003 lookalike match (faß.de → fass.de) | Fixed by refusing Unicode hosts |
| M5.4 | Browser relay to the TUI | 3 CLI defects in install/uninstall; 4 fail-closed residuals | Fixed; residuals in the M5.4 addendum |
| M5.5 | Extension security exit | 8 planted bugs; 2 review rounds on the fuzz harnesses | Gate fails on all 8; residuals recorded |
| M6.1 | Passkey keys in pm-crypto | 1 MEDIUM, 3 LOW | MEDIUM fixed, LOW documented in ADR 0016 |
| M6.3 | WebAuthn authenticator | 1 MEDIUM-HIGH (silent UP=1 under a standing grant) and 3 more, over 2 re-verify rounds | Fixed; code unreachable in v1 (M6.5) |
| M6.5 | v1 passkey decision | Planted host class wiring passkeys | Fails both ArchUnit rules; M6 signed off |
| M7.1 | Format migration | 3 defects | Fixed |
| M7.2 | Backup and restore | 4 defects; 2 races documented | Fixed; races in ADR 0015 |
| M7.3 | Packaging | 2 HIGH (the packaged TUI crashed; JVM options taken from the environment), 1 MEDIUM, 3 LOW | Fixed; environment JVM options refused at start (detection only) |
| M7.6 | Passphrase change | Review and fix round (stale saves, failed changes) | Fixed: CONFLICT on stale save; failures say which passphrase opens the file |
| M7.7 | CLI completeness | 8 LOW | All fixed |
| M7.8 | TUI reveal, copy, edit, delete, Wi-Fi, passphrase | Edit save failure left the edited record in memory; delete save failure closed the dialog with the item gone from the list; a password with terminal controls could be revealed; the first macOS clipboard adapter left a pipe open and ignored a stuck tool | Fixed with tests; copy and both clears checked against the real macOS pasteboard; clipboard limits are R-012 |
| M7.9 | launchd ssh-agent | 1 LOW (root trusted as a peer everywhere) | Fixed by narrowing to launchd's own listener |
| M7.10 | Tier-1 coverage | Two timing-dependent branches; conditions that could never fail | Made deterministic or removed with the reason stated |
| M7.12 | Audit log under concurrent writers | Chain forked under two writing processes (found by the M7.4 scratch run); review: partial appends, unbounded waits, head without log | Fixed; 4-JVM test, 20/20 runs |

The M7.12 finding came out of this review's own end-to-end run of the CLI. Two `pm pair`
processes on vaults in one folder appended to one `audit.log` concurrently and forked its chain,
after which every audited operation failed. That run is why the user guide's commands were
executed against a throwaway vault, not copied from help text.

## Process gaps (recorded, not hidden)

- **No branch protection and no PR review on `main`.** `CODEOWNERS` describes a two-review rule
  for Tier-1 paths. However, `gh api repos/boostings/passwordManager/branches/main/protection`
  returns "Branch not protected" (2026-10-07), and work landed as direct commits. The reviews
  above are the review of record; they are not GitHub approvals. Turning branch protection on is
  a repository-admin action (user-only).
- **Private vulnerability reporting is off.** `gh api
  repos/boostings/passwordManager/private-vulnerability-reporting` returns `{"enabled":false}`
  (2026-10-07). SECURITY.md gives a fallback ("Security contact request" issue) until the owner
  enables it.
- **CI is manual.** `ci.yml` runs on `workflow_dispatch` only. The last dispatched run before this
  record is 37138856846 (2026-10-03, success). Milestones M2 to M6 were signed off on local gate
  runs, and one CI run is dispatched at the v1 checkpoint (M7.5).
- **No external review.** The LAN SAS construction (ADR 0010 Amendment 1) was meant to get an
  external cryptographic review (M3.7, user-only), and it has not had one.
- **No real-browser test.** Every extension test runs under Node with fakes. The Chrome behaviours
  the permission review relies on are INFERRED ([extension-permission-review.md](extension-permission-review.md)).
- **Unsigned releases.** There is no code signing, no notarization and no signed `SHA256SUMS`; the
  credentials do not exist on the build machine ([packaging.md](../release/packaging.md)).
- **Windows and Linux are not exercised on this machine.** The CI matrix covers them when
  dispatched. Native installers for those systems were never built.

## Open residual risks at v1

Accepted risks are in [risk-register.md](risk-register.md); this list points to the ones a v1
user should know about:

- R-001: a compromised OS or administrator. Out of scope.
- R-003: Java cannot guarantee that secret memory is wiped. Mitigated as far as Java allows.
- R-005: a recipient keeps a copy of a shared secret; revocation cannot recall it. Accepted.
- R-008: installers are not signed. Partly mitigated by reproducible archives and the hash
  manifest.
- R-011: a same-user process can reach the browser relay socket. Every release still needs a
  prompt. Accepted.
- R-012: a password copied in the app is readable by every same-user program, and a clipboard
  manager can keep it, until pm clears it. Accepted; Copy is macOS-only in v1.
- ADR 0008: known limitations of best-effort zeroing.
- ADR 0013: connecting to the agent has no deadline of its own, and key copies outlive a lock.
- ADR 0014 and M5: filled values are in the page's DOM (TM-54), and the MV3 worker lifetime is
  inferred.
- ADR 0015: two backup races are documented.
- ADR 0016: unused passkey code ships unreachable. Bringing it back needs a new review.

## CERT exceptions

All rows are in [cert-exceptions.md](cert-exceptions.md):

- Signed off: CE-001 to CE-013, CE-015, CE-016, CE-020, CE-021, CE-025, CE-045, CE-046 and
  CE-050 (M6.5).
- Accepted at the M5.4 merge: CE-065 and CE-066.
- Proposed and still awaiting sign-off in this record: CE-035, CE-036, CE-037 (M3.6) and CE-087
  (M7.7) and CE-088 (M7.8). They are re-read against the code and signed off, or sent back, at the M7 sign-off
  (M7.5).

Recorded by: Lane A (Jimmy), security owner, 2026-10-07.
