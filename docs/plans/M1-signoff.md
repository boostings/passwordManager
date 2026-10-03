# M1 sign-off: close out docs/plans/M1-team-sprint.md

Requested 2026-10-03: "do all of those tasks to finish up M1. Jstacs78 = jacob's github handle".
Gate: `./gradlew --rerun-tasks check certReport gitleaksScan` (Homebrew JDK 21) plus CI green on 3 OSes.
Lane commits are authored by the lane owner (see memory lane-authors); no AI attribution.

- [x] **S1** CODEOWNERS: add @Jstacs78 to `modules/pm-cli/` and `modules/pm-tui/`; tick sprint Phase 0.
  Accept: no placeholder comments left; check-docs OK. Commit `M1.0 E:`.
  - Result: @Jstacs78 on pm-cli/pm-tui; sprint Phase 0 ticked; check-docs OK.
- [x] **S2** Lane C fix: Argon2 heap refusal maps to `VaultException.Code.INSUFFICIENT_MEMORY`, not CORRUPT,
  in `VaultService.create` and `unlockWithPassphrase`; tests for both paths. Accept: gate green. Commit `M1.4 C:`.
  - Result: VaultService.passphraseKek maps BAD_PARAMS→INSUFFICIENT_MEMORY; 2 tests fail with CORRUPT without the fix; gate green, 680 tests, 0 findings.
- [ ] **S3** Security owner (A): CE-001..CE-005 reviewed against the code and marked signed off; plan.md
  "Project status" updated with M1 done. Commit `M1.4 A:`.
- [ ] **S4** `docs/security/milestone-signoff.md` `## M1`: headers `### A`..`### E` (E first), then each lane's
  criteria, proving test, and the real result line from CI run on all 3 OSes. One `M1.4 <lane>:` commit per lane.
- [ ] **S5** Full gate, push, CI green on ubuntu/macos/windows for the final commit, tag `m1` (tagger Jacob),
  push tag; tick sprint Phase 4.
