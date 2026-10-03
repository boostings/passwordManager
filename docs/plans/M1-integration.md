# M1 integration + push checkpoint

User request (2026-10-02): finish A and E, push everything to main, resolve all merge conflicts.
Authorship: Lane E commits (`M1.x E:`) re-authored to Jacob <jacobstachyra1@gmail.com> before push; Lane A stays Jimmy; Ben's Lane C commit untouched.
Gate: `./gradlew --rerun-tasks check certReport` (JDK 21 toolchain path) → BUILD SUCCESSFUL + `Result: 0 findings.`

- [x] **I1** Merge origin/main (Ben's Lane C aaac981) into integration; resolve conflicts; gate green
  - Result: merged (d9125d6, 2fc36f1, 9aafab3); Ben's files taken verbatim, D stubs added. Gate green except `:modules:pm-vault:test` 66/81 failing on Lane B/D stubs. User chose to push with those red until B/D land.
- [x] **I2** Merge A5 fixes (code + gate/docs) from the second Lane A review
  - Result: merged 64039b4, b1c1da7; plus 7763e77 (FIO13 RecoveryKey.format false positive), 1e8bd63 (Lane C magic via ConstantTime), 9a294fa. Gate minus vault tests: BUILD SUCCESSFUL, 0 findings.
- [x] **I3** Fix Lane E adversarial-review findings
  - Result: CLI 7633b91 (exit 6 recovery-key-not-shown, exit 5 internal, format/bidi sanitising, --vault/-- handling, tune only on init; pm-cli 127 tests) and TUI 00e4a3d (DisplaySafe, forms cleared on cancel/lock/quit, onLock never after close, put-failure zeroing; pm-tui 41 tests) merged; CE-002 corrected 9b14ea2. Open: Session.close throwing during TUI lock escapes run (CLI maps it to exit 5); symlinked --vault left to Lane B; `list --help` exits 0.
- [x] **I4** A3b (wrong passphrase runs full Argon2) and E3 (end-to-end CLI) against real Lane C, or record exact Lane D blocker
  - Result: A3b done (ba49de6, slot-level proof, no early return in VaultService unlock). E3 BLOCKED: real FileVaultPort → VaultService.create fails at `pm.storage.VaultFileStore.open` (Lane B stub) and then `CborWriter.encode`/`RecordCodec` (Lane D stubs); same cause as the 66 failing pm-vault tests.
- [x] **I5** Re-author E commits to Jacob, final gate, push to origin/main (no force), verify remote == local
  - Result: pushed aaac981..9230701 fast-forward; 15 E commits authored by Jacob; gate green except 66 pm-vault tests on Lane B/D stubs (user accepted).

## Round 2 (2026-10-03): Lanes B/D landed, finish M1-team-sprint Phases 0 and 3

- [x] **I6** Integrate teammates' Lane B (Ra1ny1) and Lane D (M0hayan) plus Ben's cleanup; push so main builds
  - Result: pushed 3173a81..d4f6c36; full gate green, 668 tests, 0 findings, no leaks. B/D fix commits authored by their owners.
- [ ] **I7** Phase 3 tests: EndToEndTest (E), VaultPermissionsTest (B), ConstantTimeReviewTest (A), EnvelopeFuzzTest + fuzz runs + property tests (D); full gate green; push
- [ ] **I8** Phase 0 docs: ADR 0002/0003/0004/0006 Accepted, ADR 0006 Amendment 1, docs/schemas/records.cddl; push
