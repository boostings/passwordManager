# M1 Lane A (Crypto) Checkpoint

Lane A slice of `M1-team-sprint.md`. Contracts: §2 "A: pm.crypto". Gate: `./gradlew check certReport`
(needs `org.gradle.java.installations.paths` pointing at a JDK 21).

- [x] **A0** Ratify ADRs 0005, 0007, 0008 (done: Status Accepted; check-docs + gate green)
- [x] **A1** pm-crypto public API stubs (done: full §2 API; SecretBytes/SecretChars/Csprng/Argon2Params/CryptoException real, rest stubbed; gate green, 0 findings)
- [x] **A2a** SecretBytes, SecretChars, Csprng + tests (done: 34 tests green under corrected gate; 0 findings)
- [x] **A2-gate** Fix CERT gate: PMD analyzed nothing, Semgrep skipped tests, FIO13 over-matched (done: planted violations prove PMD + Semgrep catch; 0 findings)
- [x] **A2b** Argon2id, HKDF, AES-KWP, AES-GCM, Kdf.tune + KATs and properties (done: BC 1.86 checksums verified vs Central; 33 tests; CE-001 pending sign-off; full Lane A = 85 tests, 0 findings)
- [x] **A2c** RecoveryKey, SafeLog + tests (done: 18 tests green under corrected gate; Kdf.tune moved to A2b)
- [x] **A3a** ArchUnit constant-time rules + gate input/PMD-error fixes + pm-crypto 100% branch coverage enforced in check (done: 3 ArchUnit rules proven by planted violations; stale-report + PMD-error holes proven closed; 114/114 branches; 104 tests, 0 findings)
- [x] **A4** Fix adversarial-review findings (SafeLog allowlist, FIO13 widening, semgrepignore anchoring, apply() escape, GCM key consumed on seal, heap-budgeted Argon2, ASCII-only recovery parse, IKM >= 32, test fixes, ADR 0008 limitations) (done: all 10 findings fixed with harness evidence — heap copies 2→0 for recovery key, GCM key reuse now SECRET_CLOSED, OOM→BAD_PARAMS; 130/130 branches; 152 tests, 0 findings)
- [x] **A5** Fix second-round review findings (heap budget lockout, gate staleness on build packages, FIO13 contract names, GCM fresh-salt contract, SafeLog numbers, constant-time ArchUnit gaps, ConstantTime API, ledger IdentityHashMap/MemoryMXBean evasions, §2 amendments)
  - Result: D1–D9, I1 and both evasions fixed (review2-code/docs, merged b1c1da7/64039b4); open note: m=1 GiB needs -Xmx≥1150m under the 1.1×m budget; CE-004/CE-005 added, pending sign-off.
- [x] **A3b** Wrong passphrase runs Argon2 to completion (done: slot-level proof via package-private SlotCrypto.Stretcher seam — wrong pass runs Argon2id exactly once with header m/t/p/salt, same as right, fails only at KWP with AUTH_FAILED like a tampered wrap; best-of-3 timing sanity; planted reduced-iterations defect caught; 12 slot tests; no early return found)
