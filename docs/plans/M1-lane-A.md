# M1 Lane A (Crypto) Checkpoint

Lane A slice of `M1-team-sprint.md`. Contracts: §2 "A: pm.crypto". Gate: `./gradlew check certReport`
(needs `org.gradle.java.installations.paths` pointing at a JDK 21).

- [x] **A0** Ratify ADRs 0005, 0007, 0008 (done: Status Accepted; check-docs + gate green)
- [x] **A1** pm-crypto public API stubs (done: full §2 API; SecretBytes/SecretChars/Csprng/Argon2Params/CryptoException real, rest stubbed; gate green, 0 findings)
- [x] **A2a** SecretBytes, SecretChars, Csprng + tests (done: 34 tests green under corrected gate; 0 findings)
- [x] **A2-gate** Fix CERT gate: PMD analyzed nothing, Semgrep skipped tests, FIO13 over-matched (done: planted violations prove PMD + Semgrep catch; 0 findings)
- [x] **A2b** Argon2id, HKDF, AES-KWP, AES-GCM, Kdf.tune + KATs and properties (done: BC 1.86 checksums verified vs Central; 33 tests; CE-001 pending sign-off; full Lane A = 85 tests, 0 findings)
- [x] **A2c** RecoveryKey, SafeLog + tests (done: 18 tests green under corrected gate; Kdf.tune moved to A2b)
- [ ] **A3a** ArchUnit constant-time rules + gate input/PMD-error fixes + pm-crypto 100% branch coverage enforced in check
- [ ] **A4** Fix adversarial-review findings (SafeLog allowlist, FIO13 widening, semgrepignore anchoring, apply() escape, GCM key consumed on seal, heap-budgeted Argon2, ASCII-only recovery parse, IKM >= 32, test fixes, ADR 0008 limitations)
- [~] **A3b** Wrong passphrase runs Argon2 to completion (BLOCKED: needs Lane C VaultService)
