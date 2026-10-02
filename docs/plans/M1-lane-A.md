# M1 Lane A (Crypto) Checkpoint

Lane A slice of `M1-team-sprint.md`. Contracts: §2 "A: pm.crypto". Gate: `./gradlew check certReport`
(needs `org.gradle.java.installations.paths` pointing at a JDK 21).

- [x] **A0** Ratify ADRs 0005, 0007, 0008 (done: Status Accepted; check-docs + gate green)
- [x] **A1** pm-crypto public API stubs (done: full §2 API; SecretBytes/SecretChars/Csprng/Argon2Params/CryptoException real, rest stubbed; gate green, 0 findings)
- [x] **A2a** SecretBytes, SecretChars, Csprng + tests (done: 34 tests green under corrected gate; 0 findings)
- [x] **A2-gate** Fix CERT gate: PMD analyzed nothing, Semgrep skipped tests, FIO13 over-matched (done: planted violations prove PMD + Semgrep catch; 0 findings)
- [ ] **A2b** Argon2id, HKDF, AES-KWP, AES-GCM + known-answer and property tests (needs Bouncy Castle dep from Lane E Phase 0)
- [x] **A2c** RecoveryKey, SafeLog + tests (done: 18 tests green under corrected gate; Kdf.tune moved to A2b)
- [~] **A3** Constant-time / full-KDF assertions (BLOCKED: needs Lane C unlock code)
