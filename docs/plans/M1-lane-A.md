# M1 Lane A (Crypto) Checkpoint

Lane A slice of `M1-team-sprint.md`. Contracts: §2 "A: pm.crypto". Gate: `./gradlew check certReport`
(needs `org.gradle.java.installations.paths` pointing at a JDK 21).

- [x] **A0** Ratify ADRs 0005, 0007, 0008 (done: Status Accepted; check-docs + gate green)
- [ ] **A1** pm-crypto public API stubs
- [ ] **A2a** SecretBytes, SecretChars, Csprng + tests
- [ ] **A2b** Argon2id, HKDF, AES-KWP, AES-GCM + known-answer and property tests (needs Bouncy Castle dep from Lane E Phase 0)
- [ ] **A2c** RecoveryKey, Kdf.tune, SafeLog + tests
- [ ] **A3** Constant-time / full-KDF assertions (blocked on Lane C unlock code)
