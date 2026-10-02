# M1 Lane E checkpoint: pm-tui + pm-cli

Source of truth: `docs/plans/M1-team-sprint.md` §2 "E", §3 E, §5 E, §6 E.
Gate: `JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew --console=plain --rerun-tasks -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 check certReport` → BUILD SUCCESSFUL and `Result: 0 findings.`

Decision (2026-10-02, user): Lanes C/D are unbuilt, so E builds against §2 C/D contract stubs
(branch `m1/e/cd-stubs`, replaced by C/D later) and tests against in-memory fakes behind an E-owned port.
E commits are to be re-authored to the Lane E teammate before push (name pending from user).

- [x] **E0** Lanterna 3.1.3 dependency + verification metadata (done: jar/pom sha1 match Central (no .sha256 published); signing key unavailable on keyservers → ignored-key, checksum-pinned only)
- [x] **E1** C/D contract stubs (pm-vault, scaffolding only) + E stubs: TuiApp, IdleLock, Main, module-infos (done: VaultPort/Session seam; §2 amended to `requires transitive` lanterna; CE-002 DoNotUseThreads on IdleLock, CE-003 EI_EXPOSE_REP on holder records; gate green 0 findings)
- [x] **E2a** CLI: Main/run(args, ConsoleIo), init/add-login/list/search, exit codes, Messages + MainArgsTest (done: 69 CLI tests incl. canary; FIO13 now honours @SecretBoundary like MSC03; gate green 0 findings)
- [ ] **E2b** TUI: unlock, dashboard + search, detail (masked), add-login dialog + DashboardTest (virtual terminal)
- [x] **E2c** IdleLock (ReentrantLock, not synchronized) + IdleLockTest with deterministic scheduler (done: generation counter blocks stale expiry; 11 tests incl. real-executor smoke; gate green 0 findings)
- [ ] **E-review** Adversarial review of all E changes; findings fixed or recorded
- [~] **E3** EndToEndTest with canary passphrase (BLOCKED: needs real Lane C VaultService)
