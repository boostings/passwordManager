# Threat → Requirement → CERT → Test Traceability

Test IDs are the canonical names used in test classes (`@Tag("T-KDF-01")`)
so the certReport and coverage tooling can prove each threat has a test.
Status: Planned until the test exists and passes in CI.

| Threat | SR | CERT | Test / check | Milestone | Status |
| --- | --- | --- | --- | --- | --- |
| TM-01 | SR-504 | — | T-UI-06 | M1 | Planned |
| TM-02 | SR-030 | — | T-UI-02 | M1 | Planned |
| TM-03 | — | — | R (TUI review) + docs | M1 | Planned |
| TM-04 | SR-109 | — | T-UI-04 | M2 | Planned |
| TM-10 | SR-010, SR-011 | MSC02-J | T-KDF-01, T-UI-01 | M1 | Planned |
| TM-11 | SR-015, SR-020, SR-701 | — | T-ENC-02, T-TAMPER-01, T-MIG-01 | M1 | Planned |
| TM-12 | SR-014 | — | T-ENC-01 + R | M1 | Planned |
| TM-13 | SR-040 | FIO00-J, FIO01-J | T-FS-01 | M1 | Planned |
| TM-14 | SR-041 | FIO02-J | T-FS-02 | M1 | Planned |
| TM-15 | SR-505, SR-502 | OBJ07-J, OBJ14-J | T-MEM-01, T-PKG-01 | M1, M7 | Planned |
| TM-16 | SR-051, SR-016 | — | Semgrep cert.CT-compare + M7 manual | M1 | Planned |
| TM-17 | SR-021, SR-507 | MSC05-J, SER12-J | T-FUZZ-VAULT, ArchUnit | M1 | Planned |
| TM-18 | SR-050 | — | T-UI-03 | M1 | Planned |
| TM-20 | SR-100, SR-101 | MET03-J, SEC02-J | ArchUnit, T-IPC-01 | M2 | Planned |
| TM-21 | SR-102 | IDS07-J | T-ENV-01 | M2 | Planned |
| TM-22 | SR-103, SR-104 | — | T-POLICY-01, T-POLICY-02 | M2 | Planned |
| TM-23 | SR-112 | — | T-AUDIT-01 | M2 | Planned |
| TM-24 | SR-106 | FIO03-J | T-ENV-02 | M2 | Planned |
| TM-25 | SR-108 | FIO00-J, FIO16-J | T-IPC-02 | M2 | Planned |
| TM-26 | SR-111 | — | T-POLICY-03 | M2 | Planned |
| TM-30 | SR-200, SR-201 | — | T-LAN-01, T-LAN-02 | M3 | Planned |
| TM-31 | SR-201 | MSC00-J | T-LAN-02, external review | M3 | Planned |
| TM-32 | SR-203 | — | T-LAN-04 | M3 | Planned |
| TM-33 | SR-202 | — | T-LAN-03 | M3 | Planned |
| TM-34 | SR-204, SR-205 | — | T-LAN-05, T-LAN-06 | M3 | Planned |
| TM-35 | SR-206 | MSC05-J, IDS11-J | T-FUZZ-LAN | M3 | Planned |
| TM-36 | SR-207 | THI04-J, FIO14-J | T-LAN-07 | M3 | Planned |
| TM-37 | SR-208 | ERR03-J | T-LAN-08 | M3 | Planned |
| TM-40 | SR-209 | — | T-WEB-01 | M3 | Planned |
| TM-41 | SR-204, SR-209 | — | T-LAN-05, T-WEB-01 | M3 | Planned |
| TM-42 | SR-210 | — | T-WEB-02 | M3 | Planned |
| TM-50 | SR-300, SR-304 | — | T-EXT-01, T-EXT-04 | M5 | Planned |
| TM-51 | SR-301 | — | T-EXT-02 | M5 | Planned |
| TM-52 | SR-302 | — | T-EXT-03 | M5 | Planned |
| TM-53 | SR-303 | MSC05-J | T-FUZZ-NM | M5 | Planned |
| TM-51 | SR-301, SR-305 | — | T-EXT-02 (`ExtensionAllowlistTest`, `NativeHostTest`) | M5.1 | Tested |
| TM-53 | SR-303, SR-305 | MSC05-J, IDS00-J | T-FUZZ-NM unit half (`NativeFramesTest`, `JsonTextTest`), T-EXT-05 (`MessagesTest`); fuzz harness M5.5 | M5.1 | Tested |
| TM-50 | SR-300, SR-306 | IDS01-J | T-EXT-01 (`OriginTest`, `BridgeTest` exact-origin cases) | M5.2 | Tested |
| TM-52 | SR-302, SR-307 | MET03-J | T-EXT-03 (`BridgeTest` denying broker, session-policy scope) | M5.2 | Tested |
| TM-50, TM-54 | SR-304, SR-309 | — | T-EXT-04 (`extension/test/fill.test.js`, `background.test.js`) | M5.3 | Tested |
| TM-52 | SR-308 | — | T-EXT-06 (`extension/test/manifest.test.js`) + permission review M5.5 | M5.3 | Tested |
| TM-60 | SR-013 | — | T-KEY-02 | M1 | Planned |
| TM-61 | SR-017 | — | ArchUnit | M4 | Planned |
| TM-61 | SR-060 | MSC03-J, FIO13-J | ArchUnit `onlyTheCliReachesSshKeys`, `SshKeyTest` | M4 | Implemented (M4.3) |
| — | SR-061 | FIO00-J, FIO15-J, FIO16-J | `SshAgentClientTest` | M4 | Implemented (M4.3) |
| — | SR-062 | IDS00-J, NUM00-J, MSC05-J | `SshKeyTest`, `SshAgentClientTest` | M4 | Implemented (M4.3) |
| — | SR-063 | FIO01-J, FIO16-J | `SshKeyExportTest` | M4 | Implemented (M4.3) |
| — | SR-064 | ERR01-J | `SshKeyTest` | M4 | Implemented (M4.3) |
| TM-70 | SR-074 | MSC00-J | T-HEALTH-01 (`BreachClientTest`, network capture) | M4 | Implemented (M4.2) |
| TM-71 | SR-602 | — | T-UPD-01 | M7 | Planned |
| TM-80 | SR-700 | IDS04-J, FIO16-J | T-BKP-01 | M1 | Planned |
| TM-81 | SR-701, SR-702 | FIO02-J, ERR03-J | T-MIG-01 (MigrationTest, GoldenFixtureTest) | M7 | Planned |
| TM-82 | SR-700, SR-703, SR-704 | FIO01-J, FIO02-J, ERR03-J | T-BKP-01 (VaultBackupsTest, BackupDirectoryTest) | M7 | Planned |
| TM-81 | SR-105 | MSC05-J | T-FUZZ-ENV | M2 | Planned |
| TM-82 | SR-110 | — | T-ENV-03 | M2 | Planned |
| TM-90 | SR-600 | — | CI dependency verification + scan | M0 | Planned |
| TM-91 | SR-601 | ENV01-J | CI reproducible build | M7 | Planned |
| TM-92 | SR-800 | MSC03-J | CI gitleaks | M0 | Planned |
| TM-93 | SR-801 | ENV05-J, ENV06-J | T-PKG-01 | M7 | Planned |
| all | SR-900 | all | certReport | M0 | Planned |

## M4 generation and health

| Threat | SR | CERT | Test / check | Milestone | Status |
| --- | --- | --- | --- | --- | --- |
| — (weak or biased generated secret) | SR-070, SR-071 | MSC02-J | `UniformTest`, `PasswordGeneratorTest`, `PassphraseGeneratorTest` | M4 | Implemented (M4.1) |
| — (generated secret left in memory) | SR-072 | MSC03-J | `PasswordGeneratorTest.resultIsOwnedAndZeroedOnClose`, R | M4 | Implemented (M4.1) |
| — (corrupt wordlist) | SR-073 | IDS00-J | `PassphraseGeneratorTest.wordlistValidationRejectsCorruptLists` | M4 | Implemented (M4.1) |
| TM-70 (breach check leaks full password hash) | SR-074 | MSC00-J | T-HEALTH-01 `BreachClientTest` (fake loopback server sees only a 5-char prefix) | M4 | Implemented (M4.2) |
| — (unrequested network use) | SR-078 | MSC00-J, IDS01-J | `BreachClientTest.offlineHealthCheckNeverTouchesTheNetwork`, `.baseUriValidation`, `.strictRangeParsing` | M4 | Implemented (M4.2) |
| — (weak password undetected) | SR-075 | IDS00-J | `StrengthMeterTest` | M4 | Implemented (M4.2) |
| — (plaintext password map in memory) | SR-076 | MSC03-J | `ReuseAndAgeTest`, R | M4 | Implemented (M4.2) |
| — (stale password undetected) | SR-077 | — | `ReuseAndAgeTest`, `HealthCheckTest` | M4 | Implemented (M4.2) |
