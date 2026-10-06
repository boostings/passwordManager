# Threat → Requirement → CERT → Test Traceability

Test IDs are the canonical names used in test classes (`@Tag("T-KDF-01")`)
so the certReport and coverage tooling can prove each threat has a test.
Status: Planned until the test exists. "Implemented (M<n>.<k>)" means the tests exist and pass the
full local gate (`./gradlew check certReport gitleaksScan`). The manual CI workflow has not been dispatched since
M1, so CI confirmation is recorded per milestone in `docs/security/milestone-signoff.md` when it
happens, not in this column. (Changed at M3.7: this line used to say "passes in CI", which no
M3, M4, M6 or M7 row met; the rows already used the local-gate meaning.)
Every test ID named in an M3 or M4 row is a JUnit `@Tag` on the tests that implement it:
- T-HEALTH-01 on `BreachClientTest`, tagged at M4.5.
- T-FUZZ-SSH on `OpenSshKeyFuzzTest` and `AgentReplyFuzzTest`.
- T-FUZZ-BREACH on `BreachRangeFuzzTest`.

T-PKG-01..04 (M7.3 rows) are not yet tagged. M4 rows that name only class or method names (no
T-ID) point at those tests directly. At M4.5, every M4 row was spot-checked against the tree: each
named test class and method exists. `certReport` aggregates scanner findings only. It does not
read tags, so the tag-to-row mapping is checked by review, not by the gate.

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
| TM-30 | SR-200, SR-201 | — | T-LAN-01, T-LAN-02 (CLI and TUI): `LanEndToEndTest.pairShareReceiveRevokeAndRefuseAnUnpairedPeer` (both screens show the same code; an unpaired vault is turned away), `LanEndToEndTest.aRejectedCodePinsNothing`, `LanScreensTest.pairShareReceiveAndRevokeBetweenTwoScreens`, `LanScreensTest.aRejectedCodePinsNothingAndADeniedShareSendsNothing`, `LanScreensTest.anAnswerOnlyReachesTheQuestionOnScreenAndASecondOneWaits`. M3.6 has no discovery: the user types the address and trust comes only from the confirmed ceremony | M3 | Implemented (M3.6) |
| TM-31 | SR-201 | MSC00-J | T-LAN-02: `PairingTest` (pm-crypto), `TlsTest`, `PairingSessionTest` (relaying MITM gets different digits, forwarded MAC fails), `PairerTest` (loopback mutual TLS 1.3), `PairingSessionFuzzTest`; external review | M3 | Implemented (M3.1, M3.3); external review open |
| TM-32 | SR-203 | — | T-LAN-04: `LockoutTest`, `PairerTest.failuresAreCountedAndTheThirdLocksPairing` | M3 | Implemented (M3.3) |
| TM-33 | SR-202 | — | T-LAN-03: `SequenceAndOctetsTest`, `PairingSessionTest`, `ShareSessionTest`, `PairingSessionFuzzTest`, `ShareSessionFuzzTest` | M3 | Implemented (M3.2–M3.4) |
| TM-34 | SR-204, SR-205 | — | T-LAN-05: `SharesTest`, `ShareSessionTest`, `ShareServerTest`, `ShareSessionFuzzTest`; T-LAN-06 (protocol side): `ShareServerTest.aRevokedOrUntrustedOrUnofferedDeviceFailsTheHandshake`; T-LAN-06 (vault side): `LanEndToEndTest.removingADeviceInAnotherProcessClosesAWindowAlreadyOpenToIt`, `SharesTest.aDeviceNoLongerAdmittedGetsNoDataEvenAfterTheOffer` | M3 | SR-204 Implemented (M3.4); SR-205 Implemented (M3.6) |
| TM-35 | SR-206 | MSC05-J, IDS11-J | T-FUZZ-LAN: `FramesTest`, `MessagesTest`, `LanCodecFuzzTest`, `PairingSessionFuzzTest`, `ShareSessionFuzzTest`, `WebRouteFuzzTest`; runs in `docs/security/fuzz/M3-fuzz-runs.md` | M3 | Implemented (M3.2, M3.7) |
| TM-36 | SR-207 | THI04-J, FIO14-J | T-LAN-07: `ShareServerTest` (port closed after delivery, expiry, revocation), `WebServerTest` (port closed after delivery, expiry, close) | M3 | Implemented (M3.4, M3.5) |
| TM-37 | SR-208 | ERR03-J | T-LAN-08: `LanHelpersTest.aPayloadAppliesOnlyIfItMatchesTheAcceptedOfferAndOnlyOnce` (kind or summary differing from the accepted offer, or an unpaired sender, applies nothing; a failed save takes back the item and the replay entry), `LanEndToEndTest.pairShareReceiveRevokeAndRefuseAnUnpairedPeer` (received login equals the original), `LanScreensTest.pairShareReceiveAndRevokeBetweenTwoScreens` | M3 | Implemented (M3.6) |
| TM-40 | SR-209 | — | T-WEB-01: `WebShareTest`, `WebIdentityTest`, `WebServerTest`, `NodePageTest`, `WebRouteFuzzTest` | M3 | Implemented (M3.5) |
| TM-41 | SR-204, SR-209 | — | T-LAN-05, T-WEB-01: `WebServerTest` (ciphertext once, only after the page, 410 after expiry and revocation), `WebRouteFuzzTest` | M3 | Implemented (M3.5) |
| TM-42 | SR-210 | — | T-WEB-02: `WebPageTest` (CSP hash, no storage APIs), `WebServerTest` (security headers), `NodePageTest` | M3 | Implemented (M3.5) |
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
| TM-61 | SR-017 | MSC02-J | ArchUnit `ModuleBoundaryTest.onlyCryptoUsesJca`. No class outside `pm.crypto` depends on `javax.crypto` or `java.security`, other than `Principal`. The M4 code is covered too: SSH keys and the agent live in `pm.crypto.ssh`, and breach SHA-1 goes through `pm.crypto.Hash` | M4 | Implemented (M4.5: the rule predates M4 and passes over all M4 code in the gate; this row said Planned) |
| TM-61 | SR-060 | MSC03-J, FIO13-J | ArchUnit `onlyTheCliReachesSshKeys`, `SshKeyTest` | M4 | Implemented (M4.3) |
| — | SR-061 | FIO00-J, FIO15-J, FIO16-J | `SshAgentClientTest` | M4 | Implemented (M4.3) |
| — | SR-140 | FIO00-J, FIO15-J | `SshAgentClientTest.theUserAndRootAreTrustedAndNoOneElse`, `.aRootPeerIsTrustedOnlyWhereAllowed`, `.launchdsListenerIsRecognisedByPlaceOwnerAndMode`, `.refusesADirectoryOwnedBySomeoneElse`, `.refusesASocketOwnedBySomeoneElse`, `.theMacOsLaunchdAgentSocketIsAccepted` (macOS launchd socket only) | M7 | Implemented (M7.9) |
| — | SR-062 | IDS00-J, NUM00-J, MSC05-J | `SshKeyTest`, `SshAgentClientTest` | M4 | Implemented (M4.3) |
| — | SR-063 | FIO01-J, FIO16-J | `SshKeyExportTest` | M4 | Implemented (M4.3) |
| — | SR-064 | ERR01-J | `SshKeyTest` | M4 | Implemented (M4.3) |
| TM-61 (hostile key file or agent reply) | SR-062, SR-064 | IDS00-J, NUM00-J, MSC05-J | T-FUZZ-SSH: `OpenSshKeyFuzzTest` and `AgentReplyFuzzTest`. These check the exact documented code (an independent armour grammar and header model for key files; a differential agent-reply reference), bounded allocation (the agent ceiling tied to the 256 KiB frame limit), spec limits written in the harness, and a round trip. They include deterministic at-limit and one-past-limit tests (`limitsHoldAtAndJustPastTheirValues`: 64 KiB file, 4 KiB comment, 1,024/1,025 identities, 256 KiB frame ± 1). The M4.5 review's grammar oracle found lax base64 and a mid-line END accepted (fixed in `OpenSshFormat`, `SshKeyTest.refusesLaxBase64AndAnEndLineThatDoesNotStartALine`) and a FAILURE reply with trailing bytes accepted (fixed in `SshAgentClient`). Runs and planted-bug proofs are in `docs/security/fuzz/M4-fuzz-runs.md` | M4 | Implemented (M4.5) |
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
| TM-70 (hostile or oversized range response misread) | SR-074, SR-078 | IDS00-J, NUM00-J | T-FUZZ-BREACH: `BreachRangeFuzzTest`. It checks `BreachClient.match` against a regex reference of ADR 0012 §8, that only `MALFORMED` is thrown, that the suffix is zero-filled, and that allocation stays bounded. Every input goes through the production collector (`BreachClient.boundedBody()`, the 1 MiB cap `fetch` uses), stretched up to 1 MiB + 1, and `.productionBodyLimitHoldsAtAndJustPastOneMebibyte` pins 1 MiB and 1 MiB + 1. Runs are in `docs/security/fuzz/M4-fuzz-runs.md` | M4 | Implemented (M4.5) |

## M4.4 generate, health and ssh in the CLI and TUI

| Threat | SR | CERT | Test / check | Milestone | Status |
| --- | --- | --- | --- | --- | --- |
| — (generated secret copied into logs or extra output) | SR-072, SR-501 | MSC03-J, FIO13-J | `GenerateCommandTest` (stdout holds exactly the secret, entropy on stderr, `@SecretBoundary` print-once from the `SecretChars` buffer; `.generateRunsWithoutATerminalSoItCanBePiped`: only `generate` runs without a console, others still refused); `ToolsTest.generatorHonoursThePolicyAndClearsItsResult` (TUI result emptied on close and lock) | M4 | Implemented (M4.4) |
| — (unrequested network use by `pm health`) | SR-078 | MSC00-J | `HealthCommandTest.withoutBreachNoClientIsBuiltAndNoRequestIsSent`, `.breachAsksFirstAndSendsNothingWhenDeclined`, `.closedInputAtTheConfirmationSendsNothing`, `.onlyAnExactYConfirms`, `.nothingToLookUpSkipsThePromptAndTheClient` (loopback server sees no request, no client built); TUI health view is offline only (`ToolsTest.healthOpensFromTheMenuWithTheBreachHint`) | M4 | Implemented (M4.4) |
| TM-70 (breach check leaks more than a hash prefix) | SR-074 | MSC00-J | `HealthCommandTest.confirmedBreachSendsOnePrefixPerDistinctPassword` (only `/range/<5 hex>` requests, one per distinct password); confirmation text names the 5-character prefix | M4 | Implemented (M4.4) |
| — (breach failure misreported) | SR-501 | ERR00-J | `HealthCommandTest.malformedAndTimedOutRepliesMapToClearMessages`, `.everyFailureCodeHasAMessage` | M4 | Implemented (M4.4) |
| — (private key bytes handled outside `pm.crypto.ssh`) | SR-060 | MSC03-J | `SshCommandsTest` (import/add/remove/export via the `pm.crypto.ssh` API only); `pm.tui` reaches the agent through the `SshActions` port implemented in `pm.cli` (ArchUnit `onlyTheCliReachesSshKeys`) | M4 | Implemented (M4.4) |
| — (unsafe or missing agent socket) | SR-061 | FIO00-J | `SshCommandsTest.noAgentIsReportedClearly` (unset `SSH_AUTH_SOCK` and no listener are both exit 9), `.tuiAdapterMapsEveryOutcome` | M4 | Implemented (M4.4) |
| — (stalled agent hangs the CLI or freezes the TUI) | SR-061, SR-504 | TPS00-J, FIO00-J | `SshAgentClientTest.aStalledAgentTimesOutAndTheConnectionIsClosed`, `.timeoutsMustBePositive` (10 s deadline on every agent request, connection dropped); `SshCommandsTest.aStalledAgentEndsInABoundedError` (exit 9, `AGENT_TIMEOUT` in the TUI); `ToolsTest.aPendingAgentCallKeepsTheUiLiveAndLockTearsTheDialogDown`, `.aRefusedOrFailingCallIsReportedAsAFailure` (agent calls run off the GUI thread on a private key copy; lock tears the dialog down and a late result is dropped) | M4 | Implemented (M4.4) |
| — (agent-supplied text injects terminal escapes) | SR-501 | IDS03-J | `SshAgentClientTest.agentKeyTypesAreMadeSafeToPrint`; `SshCommandsTest.agentFieldsArePrintedSafely` (type, fingerprint and comment pass through `Cli.displaySafe`) | M4 | Implemented (M4.4) |
| — (key file swapped or read through a link during import; plaintext original left behind) | SR-060 | FIO01-J, FIO05-J | `SshCommandsTest.importRefusesMalformedMissingAndLinkedFiles`, `.importRefusesDirectoriesAndOversizedFiles` (one `O_NOFOLLOW` open, regular-file and (device, inode) check around it, capped read), `.importWarnsWhenOthersCanReadTheKeyFile`, `.importDefaultsTheTitleToTheComment` (delete-the-original advice) | M4 | Implemented (M4.4) |
| — (export overwrites a file or leaves it readable) | SR-063 | FIO01-J, FIO02-J | `SshCommandsTest.exportWritesAnOwnerOnlyFileAndNeverOverwrites` (0600, refused before unlock when the target exists), `.exportToAMissingFolderIsAUsageErrorBeforeUnlocking` (exit 2) | M4 | Implemented (M4.4) |
| — (key release not audited) | SR-112 | — | `SshCommandsTest.addWithConstraintsThenListThenRemove`, `.exportWritesAnOwnerOnlyFileAndNeverOverwrites`, `.tuiAdapterMapsEveryOutcome`, `.aFailedExportIsAuditedAsFailed`, `.aStalledAgentEndsInABoundedError` (an `export` entry before each release naming the target and the key's public SHA-256 fingerprint, never the title; a release that then fails gets a second entry with decision `FAILED`) | M4 | Implemented (M4.4) |

## M6 passkey keys

| Threat | SR | CERT | Test / check | Milestone | Status |
| --- | --- | --- | --- | --- | --- |
| — (passkey private key leaves pm-crypto) | SR-080, SR-402 | MSC03-J, OBJ01-J | Compiler (`exports pm.crypto.passkey to pm.vault, pm.domain, pm.browser`, `exports pm.crypto.passkey.storage to pm.vault`), ArchUnit `onlyVaultDomainAndBrowserReachPasskeys`, `onlyTheVaultReachesPasskeyStorage`, `PasskeyKeyTest.secretsAreZeroedOnClose`, `PasskeyStorageTest` | M6 | Implemented (M6.1) |
| — (corrupted or substituted stored key signs) | SR-081 | IDS00-J | `PasskeyKeyTest.invalidStorageFormsAreRefused` | M6 | Implemented (M6.1) |
| — (biased or weak passkey scalar) | SR-081, SR-084 | MSC02-J | `PasskeyKeyTest.generationRejectsOutOfRangeCandidates`, `.credentialIdsAreRandom32Bytes` | M6 | Implemented (M6.1) |
| — (signature rejected by relying parties or nonce reuse) | SR-082 | IDS00-J | `PasskeyKeyTest.rfc6979VectorsAreReproducedExactly`, `.assertionSignatureIsDerOverAuthenticatorDataAndClientDataHash`, `Es256Test` | M6 | Implemented (M6.1) |
| — (public key misencoded or malformed key accepted) | SR-083 | IDS00-J | `CoseKeyTest` | M6 | Implemented (M6.1) |
| — (passkey key read outside pm.vault, or shown in logs) | SR-085, SR-086, SR-402 | MSC03-J, OBJ01-J | `PasskeyRecordTest.noPublicMethodHandsOutTheKeyOrAdvancesTheCounter`, `.thePublicCodecRefusesPasskeysBothWays`, `.toStringShowsNoSecretOrIdentifyingBytes`, `.closeZeroFillsTheKey`; `PasskeyOutsideModuleTest` (javac refuses an outside module); ArchUnit `onlyTheVaultReachesVaultInternals`, `onlyTheVaultBuildsPasskeyRecords`; `pm.vault.internal` not exported | M6 | Implemented (M6.2) |
| — (passkey key closed or replaced from outside the vault) | SR-085 | OBJ05-J | T-PK-02 `PasskeyVaultOwnershipTest.recordsAndSearchHandOutKeylessViews`, `.closingAnythingHandedOutLeavesTheVaultUsable`, `.aPutKeepsTheVaultsKeyAndCounterAndTakesOnlyTheEditableFields` | M6 | Implemented (M6.2) |
| — (signing pushes recovery points out of the .bak.N rotation) | SR-087 | FIO02-J | T-PK-02 `PasskeyVaultOwnershipTest.signingDoesNotPushOutTheBackupOfADeletedRecord` | M6 | Implemented (M6.2) |
| — (spoofed RP ID or misleading account name shown to the user) | SR-085 | IDS00-J | `PasskeyRecordTest.refusesRpIdsThatAreNotCanonicalHostNames`, `.refusesNamesThatAreUnsafeToDisplay`, `.refusesNamesWithNoVisibleCharacter`, `.acceptsNamesWithALetterNumberPunctuationOrSymbol` | M6 | Implemented (M6.2) |
| — (signature over a foreign RP ID hash, an unchecked flag set or a counter other than the persisted one) | SR-087 | IDS00-J | T-PK-02 `PasskeyVaultOwnershipTest.authenticatorDataNotBoundToTheRecordIsRefusedAndTheCounterStaysBurnt`, `.userVerifiedAndExtensionDataAreLeftToTheCaller` | M6 | Implemented (M6.2) |
| — (passkey record silently loses or gains fields on rewrite, or holds a key that does not load) | SR-086 | IDS00-J, SER01-J | `PasskeyRecordTest.theKeySetIsExact`, `.theCddlListsExactlyTheKeysTheCodecWrites`, `.roundTripsThroughThePayloadWithEveryField`, `.aKeyThatDoesNotLoadIsRefusedAtDecode` | M6 | Implemented (M6.2) |
| AC-51 (counter regresses, RP flags clone) | SR-087, SR-088, SR-401 | ERR03-J, LCK00-J | T-PK-02 `PasskeyCounterTest` (save failure, codec failure, crash after save, concurrent signers); `PasskeyVaultOwnershipTest` (stale put, re-entrant port, restore raises by 2^20 and above the overwritten vault, same backup restored twice, raise to the top exhausts); a hand-copied `.bak.N` or older vault file still regresses it (residual, ADR 0016 addendum) | M6 | Implemented (M6.2), manual-copy case open |
| — (counter wraps or repeats at u32 maximum) | SR-089 | NUM00-J | `PasskeyCounterTest.theCounterStopsAtTwoToTheThirtyTwoMinusOne` | M6 | Implemented (M6.2) |

## M7 packaging (M7.3)

| Threat | SR | CERT | Test / check | Milestone | Status |
| --- | --- | --- | --- | --- | --- |
| TM-93 (debug or monitoring entry point in the shipped runtime) | SR-710, SR-801 | ENV05-J, ENV06-J | T-PKG-01: `jlinkImage` fails on any forbidden module and on a missing required one (`java --list-modules` of the built image) | M7 | Implemented (M7.3) |
| TM-93, TM-15 (attach, heap dump or core dump exposes vault memory) | SR-711, SR-502 | ENV05-J, ENV06-J | T-PKG-01: `jlinkImage` checks `-XX:+PrintFlagsFinal` of the built runtime; flags also passed as jpackage `--java-options`; R of `tools/packaging/launcher/pm`, `pm.bat` | M7 | Implemented (M7.3) |
| TM-93, TM-15 (JVM options injected through `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` or `JDK_JAVA_OPTIONS` undo the hardening) | SR-711, SR-502 | ENV05-J | `MainJvmOptionsTest` (each variable gives exit 2, value not echoed; empty or unset runs), `EnvTest.jvmOptionVariablesAreDetectedByPresenceOnly`, `releaseSmoke` (app-image launcher with `JAVA_TOOL_OPTIONS` exits 2) | M7 | Implemented (M7.3); detection only, residual risk accepted (docs/release/packaging.md) |
| TM-91 (tampered or non-reproducible release) | SR-712, SR-601 | ENV01-J | T-PKG-04: `tools/packaging/repro-check.sh` (two clean builds identical; second-machine run is a user-only step, docs/release/packaging.md) | M7 | Implemented (M7.3), second machine pending |
| TM-90 (unknown dependency shipped) | SR-713, SR-600 | — | T-PKG-02/T-PKG-03: `releaseMetadataCheck` (in `check`): SBOM parsed back, every jar's purl and SHA-256 and the runtime `lib/modules` SHA-256 recomputed, graph refs resolve; manifest writer/verifier detects a changed byte, a malformed line and a `../` name | M7 | Implemented (M7.3) |
| TM-91 (installer payload differs from the reviewed image) | SR-713, SR-601 | — | `releaseSmoke`: app-image and mounted dmg `lib/modules`, `release` and jars match the image; packaged `pm --help` runs | M7 | Implemented (M7.3) |
| TM-93 (packaged runtime lacks a module the app needs at run time; the shipped TUI crashes) | SR-710 | — | `releaseSmoke`: the archive and app-image launchers create a throwaway vault and the TUI is still running, with no internal error, 30 s after opening (under `script(1)`) | M7 | Implemented (M7.3) |
| TM-91 (unsigned or wrongly signed installer) | SR-714, SR-601 | MSC03-J | Signing hooks (env-driven); Developer ID, notarization, Authenticode and gpg key are user-only | M7 | Hooks implemented; signing pending (user-only) |

## M3.6 LAN sharing in the CLI and TUI

| Threat | SR | CERT | Test / check | Milestone | Status |
| --- | --- | --- | --- | --- | --- |
| TM-30, TM-31 (pinned trust stored outside the vault) | SR-090 | MSC03-J | `DeviceRecordTest`, `LanHelpersTest.theDeviceIdentityLivesInTheVaultAndIsNeverShared` | M3 | Implemented (M3.6) |
| TM-31, TM-32 (pairing confirmed without comparing the code) | SR-091, SR-203 | — | `LanEndToEndTest.aRejectedCodePinsNothing`, `LanScreensTest.aRejectedCodePinsNothingAndADeniedShareSendsNothing` | M3 | Implemented (M3.6) |
| TM-34, TM-40 (share sent without approval, browser link risk unexplained) | SR-092, SR-209 | — | `LanCommandsTest.aDeniedBrowserShareOpensNothingButShowedEveryWarningFirst`, `LanEndToEndTest.browserShareShowsTheUrlFingerprintAndWarningsAndIsRevocable` | M3 | Implemented (M3.6) |
| TM-33, TM-34 (unpaired peer or revoked window receives an item) | SR-093, SR-204, SR-205 | ERR03-J | `LanEndToEndTest.pairShareReceiveRevokeAndRefuseAnUnpairedPeer` (end-to-end loopback, two file vaults), `LanScreensTest.pairShareReceiveAndRevokeBetweenTwoScreens` | M3 | Implemented (M3.6) |
| TM-34 (removed device served by a window opened before the removal) | SR-095, SR-205 | — | `LanEndToEndTest.removingADeviceInAnotherProcessClosesAWindowAlreadyOpenToIt`, `LanEndToEndTest.removalReachesAWindowOpenedUnderAnotherRunDirectory`, `SharesTest.aDeviceNoLongerAdmittedGetsNoDataEvenAfterTheOffer` | M3 | Implemented (M3.6) |
| TM-32 (lockout reset by starting a new pairing) | SR-096, SR-203 | — | `LanEndToEndTest.thePairingLockoutHoldsForTheNextPairInvocation`, `LanEndToEndTest.aConcurrentPairingNeverWeakensThePersistedLockout`, `LockoutTest.aSavedStateRestoresAndAFarFutureLockIsCappedAtOneHour` | M3 | Implemented (M3.6) |
| TM-33, TM-37 (share replayed to a new receive; payload differs from the accepted offer) | SR-097, SR-098, SR-204, SR-208 | ERR03-J | `LanHelpersTest.aPayloadAppliesOnlyIfItMatchesTheAcceptedOfferAndOnlyOnce`, `DeviceRecordTest.receivedSharesAreKeptUntilTheyExpireWithoutRepeatsAndBounded` | M3 | Implemented (M3.6) |
| TM-31 (a Yes meant for another question confirms a pairing code) | SR-098, SR-091 | — | `LanScreensTest.anAnswerOnlyReachesTheQuestionOnScreenAndASecondOneWaits` | M3 | Implemented (M3.6) |
| TM-36 (listener left open after lock or removal) | SR-094, SR-207 | THI04-J | `LanScreensTest.aBrowserLinkShowsTheWarningsUrlAndFingerprintAndLockRevokesIt`, `LanEndToEndTest` (`devices remove` rotate checklist) | M3 | Implemented (M3.6) |

## M6.3 WebAuthn authenticator

| Threat | SR | CERT | Test / check | Milestone | Status |
| --- | --- | --- | --- | --- | --- |
| — (page claims an RP ID it does not control, or a public suffix) | SR-116, SR-400 | IDS00-J | T-PK-01 `RpIdTest`, `PublicSuffixListTest`; T-PK-04 `WebauthnBridgeTest.createRefusalsHappenBeforeAnyPrompt`, `.getRefusalsHappenBeforeAnyPrompt` | M6 | Implemented (M6.3) |
| — (assertion bound to another origin, a framed context or another ceremony) | SR-117 | IDS00-J | T-PK-04 `WebAuthnVectorsTest.clientDataOfTheVectorsIsCheckedAndHashed`, `.clientDataMustBeOneBoundedObjectWithTheRequiredMembers` | M6 | Implemented (M6.3) |
| — (relying party rejects pm's credentials, or pm claims UV it did not do) | SR-118 | IDS00-J | T-PK-04 `WebAuthnVectorsTest` (§16 vectors), `AuthenticatorDataTest` | M6 | Implemented (M6.3) |
| — (key generated or returned outside the vault; enrollment lost on a failed save) | SR-115, SR-402 | MSC03-J | T-PK-03 `PasskeyEnrollmentTest`; T-PK-04 `WebauthnMessagesTest` | M6 | Implemented (M6.3) |
| AC-51, — (sign-in without approval, wrong passkey, counter lowered) | SR-119, SR-401 | ERR03-J | T-PK-04 `WebauthnBridgeTest` (N sign-ins strictly increase, restore cannot lower, every refusal, unconsumed grant) | M6 | Implemented (M6.3) |
| — (UP claimed for a ceremony nobody approved: a session or policy grant covering later passkey creates or sign-ins, silent `.bak` rotation by repeated creates) | SR-119 | ERR03-J | T-PK-04 `WebauthnBridgeTest.aSessionAnswerCountsOnceSoTheNextGetPromptsAgain`, `.aPolicyAnswerLeavesNoPolicySoAGetAfterLockAndUnlockPrompts`, `.everyEnrollmentPromptsEvenAfterASessionAnswer`; `ApprovalBrokerTest.row5PasskeyPromptsEveryTimeWhateverTheAnswer`; `ApprovalDialogTest.aPasskeyPromptOffersOnlyOnceOrDenyAndIgnoresSAndP` | M6 | Implemented (M6.3) |
| — (page learns which credentials the vault holds without consent, WebAuthn §14.5) | SR-119 | ERR03-J | T-PK-04 `WebauthnBridgeTest.anExcludedCredentialIsReportedOnlyAfterTheUserConsents`; pre-prompt `NOT_FOUND`/`AMBIGUOUS`/`NOT_ALLOWED` stay with the extension (ADR 0016, M6.4 obligation) | M6 | Implemented (M6.3) |
| — (an autofill grant, another passkey's grant or another origin's grant spent on a passkey by a caller of the port other than the bridge) | SR-119 | ERR03-J | T-PK-04 `WebauthnBridgeTest.thePortRefusesASilentAutofillGrantForTheSamePasskey`, `.thePortRefusesAGrantForAnotherPasskeyOrOrigin`, `.thePortRefusesEveryGrantWithoutAPublicSuffixList` | M6 | Implemented (M6.3) |
| — (damaged Public Suffix List ends the native host) | SR-116 | ERR03-J | T-PK-01 `PslUnavailableHostTest`, `RpIdTest.aDamagedListRefusesEveryCheckWithPslUnavailableAndIsReadOnce`, `PublicSuffixListTest.aMissingOrTamperedSnapshotIsEmptyNotAnError` | M6 | Implemented (M6.3) |
| — (passkey renamed, removed, or vault locked or saved from inside the signing port) | SR-115 | MSC03-J | T-PK-03 `PasskeyEnrollmentTest.lockedAndReentrantCallsAreRefused` (create, edit, rename, put, remove, save and close `REENTRANT`), `PasskeyCounterTest.anotherThreadsRemoveWaitsForTheSignature` | M6 | Implemented (M6.3) |
