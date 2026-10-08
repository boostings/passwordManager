// Jazzer fuzz harnesses (T-FUZZ-*). Short run in CI, long run nightly.
dependencies {
    testImplementation(project(":modules:pm-crypto"))
    testImplementation(project(":modules:pm-vault"))
    testImplementation(project(":modules:pm-domain"))
    testImplementation(project(":modules:pm-sharing"))
    testImplementation(project(":modules:pm-browser"))
    testImplementation("com.code-intelligence:jazzer-junit:0.24.0")
}

tasks.withType<Test>().configureEach {
    jvmArgs("-XX:-DisableAttachMechanism")
    // Jazzer's default filter instruments only classes found in class-path directories. pm-crypto,
    // pm-vault, pm-domain and pm-sharing reach this module as jars, so without this the parsers and
    // protocol state machines under test would get no coverage feedback in fuzzing mode
    // (JAZZER_FUZZ=1) and the fuzzer would mutate blindly. pm.crypto.** covers the M4 ssh key and
    // agent parsers (pm.crypto.ssh); pm.browser.** and pm.approval.** cover the M5 native messaging
    // host, the bridge and the approval broker behind it.
    systemProperty(
        "jazzer.instrument",
        "pm.crypto.**,pm.vault.**,pm.domain.**,pm.sharing.**,pm.browser.**,pm.approval.**,pm.fuzz.**",
    )
}
