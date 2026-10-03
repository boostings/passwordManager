// Jazzer fuzz harnesses (T-FUZZ-*). Short run in CI, long run nightly.
dependencies {
    testImplementation(project(":modules:pm-vault"))
    testImplementation("com.code-intelligence:jazzer-junit:0.24.0")
}

tasks.withType<Test>().configureEach {
    jvmArgs("-XX:-DisableAttachMechanism")
    // Jazzer's default filter instruments only classes found in class-path directories. pm-vault
    // reaches this module as a jar, so without this the parsers under test would get no coverage
    // feedback in fuzzing mode (JAZZER_FUZZ=1) and the fuzzer would mutate blindly.
    systemProperty("jazzer.instrument", "pm.vault.**,pm.fuzz.**")
}
