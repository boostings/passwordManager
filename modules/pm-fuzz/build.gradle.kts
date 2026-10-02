// Jazzer fuzz harnesses (T-FUZZ-*). Short run in CI, long run nightly.
dependencies {
    testImplementation(project(":modules:pm-vault"))
    testImplementation("com.code-intelligence:jazzer-junit:0.24.0")
}

tasks.withType<Test>().configureEach {
    jvmArgs("-XX:-DisableAttachMechanism")
}
