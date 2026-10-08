// pm-vault — see plan.md §10 module tiers
dependencies {
    api(project(":modules:pm-crypto"))
    api(project(":modules:pm-storage"))
}

// Tier 1: the gate enforces 100% branch coverage for pm-vault (the rule itself is configured in the root build).
tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
}
