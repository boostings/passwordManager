// pm-storage — see plan.md §10 module tiers
dependencies {
}

// Tier 1: the gate enforces 100% branch coverage for pm-storage (the rule itself is configured in the root build).
tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
}
