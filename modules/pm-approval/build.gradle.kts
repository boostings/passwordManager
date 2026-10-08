// pm-approval — see plan.md §10 module tiers
dependencies {
    api(project(":modules:pm-domain"))
}

// Tier 1: the gate enforces 100% branch coverage for pm-approval (the rule itself is configured in the root build).
tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
}
