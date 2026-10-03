// pm-browser — see plan.md §10 module tiers
dependencies {
    // Every credential release goes through the approval broker (SR-100, SR-302).
    api(project(":modules:pm-approval"))
}

// Tier 1 parser of input from the browser: the gate enforces 100% branch coverage here as for
// pm-crypto and pm-sharing.
tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
}
