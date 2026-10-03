// pm-sharing — see plan.md §10 module tiers
dependencies {
    // The LAN wire format reuses the vault's deterministic CBOR codec (qualified export, SR-206).
    api(project(":modules:pm-vault"))
}

// Tier 1 network-facing parser: the gate enforces 100% branch coverage here as for pm-crypto.
tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
}
