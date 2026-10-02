// pm-crypto — see plan.md §10 module tiers
dependencies {
    // ADR 0007: the one audited third-party crypto dependency (Argon2id, HKDF); pinned and checksum-verified.
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
}

// Tier 1: the gate enforces 100% branch coverage for pm-crypto (the rule itself is configured in the root build).
tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
}
