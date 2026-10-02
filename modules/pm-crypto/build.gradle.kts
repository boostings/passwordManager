// pm-crypto — see plan.md §10 module tiers
dependencies {
    // ADR 0007: the one audited third-party crypto dependency (Argon2id, HKDF); pinned and checksum-verified.
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
}
