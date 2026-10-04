// pm-cli — see plan.md §10 module tiers
dependencies {
    implementation(project(":modules:pm-tui"))
    implementation(project(":modules:pm-approval"))
}

// No application plugin: this copies the pm-cli jar and every runtime module jar into one
// directory, used as the JPMS module path by scripts/pm (java -p build/modules -m pm.cli/pm.cli.Main).
tasks.register<Sync>("installModules") {
    group = "distribution"
    description = "Copy pm-cli and its runtime module jars into build/modules (used by scripts/pm)."
    from(tasks.named("jar"))
    from(configurations.named("runtimeClasspath"))
    into(layout.buildDirectory.dir("modules"))
}

// M7.3 release packaging: jlink runtime, jpackage, reproducible archives, CycloneDX SBOM and
// SHA256SUMS (docs/release/packaging.md). Adds `release` and its parts; only the fast,
// OS-independent releaseMetadataCheck joins `check`.
apply(from = rootProject.file("tools/packaging/release.gradle.kts"))
