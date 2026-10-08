// pm-cli — see plan.md §10 module tiers
dependencies {
    implementation(project(":modules:pm-tui"))
    implementation(project(":modules:pm-approval"))
    implementation(project(":modules:pm-sharing"))
    // M5.4: pm browser install/status and the native host entry (ADR 0014 §8).
    implementation(project(":modules:pm-browser"))
}

// M7.7: `pm --version` reads the version at run time, from the pm.cli module descriptor or, on
// the class path, the jar manifest; both come from the one project version, never a literal.
val pmVersion: String = project.version.toString()
tasks.named<JavaCompile>("compileJava") {
    options.javaModuleVersion.set(pmVersion)
}
tasks.named<Jar>("jar") {
    manifest {
        attributes("Implementation-Version" to pmVersion)
    }
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
