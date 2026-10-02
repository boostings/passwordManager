import com.github.spotbugs.snom.SpotBugsTask
import net.ltgt.gradle.errorprone.errorprone
import java.time.Instant

plugins {
    java
    id("net.ltgt.errorprone") version "4.4.0" apply false
    id("com.github.spotbugs") version "6.2.6" apply false
    pmd
}

val tier1 = setOf("pm-crypto", "pm-vault", "pm-storage", "pm-approval", "pm-sharing", "pm-browser")

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "net.ltgt.errorprone")
    apply(plugin = "com.github.spotbugs")
    apply(plugin = "pmd")
    apply(plugin = "jacoco")

    group = "pm"
    version = "0.0.1-M0"

    java {
        toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
        modularity.inferModulePath.set(true)
    }

    dependencies {
        "errorprone"("com.google.errorprone:error_prone_core:2.42.0")
        "spotbugsPlugins"("com.h3xstream.findsecbugs:findsecbugs-plugin:1.14.0")
        "testImplementation"(platform("org.junit:junit-bom:5.13.4"))
        "testImplementation"("org.junit.jupiter:junit-jupiter")
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
        "testImplementation"("net.jqwik:jqwik:1.9.3")
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror", "-parameters"))
        options.errorprone {
            disableWarningsInGeneratedCode.set(true)
            allErrorsAsWarnings.set(false)
            // CERT-mapped checks promoted to errors (see docs/security/cert-applicability.md)
            error(
                "CheckReturnValue",          // EXP00-J
                "EqualsHashCode",            // MET09-J
                "ArrayEquals",               // EXP02-J
                "BoxedPrimitiveEquality",    // EXP03-J
                "CollectionIncompatibleType",// EXP04-J
                "DoubleCheckedLocking",      // LCK10-J
                "GuardedBy",                 // VNA/LCK families
                "ThreadPriorityCheck",
                "MissingOverride",
                "DefaultCharset",            // FIO11-J
                "StringSplitter"
            )
        }
    }
    // Reproducible archives (SR-601)
    tasks.withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform { excludeTags("hardware") }
        jvmArgs("-XX:+DisableAttachMechanism")
        systemProperty("pm.canary.secret", "CANARY-7f3a9c2e-DO-NOT-LOG")
    }

    configure<PmdExtension> {
        toolVersion = "7.17.0"
        isConsoleOutput = true
        isIgnoreFailures = false
        ruleSets = listOf()
        ruleSetFiles = files(rootProject.file("tools/cert-rules/pmd-cert.xml"))
    }

    configure<com.github.spotbugs.snom.SpotBugsExtension> {
        effort.set(com.github.spotbugs.snom.Effort.MAX)
        reportLevel.set(com.github.spotbugs.snom.Confidence.LOW)
        ignoreFailures.set(false)
        excludeFilter.set(rootProject.file("tools/cert-rules/spotbugs-exclude.xml"))
    }
    tasks.withType<SpotBugsTask>().configureEach {
        reports.create("xml") { required.set(true) }
        reports.create("html") { required.set(true) }
    }

    if (name in tier1) {
        tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
            violationRules { rule { limit { counter = "BRANCH"; minimum = "1.00".toBigDecimal() } } }
        }
        // Tier 1 modules may not depend on TUI/CLI or platform modules (enforced also by ArchUnit).
        configurations.all {
            resolutionStrategy.eachDependency {
                if (requested.group == "pm" && (requested.name.startsWith("pm-tui") || requested.name.startsWith("pm-cli") || requested.name.startsWith("pm-platform"))) {
                    throw GradleException("Tier 1 module ${project.name} may not depend on ${requested.name}")
                }
            }
        }
    }
}

// ---- Semgrep CERT rule pack ------------------------------------------------
val semgrepCert = tasks.register<Exec>("semgrepCert") {
    group = "verification"
    description = "Run the CERT Semgrep rule pack (tools/cert-rules/semgrep/) over all Java sources."
    val out = layout.buildDirectory.file("reports/semgrep-cert.json")
    outputs.file(out)
    // Real inputs, so a source or rule change re-runs the scan instead of reusing a stale report.
    // Semgrep scans every non-git-ignored file under modules/ (tracked or not; verified with an
    // untracked probe file), so the Java file tree plus the ignore files fully determine the scan
    // set and `git ls-files` is not needed. The tree is a superset (it also contains git-ignored
    // files), which can only cause an extra run, never a stale one. The single exclude is each
    // module's own output dir (modules/<module>/build/), the same anchored path that .gitignore
    // and .semgrepignore skip. An unanchored `**/build/**` would also drop a source package named
    // `build` (src/main/java/pm/crypto/build/), which Semgrep does scan, and the report would go
    // stale; keep all three anchored the same way.
    inputs.files(fileTree("modules") { include("**/*.java"); exclude("*/build/**") })
        .withPropertyName("javaSources").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.dir("tools/cert-rules/semgrep")
        .withPropertyName("rules").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.file(".semgrepignore")
        .withPropertyName("semgrepignore").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.files(".gitignore")
        .withPropertyName("gitignore").withPathSensitivity(PathSensitivity.RELATIVE)
    doFirst { out.get().asFile.parentFile.mkdirs() }
    commandLine("semgrep", "scan", "--config", "tools/cert-rules/semgrep", "--error", "--json",
        "--output", out.get().asFile.path, "--metrics=off", "modules")
}

// ---- gitleaks --------------------------------------------------------------
val gitleaksScan = tasks.register<Exec>("gitleaksScan") {
    group = "verification"
    description = "Secret scan of the working tree and history (SR-800)."
    commandLine("gitleaks", "git", "--redact", "--no-banner", "--config", "tools/cert-rules/gitleaks.toml", ".")
}

// ---- certReport ------------------------------------------------------------
val certReport = tasks.register("certReport") {
    group = "verification"
    description = "Aggregate compiler, PMD, SpotBugs, Semgrep and ArchUnit results into build/reports/cert-compliance.md and fail on any Enforced-rule finding."
    // spotbugsTest is required because the parser below reads every XML in reports/spotbugs,
    // including test.xml; without the dependency it could read a stale or missing test report.
    dependsOn(subprojects.map { it.tasks.matching { t -> t.name in setOf("pmdMain", "pmdTest", "spotbugsMain", "spotbugsTest", "test") } })
    dependsOn(semgrepCert)
    val reportFile = layout.buildDirectory.file("reports/cert-compliance.md")
    outputs.file(reportFile)
    // The report embeds the commit hash and a timestamp, and aggregates reports from many tasks,
    // so it must regenerate on every invocation; never let Gradle call it UP-TO-DATE.
    outputs.upToDateWhen { false }
    doLast {
        val findings = mutableListOf<String>()
        // PMD
        subprojects.forEach { p ->
            p.layout.buildDirectory.dir("reports/pmd").get().asFile.listFiles { f -> f.extension == "xml" }?.forEach { f ->
                Regex("<violation[^>]*rule=\"([^\"]+)\"[^>]*>").findAll(f.readText()).forEach { m -> findings += "PMD ${m.groupValues[1]} in ${p.name}" }
                // A PMD processing error means a file was never analysed; count it so "0 findings" cannot be vacuous.
                Regex("<error[^>]*filename=\"([^\"]+)\"").findAll(f.readText()).forEach { m -> findings += "PMD processing error on ${m.groupValues[1].substringAfterLast('/')} in ${p.name}" }
            }
            p.layout.buildDirectory.dir("reports/spotbugs").get().asFile.listFiles { f -> f.extension == "xml" }?.forEach { f ->
                Regex("<BugInstance[^>]*type=\"([^\"]+)\"").findAll(f.readText()).forEach { m -> findings += "SpotBugs ${m.groupValues[1]} in ${p.name}" }
            }
        }
        // Semgrep
        val sg = layout.buildDirectory.file("reports/semgrep-cert.json").get().asFile
        if (sg.exists()) {
            Regex("\"check_id\":\\s*\"([^\"]+)\"").findAll(sg.readText()).forEach { m -> findings += "Semgrep ${m.groupValues[1]}" }
        }
        val md = buildString {
            appendLine("# CERT compliance report")
            appendLine()
            appendLine("Generated: ${Instant.now()}  Commit: ${runCatching { ProcessBuilder("git","rev-parse","--short","HEAD").start().inputStream.bufferedReader().readText().trim() }.getOrDefault("?")}")
            appendLine()
            appendLine("Applicability table: docs/security/cert-applicability.md")
            appendLine()
            appendLine("| Source | Findings |"); appendLine("| --- | --- |")
            appendLine("| Compiler (-Werror, Error Prone) | pass (build would have failed) |")
            appendLine("| PMD cert ruleset | ${findings.count { it.startsWith("PMD") }} |")
            appendLine("| SpotBugs + FindSecBugs | ${findings.count { it.startsWith("SpotBugs") }} |")
            appendLine("| Semgrep cert pack | ${findings.count { it.startsWith("Semgrep") }} |")
            appendLine()
            if (findings.isEmpty()) appendLine("**Result: 0 findings.**") else { appendLine("## Findings"); findings.forEach { appendLine("- $it") } }
        }
        reportFile.get().asFile.apply { parentFile.mkdirs(); writeText(md) }
        println(md)
        if (findings.isNotEmpty()) throw GradleException("certReport: ${findings.size} finding(s). See ${reportFile.get().asFile}")
    }
}

tasks.register("verifyAll") {
    group = "verification"
    description = "Full gate: check + gitleaks + certReport"
    dependsOn("check", gitleaksScan, certReport)
}
