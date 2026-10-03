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

// The MV3 extension in /extension is tested with Node's built-in runner (no npm dependencies).
// `check` runs it so the gate covers the extension too; a machine without Node fails loudly
// instead of skipping the extension silently.
val extensionDir = rootProject.layout.projectDirectory.dir("extension")
val nodeOnPath: File? = (System.getenv("PATH") ?: "")
    .split(File.pathSeparator)
    .filter { it.isNotBlank() }
    .flatMap { listOf(File(it, "node"), File(it, "node.exe")) }
    .firstOrNull { it.isFile && it.canExecute() }

val extensionTest = tasks.register<Exec>("extensionTest") {
    group = "verification"
    description = "Runs the browser extension's tests with `node --test` (Node 20+ on PATH)."
    workingDir = extensionDir.asFile
    inputs.dir(extensionDir.dir("src"))
    inputs.dir(extensionDir.dir("test"))
    inputs.dir(extensionDir.dir("native-host"))
    val marker = layout.buildDirectory.file("extension-test/passed")
    outputs.file(marker)
    commandLine(nodeOnPath?.absolutePath ?: "node", "--test", "test/*.test.js")
    doFirst {
        if (nodeOnPath == null) {
            throw GradleException(
                "extensionTest needs Node.js 20 or later on PATH to run extension/test (node --test). " +
                    "Install Node, or put it on PATH, and re-run.")
        }
    }
    doLast {
        marker.get().asFile.apply { parentFile.mkdirs(); writeText("ok\n") }
    }
}

tasks.named("check") {
    dependsOn(extensionTest)
}
