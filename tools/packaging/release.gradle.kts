// Release packaging for pm (M7.3; SR-710 to SR-714, SR-502, SR-600, SR-601, SR-801).
// Applied by modules/pm-cli/build.gradle.kts. How to build, verify and sign: docs/release/packaging.md.
//
//   ./gradlew release                  everything below, for the current OS
//   ./gradlew jlinkImage               minimal runtime (JDK modules only) in build/release/runtime
//   ./gradlew releaseArchives          reproducible tar.gz + zip of runtime + app jars + launcher
//   ./gradlew jpackageImage            jpackage app-image (unsigned unless signing env vars are set)
//   ./gradlew jpackageInstallers       dmg+pkg (macOS), deb/rpm (Linux), msi (Windows) when the tools exist
//   ./gradlew cyclonedxSbom            CycloneDX 1.5 JSON SBOM of the runtime module path
//   ./gradlew sha256Manifest           SHA256SUMS over build/release/dist
//   ./gradlew verifyReleaseHashes      re-hash build/release/dist against SHA256SUMS
//   ./gradlew releaseSmoke             run the packaged launchers (--help, and the TUI for 30 s under a
//                                      pty); compare app-image and dmg payload hashes
//
// No third-party Gradle plugin is used (the SBOM and manifest are written here from the resolved
// runtime classpath), so gradle/verification-metadata.xml is unchanged. `check` runs only
// releaseMetadataCheck (with jlinkImage); jpackage, installers and smoke runs are under `release`.

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.lang.module.ModuleFinder
import java.security.MessageDigest
import java.time.Instant
import java.util.HexFormat
import java.util.UUID
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.component.ProjectComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedComponentResult
import org.gradle.api.artifacts.result.ResolvedDependencyResult

// ---- Platform, names and directories ---------------------------------------------------------

val hostOs: String = System.getProperty("os.name").lowercase().let {
    when {
        it.startsWith("mac") -> "macos"
        it.startsWith("windows") -> "windows"
        else -> "linux"
    }
}
val hostArch: String = when (val a = System.getProperty("os.arch")) {
    "aarch64", "arm64" -> "aarch64"
    "amd64", "x86_64" -> "x64"
    else -> a
}
val pmVersion: String = project.version.toString()
// jpackage needs a numeric version whose first component is not zero on macOS; the project
// version (0.0.1-M0) is not one. Override with -Ppm.packageVersion=1.2.3 for a real release.
val packageVersion: String = (findProperty("pm.packageVersion") as String?) ?: "1.0.0"
val distName = "pm-$pmVersion-$hostOs-$hostArch"
val sbomName = "pm-$pmVersion.cdx.json"
val manifestName = "SHA256SUMS"
val mainModule = "pm.cli/pm.cli.Main"

val releaseDir = layout.buildDirectory.dir("release")
val distDir = releaseDir.map { it.dir("dist") }
val runtimeDir = releaseDir.map { it.dir("runtime") }
val imageRoot = releaseDir.map { it.dir("image") }
val appImageRoot = releaseDir.map { it.dir("jpackage") }
val installerTmp = releaseDir.map { it.dir("installers-tmp") }
val modulesDir = layout.buildDirectory.dir("modules") // installModules output: the runtime module path
val launcherDir = rootProject.layout.projectDirectory.dir("tools/packaging/launcher")
val runtimeClasspath = configurations.named("runtimeClasspath")

val jdkHome: Provider<File> = the<JavaToolchainService>()
    .launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
    .map { it.metadata.installationPath.asFile }
val jdkVersion: Provider<String> = the<JavaToolchainService>()
    .launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
    .map { it.metadata.javaRuntimeVersion }

// Modules no `requires` clause reaches but the app loads at run time. On the full JDK the boot
// layer's service binding happens to resolve them, which is why the dev launcher (scripts/pm) never
// needed them; a jlink image has only what is listed, so leaving one out fails at run time only:
// - jdk.crypto.ec: SunEC (EC and Ed25519 key handling in pm.crypto, ADR 0013) on JDK 21.
// - jdk.unsupported: Lanterna loads sun.misc.Signal reflectively (UnixLikeTTYTerminal) for the
//   SIGWINCH terminal-resize handler.
// Lanterna's `requires static java.desktop` is followed by jdkModulesFor (TextColor uses
// java.awt.Color, so the TUI dies with NoClassDefFoundError without it). releaseSmoke drives the
// TUI for 30 s to catch the next module of this kind.
val providerModules = listOf("jdk.crypto.ec", "jdk.unsupported")
// Debug, monitoring and agent entry points that must never be in the image (SR-801, ENV05-J/ENV06-J).
val forbiddenModules = listOf(
    "jdk.jdwp.agent", "jdk.management.agent", "java.management", "java.management.rmi",
    "jdk.attach", "java.instrument", "jdk.jdi", "jdk.jshell", "jdk.jcmd", "jdk.jstatd",
)
// Baked into the runtime image (jlink --add-options) and repeated as jpackage --java-options
// (SR-502, SR-711). JVM-option environment variables (JAVA_TOOL_OPTIONS, _JAVA_OPTIONS,
// JDK_JAVA_OPTIONS) are applied by the JVM after these and can override them; pm.cli.Main refuses
// to run when one is set, which detects that case but cannot undo it (docs/release/packaging.md).
val hardeningFlags = listOf(
    "-XX:+DisableAttachMechanism", "-XX:-HeapDumpOnOutOfMemoryError", "-XX:-CreateCoredumpOnCrash",
)

// ---- Helpers ----------------------------------------------------------------------------------

fun sha256(f: File): String {
    val md = MessageDigest.getInstance("SHA-256")
    f.inputStream().use { input ->
        val buf = ByteArray(1 shl 16)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
        }
    }
    return HexFormat.of().formatHex(md.digest())
}

/** Runs a command, returns its combined output, and fails the build with that output on a non-zero exit. */
fun runCommand(cmd: List<String>, dir: File? = null): String {
    val pb = ProcessBuilder(cmd).redirectErrorStream(true)
    if (dir != null) pb.directory(dir)
    val p = pb.start()
    val out = p.inputStream.bufferedReader().readText()
    val rc = p.waitFor()
    if (rc != 0) throw GradleException("${cmd.joinToString(" ")} failed (exit $rc):\n$out")
    return out
}

fun onPath(vararg names: String): Boolean = (System.getenv("PATH") ?: "").split(File.pathSeparator)
    .filter { it.isNotBlank() }
    .any { dir -> names.any { File(dir, it).let { f -> f.isFile && f.canExecute() } } }

fun env(name: String): String? = System.getenv(name)?.takeIf { it.isNotBlank() }

fun tool(name: String): String =
    File(jdkHome.get(), "bin/" + if (hostOs == "windows") "$name.exe" else name).absolutePath

/**
 * JDK modules the application needs: every `requires` (static ones included: Lanterna's
 * `requires static java.desktop` is used at run time) of every module on the runtime module path
 * that is not itself on that path, plus the run-time-only modules above. jlink then adds their
 * transitive closure.
 */
fun jdkModulesFor(moduleDir: File): List<String> {
    val refs = ModuleFinder.of(moduleDir.toPath()).findAll()
    val appModules = refs.map { it.descriptor().name() }.toSet()
    val needed = sortedSetOf<String>()
    refs.forEach { ref ->
        ref.descriptor().requires()
            .map { it.name() }
            .filterNot { it in appModules }
            .forEach { needed += it }
    }
    needed += providerModules
    return needed.toList()
}

/** Build time for reproducible metadata: SOURCE_DATE_EPOCH, else the HEAD commit time, else none. */
fun sourceDateEpoch(): Instant? {
    env("SOURCE_DATE_EPOCH")?.let { return Instant.ofEpochSecond(it.trim().toLong()) }
    return runCatching {
        val p = ProcessBuilder("git", "log", "-1", "--format=%ct").directory(rootDir).start()
        val out = p.inputStream.bufferedReader().readText().trim()
        if (p.waitFor() == 0 && out.isNotEmpty()) Instant.ofEpochSecond(out.toLong()) else null
    }.getOrNull()
}

fun purl(group: String, name: String, version: String) = "pkg:maven/$group/$name@$version?type=jar"

/**
 * CycloneDX 1.5 JSON for the runtime module path: pm-cli as the described application, every
 * runtime jar (project modules and third-party) as a component with purl and SHA-256, the jlink
 * runtime as a platform component (SHA-256 of its lib/modules class image and of its release
 * file, and the module list jlink recorded), and the resolved dependency graph. Deterministic: sorted
 * components, no random serial number (a name-based UUID of the content), timestamp from
 * [sourceDateEpoch].
 */
fun cyclonedxJson(): String {
    val config = runtimeClasspath.get()
    val root: ResolvedComponentResult = config.incoming.resolutionResult.root
    val appJar = tasks.named<Jar>("jar").get().archiveFile.get().asFile
    val runtime = runtimeDir.get().asFile
    val jimage = File(runtime, "lib/modules")
    val releaseFile = File(runtime, "release")
    if (!jimage.isFile || !releaseFile.isFile) throw GradleException("SBOM needs the jlink runtime in $runtime; run jlinkImage")
    // The MODULES line jlink wrote: the full closure actually in the image, not just the roots.
    val linked = releaseFile.readLines(Charsets.UTF_8).firstOrNull { it.startsWith("MODULES=") }
        ?.substringAfter('=')?.trim('"')?.split(' ')?.filter { it.isNotEmpty() }?.sorted()
        ?: throw GradleException("SBOM: $releaseFile has no MODULES line")

    fun refOf(id: Any): String? = when (id) {
        is ModuleComponentIdentifier -> purl(id.group, id.module, id.version)
        is ProjectComponentIdentifier -> purl("pm", id.projectName, pmVersion)
        else -> null
    }

    val components = config.incoming.artifacts.artifacts.mapNotNull { a ->
        val id = a.id.componentIdentifier
        val (group, name, version) = when (id) {
            is ModuleComponentIdentifier -> Triple(id.group, id.module, id.version)
            is ProjectComponentIdentifier -> Triple("pm", id.projectName, pmVersion)
            else -> return@mapNotNull null
        }
        val moduleName = ModuleFinder.of(a.file.toPath()).findAll().singleOrNull()?.descriptor()?.name()
        val props = listOfNotNull(
            moduleName?.let { linkedMapOf("name" to "pm:jpms-module", "value" to it) },
            linkedMapOf("name" to "pm:file", "value" to a.file.name),
        )
        linkedMapOf(
            "type" to "library",
            "bom-ref" to purl(group, name, version),
            "group" to group,
            "name" to name,
            "version" to version,
            "scope" to "required",
            "hashes" to listOf(linkedMapOf("alg" to "SHA-256", "content" to sha256(a.file))),
            "purl" to purl(group, name, version),
            "properties" to props,
        )
    }.sortedBy { it["bom-ref"] as String } + listOf(
        linkedMapOf(
            "type" to "platform",
            "bom-ref" to "pm:jlink-runtime",
            "name" to "openjdk-jlink-runtime",
            "version" to jdkVersion.get(),
            "description" to "jlink runtime image of the JDK modules pm needs (no application code);" +
                " the hash is of runtime/lib/modules, the class image holding every linked module." +
                " Native files are excluded because platform code signing rewrites them",
            "hashes" to listOf(linkedMapOf("alg" to "SHA-256", "content" to sha256(jimage))),
            "properties" to listOf(
                linkedMapOf("name" to "pm:jlink:modules", "value" to linked.joinToString(",")),
                linkedMapOf("name" to "pm:jlink:release-sha256", "value" to sha256(releaseFile)),
                linkedMapOf("name" to "pm:jlink:options", "value" to hardeningFlags.joinToString(" ")),
            ),
        ),
    )

    val dependencies = mutableListOf<Map<String, Any>>()
    val seen = mutableSetOf<String>()
    fun walk(c: ResolvedComponentResult) {
        val ref = refOf(c.id) ?: return
        if (!seen.add(ref)) return
        val children = c.dependencies.filterIsInstance<ResolvedDependencyResult>().map { it.selected }
        dependencies += linkedMapOf("ref" to ref, "dependsOn" to children.mapNotNull { refOf(it.id) }.distinct().sorted())
        children.forEach { walk(it) }
    }
    walk(root)
    dependencies.sortBy { it["ref"] as String }

    val metadata = linkedMapOf<String, Any>()
    sourceDateEpoch()?.let { metadata["timestamp"] = it.toString() }
    metadata["tools"] = linkedMapOf("components" to listOf(
        linkedMapOf("type" to "application", "name" to "gradle", "version" to gradle.gradleVersion),
    ))
    metadata["component"] = linkedMapOf(
        "type" to "application",
        "bom-ref" to purl("pm", "pm-cli", pmVersion),
        "group" to "pm",
        "name" to "pm-cli",
        "version" to pmVersion,
        "description" to "pm: local, offline password manager (launcher module pm.cli)",
        "hashes" to listOf(linkedMapOf("alg" to "SHA-256", "content" to sha256(appJar))),
        "purl" to purl("pm", "pm-cli", pmVersion),
    )

    val body = linkedMapOf<String, Any>(
        "bomFormat" to "CycloneDX",
        "specVersion" to "1.5",
        "version" to 1,
        "metadata" to metadata,
        "components" to components.filter { it["bom-ref"] != purl("pm", "pm-cli", pmVersion) },
        "dependencies" to dependencies,
    )
    val serial = "urn:uuid:" + UUID.nameUUIDFromBytes(JsonOutput.toJson(body).toByteArray(Charsets.UTF_8))
    val bom = linkedMapOf<String, Any>("bomFormat" to "CycloneDX", "specVersion" to "1.5", "serialNumber" to serial)
    body.filterKeys { it != "bomFormat" && it != "specVersion" }.forEach { (k, v) -> bom[k] = v }
    return JsonOutput.prettyPrint(JsonOutput.toJson(bom)) + "\n"
}

/** Writes `<sha256>  <name>` lines (sha256sum/shasum -c format), sorted by name, for the given files. */
fun writeSha256Sums(manifest: File, artifacts: List<File>) {
    val lines = artifacts.sortedBy { it.name }.map { "${sha256(it)}  ${it.name}" }
    manifest.writeText(lines.joinToString("\n", postfix = "\n"), Charsets.UTF_8)
}

val manifestLine = Regex("^([0-9a-f]{64})  ([A-Za-z0-9._+-]+)$")

/** Re-hashes every file named in [manifest] (relative to its directory); returns a list of problems, empty when all match. */
fun verifySha256Sums(manifest: File): List<String> {
    val problems = mutableListOf<String>()
    val lines = manifest.readLines(Charsets.UTF_8)
    if (lines.isEmpty()) problems += "$manifestName is empty"
    lines.forEachIndexed { i, line ->
        val m = manifestLine.matchEntire(line)
        if (m == null) {
            problems += "line ${i + 1} is malformed"
            return@forEachIndexed
        }
        val f = File(manifest.parentFile, m.groupValues[2])
        when {
            !f.isFile -> problems += "${f.name}: missing"
            sha256(f) != m.groupValues[1] -> problems += "${f.name}: SHA-256 mismatch"
        }
    }
    return problems
}

/** The files a release manifest covers: everything in dist except the manifest and its signature. */
fun releaseArtifacts(dir: File): List<File> =
    (dir.listFiles() ?: emptyArray()).filter { it.isFile && it.name != manifestName && !it.name.startsWith("$manifestName.") }

// ---- jlink runtime --------------------------------------------------------------------------

val jlinkImage = tasks.register("jlinkImage") {
    group = "distribution"
    description = "Builds the minimal jlink runtime (JDK modules from the module graph only) in build/release/runtime."
    dependsOn("installModules")
    inputs.dir(modulesDir).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.property("jdk", jdkVersion)
    outputs.dir(runtimeDir)
    doLast {
        val out = runtimeDir.get().asFile
        out.deleteRecursively()
        val modules = jdkModulesFor(modulesDir.get().asFile)
        val bad = modules.filter { it in forbiddenModules }
        if (bad.isNotEmpty()) throw GradleException("jlinkImage: forbidden modules required by the module graph: $bad")
        runCommand(listOf(
            tool("jlink"),
            "--module-path", File(jdkHome.get(), "jmods").absolutePath,
            "--add-modules", modules.joinToString(","),
            "--strip-debug", "--no-header-files", "--no-man-pages", "--compress=zip-6",
            "--dedup-legal-notices=error-if-not-same-content",
            "--add-options=" + hardeningFlags.joinToString(" "),
            "--output", out.absolutePath,
        ))
        // T-PKG-01: the image holds no debug/monitoring module and its JVM gets the hardening flags.
        val java = File(out, "bin/" + if (hostOs == "windows") "java.exe" else "java").absolutePath
        val listed = runCommand(listOf(java, "--list-modules")).lines().map { it.substringBefore('@').trim() }.filter { it.isNotEmpty() }
        val leaked = listed.filter { it in forbiddenModules }
        if (leaked.isNotEmpty()) throw GradleException("jlinkImage: image contains forbidden modules $leaked")
        val missing = modules.filterNot { it in listed }
        if (missing.isNotEmpty()) throw GradleException("jlinkImage: image is missing $missing")
        val flags = runCommand(listOf(java, "-XX:+PrintFlagsFinal", "-version"))
        listOf("DisableAttachMechanism" to "true", "HeapDumpOnOutOfMemoryError" to "false", "CreateCoredumpOnCrash" to "false")
            .forEach { (flag, want) ->
                if (!Regex("\\b$flag\\s+=\\s+$want\\b").containsMatchIn(flags)) {
                    throw GradleException("jlinkImage: runtime flag $flag is not $want")
                }
            }
        logger.lifecycle("jlinkImage: ${listed.size} JDK modules: ${listed.joinToString(",")}")
    }
}

// ---- Reproducible archive image -------------------------------------------------------------

val distImage = tasks.register<Sync>("distImage") {
    group = "distribution"
    description = "Assembles runtime/, app/ and bin/pm into build/release/image/$distName."
    dependsOn(jlinkImage, "installModules")
    // jlink writes legal/ files read-only (0444), so Sync cannot overwrite an earlier image.
    doFirst { imageRoot.get().dir(distName).asFile.deleteRecursively() }
    into(imageRoot.map { it.dir(distName) })
    from(runtimeDir) { into("runtime") }
    from(modulesDir) { into("app") }
    from(launcherDir) {
        include(if (hostOs == "windows") "pm.bat" else "pm")
        into("bin")
        filePermissions { unix("rwxr-xr-x") }
    }
}

// Fixed timestamps and sorted entries come from the root build's AbstractArchiveTask settings
// (preserveFileTimestamps=false, reproducibleFileOrder=true); they are restated here so the
// archive stays reproducible even if this script is applied elsewhere. Permissions are
// normalised to 0755 (executables, directories) and 0644 (everything else) so the umask and
// checkout mode of the builder do not leak into the archive.
fun AbstractArchiveTask.releaseArchiveLayout() {
    group = "distribution"
    dependsOn(distImage)
    destinationDirectory.set(distDir)
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    dirPermissions { unix("rwxr-xr-x") }
    from(imageRoot.map { it.dir(distName) }) {
        into(distName)
        eachFile { permissions { unix(if (file.canExecute()) "rwxr-xr-x" else "rw-r--r--") } }
    }
}

val releaseTar = tasks.register<Tar>("releaseTar") {
    description = "Reproducible $distName.tar.gz of the release image."
    releaseArchiveLayout()
    compression = Compression.GZIP
    archiveFileName.set("$distName.tar.gz")
}
val releaseZip = tasks.register<Zip>("releaseZip") {
    description = "Reproducible $distName.zip of the release image."
    releaseArchiveLayout()
    archiveFileName.set("$distName.zip")
}
val releaseArchives = tasks.register("releaseArchives") {
    group = "distribution"
    description = "Builds the reproducible tar.gz and zip release archives."
    dependsOn(releaseTar, releaseZip)
}

// ---- jpackage -------------------------------------------------------------------------------

/** The app-image directory jpackage produces for this OS. */
fun appImageDirFor(root: File): File = File(root, if (hostOs == "macos") "pm.app" else "pm")

/** Where jpackage puts the runtime home and the application module jars inside an app-image. */
fun appImagePayload(appImage: File): Pair<File, File> = when (hostOs) {
    "macos" -> File(appImage, "Contents/runtime/Contents/Home") to File(appImage, "Contents/app/mods")
    "windows" -> File(appImage, "runtime") to File(appImage, "app/mods")
    else -> File(appImage, "lib/runtime") to File(appImage, "lib/app/mods")
}

fun appImageLauncher(appImage: File): File = when (hostOs) {
    "macos" -> File(appImage, "Contents/MacOS/pm")
    "windows" -> File(appImage, "pm.exe")
    else -> File(appImage, "bin/pm")
}

// Stable MSI upgrade code so a newer installer upgrades an older one instead of installing beside it.
val winUpgradeUuid: String = UUID.nameUUIDFromBytes("pm.cli/msi-upgrade-code".toByteArray(Charsets.UTF_8)).toString()

val jpackageImage = tasks.register("jpackageImage") {
    group = "distribution"
    description = "jpackage app-image for this OS from the jlink runtime and the module path (signed only when signing env vars are set)."
    dependsOn(jlinkImage, "installModules")
    inputs.dir(runtimeDir)
    inputs.dir(modulesDir)
    inputs.property("packageVersion", packageVersion)
    inputs.property("signIdentity", env("PM_MAC_SIGN_IDENTITY") ?: "")
    outputs.dir(appImageRoot)
    doLast {
        val dest = appImageRoot.get().asFile
        dest.deleteRecursively()
        dest.mkdirs()
        val cmd = mutableListOf(
            tool("jpackage"), "--type", "app-image",
            "--name", "pm", "--app-version", packageVersion,
            "--vendor", "passwordManager project",
            "--description", "Local, offline password manager",
            "--runtime-image", runtimeDir.get().asFile.absolutePath,
            "--module-path", modulesDir.get().asFile.absolutePath,
            "--module", mainModule,
            "--dest", dest.absolutePath,
        )
        // Same flags as the jlink --add-options, one --java-options each, so the launcher config
        // states them too (SR-711).
        cmd += hardeningFlags.flatMap { listOf("--java-options", it) }
        when (hostOs) {
            "windows" -> cmd += "--win-console" // pm is a terminal program
            "macos" -> {
                cmd += listOf("--mac-package-identifier", "pm.cli", "--mac-package-name", "pm")
                // Signing hook (user-only: needs a Developer ID Application certificate in the keychain).
                val identity = env("PM_MAC_SIGN_IDENTITY")
                if (identity != null) {
                    cmd += listOf("--mac-sign", "--mac-signing-key-user-name", identity)
                    env("PM_MAC_KEYCHAIN")?.let { cmd += listOf("--mac-signing-keychain", it) }
                } else {
                    logger.lifecycle("jpackageImage: PM_MAC_SIGN_IDENTITY not set; app-image is ad-hoc signed only (not distributable).")
                }
            }
        }
        runCommand(cmd)
        val launcher = appImageLauncher(appImageDirFor(dest))
        if (hostOs == "windows") {
            val thumb = env("PM_WIN_SIGN_CERT_SHA1")
            if (thumb != null) authenticode(launcher, thumb)
            else logger.lifecycle("jpackageImage: PM_WIN_SIGN_CERT_SHA1 not set; pm.exe is unsigned.")
        }
        if (!launcher.isFile) throw GradleException("jpackageImage: launcher $launcher was not produced")
    }
}

/** Authenticode hook (Windows, user-only: needs a code-signing certificate and signtool on PATH). */
fun authenticode(target: File, thumbprint: String) {
    if (!onPath("signtool.exe")) throw GradleException("PM_WIN_SIGN_CERT_SHA1 is set but signtool.exe is not on PATH")
    runCommand(listOf(
        "signtool.exe", "sign", "/sha1", thumbprint, "/fd", "SHA256",
        "/tr", env("PM_WIN_TIMESTAMP_URL") ?: "http://timestamp.digicert.com", "/td", "SHA256",
        target.absolutePath,
    ))
}

/** Installer types this host can build; each missing tool is reported, never silently skipped. */
fun installerTypes(): List<String> {
    if ((findProperty("pm.installers") as String?) == "false") {
        logger.lifecycle("jpackageInstallers: skipped (-Ppm.installers=false).")
        return emptyList()
    }
    return when (hostOs) {
        "macos" -> listOf("dmg", "pkg")
        "windows" -> if (onPath("candle.exe") && onPath("light.exe")) listOf("msi") else {
            logger.lifecycle("jpackageInstallers: SKIPPED msi: WiX 3 (candle.exe, light.exe) is not on PATH.")
            emptyList()
        }
        else -> buildList {
            if (onPath("dpkg-deb")) add("deb") else logger.lifecycle("jpackageInstallers: SKIPPED deb: dpkg-deb is not on PATH.")
            if (onPath("rpmbuild")) add("rpm") else logger.lifecycle("jpackageInstallers: SKIPPED rpm: rpmbuild is not on PATH.")
        }
    }
}

val jpackageInstallers = tasks.register("jpackageInstallers") {
    group = "distribution"
    description = "Native installers from the app-image: dmg+pkg on macOS, deb/rpm on Linux, msi on Windows (skipped with a message when the tool is missing)."
    dependsOn(jpackageImage)
    doLast {
        val tmp = installerTmp.get().asFile
        val dist = distDir.get().asFile.apply { mkdirs() }
        dist.listFiles()?.filter { it.extension in setOf("dmg", "pkg", "deb", "rpm", "msi") }?.forEach { it.delete() }
        installerTypes().forEach { type ->
            tmp.deleteRecursively()
            tmp.mkdirs()
            val cmd = mutableListOf(
                tool("jpackage"), "--type", type,
                "--app-image", appImageDirFor(appImageRoot.get().asFile).absolutePath,
                "--name", "pm", "--app-version", packageVersion,
                "--vendor", "passwordManager project",
                "--dest", tmp.absolutePath,
            )
            when (hostOs) {
                "macos" -> {
                    cmd += listOf("--mac-package-identifier", "pm.cli")
                    env("PM_MAC_SIGN_IDENTITY")?.let { id ->
                        cmd += listOf("--mac-sign", "--mac-signing-key-user-name", id)
                        env("PM_MAC_KEYCHAIN")?.let { cmd += listOf("--mac-signing-keychain", it) }
                    }
                }
                "windows" -> cmd += listOf("--win-upgrade-uuid", winUpgradeUuid, "--win-menu", "--win-dir-chooser")
                else -> cmd += listOf("--linux-package-name", "pm")
            }
            runCommand(cmd)
            val produced = tmp.listFiles()?.singleOrNull { it.isFile && it.extension == type }
                ?: throw GradleException("jpackageInstallers: no .$type produced in $tmp")
            val target = File(dist, "$distName.$type")
            target.delete()
            if (!produced.renameTo(target)) throw GradleException("jpackageInstallers: cannot move $produced to $target")
            // Post-build signing hooks; each runs only when its env var is set (docs/release/packaging.md).
            if (hostOs == "macos" && type == "dmg") {
                val profile = env("PM_NOTARY_PROFILE")
                if (profile != null) {
                    runCommand(listOf("xcrun", "notarytool", "submit", target.absolutePath, "--keychain-profile", profile, "--wait"))
                    runCommand(listOf("xcrun", "stapler", "staple", target.absolutePath))
                } else {
                    logger.lifecycle("jpackageInstallers: PM_NOTARY_PROFILE not set; $target is not notarized.")
                }
            }
            if (hostOs == "windows") env("PM_WIN_SIGN_CERT_SHA1")?.let { authenticode(target, it) }
            logger.lifecycle("jpackageInstallers: ${target.name}")
        }
        tmp.deleteRecursively()
    }
}

// ---- SBOM and hash manifest -----------------------------------------------------------------

val cyclonedxSbom = tasks.register("cyclonedxSbom") {
    group = "distribution"
    description = "Writes the CycloneDX 1.5 JSON SBOM of the runtime module path to build/release/dist/$sbomName."
    dependsOn("installModules", "jar", jlinkImage)
    inputs.files(runtimeClasspath).withPathSensitivity(PathSensitivity.NAME_ONLY)
    inputs.files(tasks.named("jar")).withPathSensitivity(PathSensitivity.NAME_ONLY)
    inputs.dir(runtimeDir).withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.file(distDir.map { it.file(sbomName) })
    outputs.upToDateWhen { false } // embeds the commit time, which is not a file input
    doLast {
        val out = distDir.get().file(sbomName).asFile
        out.parentFile.mkdirs()
        out.writeText(cyclonedxJson(), Charsets.UTF_8)
    }
}

val sha256Manifest = tasks.register("sha256Manifest") {
    group = "distribution"
    description = "Writes build/release/dist/$manifestName over every release artifact (archives, installers, SBOM)."
    dependsOn(releaseArchives, cyclonedxSbom, jpackageInstallers)
    outputs.upToDateWhen { false }
    doLast {
        val dist = distDir.get().asFile
        val artifacts = releaseArtifacts(dist)
        writeSha256Sums(File(dist, manifestName), artifacts)
        logger.lifecycle(File(dist, manifestName).readText())
    }
}

val verifyReleaseHashes = tasks.register("verifyReleaseHashes") {
    group = "verification"
    description = "Re-hashes build/release/dist against its $manifestName (the same check as `shasum -a 256 -c`)."
    mustRunAfter(sha256Manifest)
    doLast {
        val manifest = distDir.get().file(manifestName).asFile
        if (!manifest.isFile) throw GradleException("verifyReleaseHashes: $manifest does not exist; run sha256Manifest")
        val problems = verifySha256Sums(manifest)
        if (problems.isNotEmpty()) throw GradleException("verifyReleaseHashes: ${problems.joinToString("; ")}")
        logger.lifecycle("verifyReleaseHashes: ${manifest.readLines().size} artifacts OK")
    }
}

// Detached signature over the manifest (any OS; user-only: needs the release key in gpg).
val signManifest = tasks.register("signManifest") {
    group = "distribution"
    description = "Detached armored gpg signature $manifestName.asc when PM_GPG_KEY is set."
    mustRunAfter(sha256Manifest)
    doLast {
        val manifest = distDir.get().file(manifestName).asFile
        val asc = File(manifest.parentFile, "$manifestName.asc")
        asc.delete()
        val key = env("PM_GPG_KEY")
        if (key == null) {
            logger.lifecycle("signManifest: PM_GPG_KEY not set; $manifestName is unsigned.")
        } else {
            runCommand(listOf("gpg", "--batch", "--yes", "--local-user", key, "--armor", "--detach-sign", "--output", asc.absolutePath, manifest.absolutePath))
        }
    }
}

// ---- Smoke and payload checks ---------------------------------------------------------------

/** Runs a launcher with `--help` under a pseudo-terminal (pm refuses to run without one) and checks the usage line. */
fun smokeHelp(launcher: File) {
    val cmd = ptyCommand(listOf(launcher.absolutePath, "--help")) ?: run {
        logger.lifecycle("releaseSmoke: SKIPPED $launcher --help: no pseudo-terminal on Windows; run it by hand in a console.")
        return
    }
    val pb = ProcessBuilder(cmd).redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
    val p = pb.start()
    val out = p.inputStream.bufferedReader().readText()
    val rc = p.waitFor()
    if (rc != 0 || !out.contains("usage: pm")) throw GradleException("releaseSmoke: $launcher --help exited $rc:\n$out")
    logger.lifecycle("releaseSmoke: $launcher --help -> exit 0, usage printed")
}

/** The pseudo-terminal wrapper command for [args] on this host, or null on Windows. */
fun ptyCommand(args: List<String>): List<String>? = when (hostOs) {
    "macos" -> listOf("script", "-q", "/dev/null") + args
    "linux" -> listOf("script", "-qfec", args.joinToString(" ") { "'" + it.replace("'", "'\\''") + "'" }, "/dev/null")
    else -> null
}

/**
 * The jpackage launcher does not clear JVM-option environment variables (the archive launcher
 * does), so pm.cli.Main must refuse to run when one is set (SR-711).
 */
fun smokeEnvRefused(launcher: File) {
    val cmd = ptyCommand(listOf(launcher.absolutePath, "--help")) ?: run {
        logger.lifecycle("releaseSmoke: SKIPPED JVM-option refusal check on Windows; run it by hand.")
        return
    }
    val pb = ProcessBuilder(cmd).redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
    pb.environment()["JAVA_TOOL_OPTIONS"] = "-XX:-DisableAttachMechanism"
    val p = pb.start()
    val out = p.inputStream.bufferedReader().readText()
    val rc = p.waitFor()
    if (rc != 2 || !out.contains("JAVA_TOOL_OPTIONS, _JAVA_OPTIONS or JDK_JAVA_OPTIONS is set") || out.contains("usage: pm")) {
        throw GradleException("releaseSmoke: $launcher ran with JAVA_TOOL_OPTIONS set (exit $rc):\n$out")
    }
    logger.lifecycle("releaseSmoke: $launcher with JAVA_TOOL_OPTIONS set -> refused, exit 2")
}

/**
 * Drives the real TUI under a pseudo-terminal: creates a throwaway vault with a fixed test
 * passphrase, opens the app, and requires that the process is still running and printed no
 * "internal error" [seconds] after the TUI took over the screen. A missing JDK module (for
 * example java.desktop for Lanterna's colours) only fails here, never in `--help`. Only the
 * process tree started here is killed afterwards.
 */
fun smokeTui(label: String, launcher: File, seconds: Long = 30) {
    val work = releaseDir.get().dir("smoke-tui").asFile.apply { deleteRecursively(); mkdirs() }
    val vault = File(work, "smoke.pmv")
    val cmd = ptyCommand(listOf(launcher.absolutePath, "--vault", vault.absolutePath)) ?: run {
        logger.lifecycle("releaseSmoke: SKIPPED $label TUI run on Windows (no pseudo-terminal); run pm by hand.")
        return
    }
    val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
    val out = StringBuffer()
    val reader = Thread {
        runCatching {
            val r = p.inputStream.reader(Charsets.UTF_8)
            val buf = CharArray(4096)
            while (true) {
                val n = r.read(buf)
                if (n < 0) break
                out.append(buf, 0, n)
            }
        }
    }.apply { isDaemon = true; start() }
    val input = p.outputStream
    fun fail(why: String): Nothing = throw GradleException(
        "releaseSmoke: $label TUI $why. Output:\n" + out.toString().replace(Regex("\u001b\\[[0-9;?]*[A-Za-z]"), ""))
    fun await(text: String, timeoutSeconds: Long) {
        val deadline = System.nanoTime() + timeoutSeconds * 1_000_000_000L
        while (!out.contains(text)) {
            if (out.contains("internal error")) fail("printed \"internal error\" before the expected prompt")
            if (!p.isAlive) fail("exited (${p.exitValue()}) before the expected prompt")
            if (System.nanoTime() > deadline) fail("did not reach the expected prompt within ${timeoutSeconds}s")
            Thread.sleep(200)
        }
    }
    fun type(text: String) {
        input.write(text.toByteArray(Charsets.UTF_8))
        input.flush()
    }
    val passphrase = "release smoke passphrase 4417\r" // throwaway vault, deleted below
    try {
        await("New passphrase:", 120)
        type(passphrase)
        await("Repeat passphrase:", 60)
        type(passphrase)
        // Creating the vault tunes and runs Argon2id; allow for a loaded machine.
        await("Press Enter to open pm", 300)
        type("\r")
        await("\u001b[?1049h", 120) // Lanterna switched to the alternate screen: the TUI is up
        val deadline = System.nanoTime() + seconds * 1_000_000_000L
        while (System.nanoTime() < deadline) {
            if (out.contains("internal error")) fail("printed \"internal error\"")
            if (!p.isAlive || p.descendants().noneMatch { it.isAlive }) fail("exited within ${seconds}s of opening")
            Thread.sleep(500)
        }
        logger.lifecycle("releaseSmoke: $label TUI still running ${seconds}s after opening, no internal error")
    } finally {
        p.descendants().forEach { it.destroyForcibly() }
        p.destroyForcibly()
        p.waitFor()
        reader.join(5_000)
        work.deleteRecursively()
    }
}

/**
 * The payload that must be byte-identical between the reproducible image and an app-image or
 * installer: the runtime's class image (lib/modules), its release file, and every application
 * jar. Native executables and libraries are excluded because macOS and Windows code signing
 * rewrites them (plan.md Phase 5: installers are checked by content, not byte-identity).
 */
fun payloadHashes(runtimeHome: File, mods: File): Map<String, String> {
    val m = sortedMapOf<String, String>()
    m["runtime/lib/modules"] = sha256(File(runtimeHome, "lib/modules"))
    m["runtime/release"] = sha256(File(runtimeHome, "release"))
    (mods.listFiles() ?: emptyArray()).filter { it.name.endsWith(".jar") }.forEach { m["app/${it.name}"] = sha256(it) }
    return m
}

fun comparePayload(label: String, expected: Map<String, String>, actual: Map<String, String>) {
    if (expected != actual) {
        val diff = (expected.keys + actual.keys).toSortedSet().filter { expected[it] != actual[it] }
        throw GradleException("releaseSmoke: $label payload differs from the reproducible image: $diff")
    }
    logger.lifecycle("releaseSmoke: $label payload matches the image (${expected.size} files)")
}

val releaseSmoke = tasks.register("releaseSmoke") {
    group = "verification"
    description = "Runs the archive and jpackage launchers (--help, JVM-option refusal, the TUI for 30 s under a pty) and checks app-image/dmg payload hashes against the image."
    dependsOn(distImage, jpackageImage)
    mustRunAfter(jpackageInstallers)
    doLast {
        val image = imageRoot.get().dir(distName).asFile
        val expected = payloadHashes(File(image, "runtime"), File(image, "app"))
        val archiveLauncher = File(image, "bin/" + if (hostOs == "windows") "pm.bat" else "pm")
        smokeHelp(archiveLauncher)
        smokeTui("archive", archiveLauncher)
        val appImage = appImageDirFor(appImageRoot.get().asFile)
        smokeHelp(appImageLauncher(appImage))
        smokeEnvRefused(appImageLauncher(appImage))
        smokeTui("app-image", appImageLauncher(appImage))
        val (rt, mods) = appImagePayload(appImage)
        comparePayload("app-image", expected, payloadHashes(rt, mods))
        val dmg = distDir.get().file("$distName.dmg").asFile
        if (hostOs == "macos" && dmg.isFile) {
            val mount = releaseDir.get().dir("dmg-mount").asFile.apply { deleteRecursively(); mkdirs() }
            runCommand(listOf("hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mount.absolutePath, dmg.absolutePath))
            try {
                val app = File(mount, "pm.app")
                smokeHelp(appImageLauncher(app))
                val (drt, dmods) = appImagePayload(app)
                comparePayload("dmg", expected, payloadHashes(drt, dmods))
            } finally {
                runCommand(listOf("hdiutil", "detach", mount.absolutePath))
            }
        }
    }
}

tasks.register("release") {
    group = "distribution"
    description = "Full local release for this OS: archives, app-image, installers, SBOM, $manifestName, signing hooks, smoke checks."
    dependsOn(releaseArchives, jpackageInstallers, cyclonedxSbom, sha256Manifest, signManifest, verifyReleaseHashes, releaseSmoke)
}

// ---- Fast check wired into `check` ----------------------------------------------------------

// Functional test of the SBOM and manifest writers (T-PKG-02/T-PKG-03). Needs only jlinkImage
// (a few seconds, part of every JDK 21 with jmods; it also runs the T-PKG-01 self-check), no
// jpackage or platform tools: generates the SBOM, parses it back, recomputes every hash, writes a manifest
// over a scratch copy, verifies it, then corrupts a file and a line and expects both caught.
val releaseMetadataCheck = tasks.register("releaseMetadataCheck") {
    group = "verification"
    description = "Checks that cyclonedxSbom and the SHA256SUMS writer/verifier produce well-formed, correct output."
    dependsOn("installModules", "jar", jlinkImage)
    val marker = layout.buildDirectory.file("release-check/passed")
    outputs.file(marker)
    outputs.upToDateWhen { false }
    doLast {
        fun require(cond: Boolean, msg: String) { if (!cond) throw GradleException("releaseMetadataCheck: $msg") }
        val json = cyclonedxJson()
        require(json == cyclonedxJson(), "SBOM generation is not deterministic")
        @Suppress("UNCHECKED_CAST")
        val bom = JsonSlurper().parseText(json) as Map<String, Any?>
        require(bom["bomFormat"] == "CycloneDX", "bomFormat")
        require(bom["specVersion"] == "1.5", "specVersion")
        require(bom["version"] == 1, "version")
        require(Regex("^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").matches(bom["serialNumber"] as String), "serialNumber")
        @Suppress("UNCHECKED_CAST")
        val meta = bom["metadata"] as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val app = meta["component"] as Map<String, Any?>
        require(app["name"] == "pm-cli" && app["purl"] == purl("pm", "pm-cli", pmVersion), "metadata.component")
        @Suppress("UNCHECKED_CAST")
        val comps = bom["components"] as List<Map<String, Any?>>
        val libs = comps.filter { it["type"] == "library" }
        val purlRe = Regex("^pkg:maven/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+@[A-Za-z0-9._+-]+\\?type=jar$")
        val jarFiles = runtimeClasspath.get().files.associateBy { it.name }
        require(libs.size == jarFiles.size, "expected ${jarFiles.size} library components, found ${libs.size}")
        libs.forEach { c ->
            require(purlRe.matches(c["purl"] as String), "bad purl ${c["purl"]}")
            require(c["bom-ref"] == c["purl"], "bom-ref != purl for ${c["name"]}")
            require(c["version"] is String && (c["version"] as String).isNotEmpty(), "version of ${c["name"]}")
            @Suppress("UNCHECKED_CAST")
            val hashes = c["hashes"] as List<Map<String, String>>
            @Suppress("UNCHECKED_CAST")
            val fileName = (c["properties"] as List<Map<String, String>>).single { it["name"] == "pm:file" }["value"]
            val jar = jarFiles[fileName] ?: throw GradleException("releaseMetadataCheck: ${c["name"]} names unknown file $fileName")
            require(hashes.single()["alg"] == "SHA-256" && hashes.single()["content"] == sha256(jar), "hash of $fileName")
        }
        listOf("org.bouncycastle" to "bcprov-jdk18on", "com.googlecode.lanterna" to "lanterna", "pm" to "pm-crypto")
            .forEach { (g, n) -> require(libs.any { it["group"] == g && it["name"] == n }, "missing component $g:$n") }
        val platform = comps.single { it["type"] == "platform" }
        require(platform["version"] == jdkVersion.get(), "platform component version")
        @Suppress("UNCHECKED_CAST")
        val platformHash = (platform["hashes"] as List<Map<String, String>>).single()
        require(platformHash["alg"] == "SHA-256" && platformHash["content"] == sha256(runtimeDir.get().file("lib/modules").asFile),
            "platform component hash is not the SHA-256 of runtime/lib/modules")
        @Suppress("UNCHECKED_CAST")
        val linkedModules = (platform["properties"] as List<Map<String, String>>).single { it["name"] == "pm:jlink:modules" }["value"]!!.split(',')
        listOf("java.base", "java.desktop", "jdk.crypto.ec", "jdk.unsupported")
            .forEach { require(it in linkedModules, "runtime module list lacks $it") }
        val refs = comps.map { it["bom-ref"] }.toSet() + app["bom-ref"]
        @Suppress("UNCHECKED_CAST")
        val deps = bom["dependencies"] as List<Map<String, Any?>>
        require(deps.any { it["ref"] == app["bom-ref"] }, "no dependency entry for the application")
        deps.forEach { d ->
            require(d["ref"] in refs, "dependency ref ${d["ref"]} is not a component")
            @Suppress("UNCHECKED_CAST")
            (d["dependsOn"] as List<String>).forEach { require(it in refs, "dependsOn $it is not a component") }
        }

        // Manifest writer and verifier on a scratch copy.
        val scratch = layout.buildDirectory.dir("release-check/dist").get().asFile.apply { deleteRecursively(); mkdirs() }
        File(scratch, sbomName).writeText(json, Charsets.UTF_8)
        jarFiles.values.forEach { it.copyTo(File(scratch, it.name)) }
        val manifest = File(scratch, manifestName)
        writeSha256Sums(manifest, releaseArtifacts(scratch))
        val lines = manifest.readLines()
        require(lines.size == jarFiles.size + 1, "manifest line count")
        require(lines == lines.sortedBy { it.substring(66) }, "manifest is not sorted by name")
        require(lines.all { manifestLine.matches(it) }, "manifest line format")
        require(verifySha256Sums(manifest).isEmpty(), "fresh manifest does not verify: ${verifySha256Sums(manifest)}")
        val victim = File(scratch, sbomName)
        victim.appendText(" ")
        require(verifySha256Sums(manifest) == listOf("$sbomName: SHA-256 mismatch"), "tampered file not detected")
        victim.writeText(json, Charsets.UTF_8)
        manifest.appendText("not a manifest line\n")
        require(verifySha256Sums(manifest).singleOrNull()?.endsWith("is malformed") == true, "malformed line not detected")
        manifest.writeText(lines.joinToString("\n", postfix = "\n") + "0".repeat(64) + "  ../escape\n")
        require(verifySha256Sums(manifest).singleOrNull()?.endsWith("is malformed") == true, "path traversal name accepted")
        marker.get().asFile.apply { parentFile.mkdirs(); writeText("ok\n") }
        logger.lifecycle("releaseMetadataCheck: SBOM ${libs.size} libraries + runtime platform; manifest writer/verifier OK")
    }
}
tasks.named("check") { dependsOn(releaseMetadataCheck) }
