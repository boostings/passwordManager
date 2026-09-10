rootProject.name = "passwordManager"

pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral() }
}
dependencyResolutionManagement {
    repositories { mavenCentral() }
}

listOf(
    "pm-crypto", "pm-vault", "pm-storage", "pm-approval", "pm-sharing", "pm-browser",
    "pm-platform-macos", "pm-platform-windows", "pm-platform-linux",
    "pm-domain", "pm-tui", "pm-cli", "pm-arch-tests", "pm-fuzz",
).forEach { include(":modules:$it") }
