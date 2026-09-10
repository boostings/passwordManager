// Architecture tests enforcing module tiers and CERT structural rules (SR-017, SR-100, SR-506, SR-507).
dependencies {
    testImplementation("com.tngtech.archunit:archunit-junit5:1.4.1")
    rootProject.subprojects.filter { it.name.startsWith("pm-") && it.name != "pm-arch-tests" && it.name != "pm-fuzz" }
        .forEach { testImplementation(project(it.path)) }
}
