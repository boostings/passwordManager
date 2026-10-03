package pm.arch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

/**
 * Structural rules from plan.md Part III, enforced on every build. Each rule cites the
 * security requirement (SR) and CERT rule it implements.
 */
@AnalyzeClasses(packages = "pm", importOptions = ImportOption.DoNotIncludeTests.class)
final class ModuleBoundaryTest {

    /** SR-017 / MSC02-J: cryptographic JCA APIs stay in pm-crypto; Principal supports file ACLs. */
    @ArchTest
    static final ArchRule onlyCryptoUsesJca =
            noClasses().that().resideOutsideOfPackages("pm.crypto..", "pm.arch..")
                    .should().dependOnClassesThat().haveNameMatching(
                            "javax\\.crypto\\..*|java\\.security\\.(?!Principal$).*")
                    .because("SR-017: cryptographic javax.crypto / java.security APIs stay in pm-crypto");

    /** SR-507 / SER12-J: no Java native serialization anywhere. */
    @ArchTest
    static final ArchRule noNativeSerialization =
            noClasses().should().dependOnClassesThat().haveNameMatching(
                            "java\\.io\\.Object(Input|Output)Stream")
                    .because("SER12-J: native serialization is banned (ADR 0006)");

    /** ADR 0002: SecurityManager and AccessController are superseded. */
    @ArchTest
    static final ArchRule noSecurityManager =
            noClasses().should().dependOnClassesThat().haveNameMatching(
                            "java\\.lang\\.SecurityManager|java\\.security\\.AccessController")
                    .because("ADR 0002: superseded by JPMS + these tests");

    /** Any {@code Runtime.exec(..)} overload. */
    private static final DescribedPredicate<JavaMethodCall> RUNTIME_EXEC =
            DescribedPredicate.describe("Runtime.exec(..)", call ->
                    call.getTargetOwner().isEquivalentTo(Runtime.class) && "exec".equals(call.getName()));

    /**
     * SR-100 / IDS07-J, plan.md §13 M2: the only class that spawns or inspects processes is the env
     * runner, which starts the approved argv with no shell (approval-model §6), plus the platform
     * adapters. Targets the process APIs themselves ({@code Runtime.exec(..)}, {@code ProcessBuilder},
     * {@code ProcessHandle}), not all of {@code java.lang.Runtime}: heap figures such as
     * {@code Runtime.maxMemory()} spawn nothing. Narrowed at M2.7 from "anything in pm-approval".
     */
    @ArchTest
    static final ArchRule onlyTheEnvRunnerSpawnsProcesses =
            noClasses().that().resideOutsideOfPackage("pm.platform..")
                    .and().haveNameNotMatching("pm\\.approval\\.run\\.EnvRunner(\\$.*)?")
                    .should().callMethodWhere(RUNTIME_EXEC)
                    .orShould().dependOnClassesThat().haveNameMatching(
                            "java\\.lang\\.(ProcessBuilder|ProcessHandle)(\\$.*)?")
                    .because("SR-100/SR-102: only pm.approval.run.EnvRunner runs the approved argv");

    /** Tier 1 modules never depend on TUI, CLI or platform modules. */
    @ArchTest
    static final ArchRule tier1DoesNotDependOnUpperLayers =
            noClasses().that().resideInAnyPackage(
                            "pm.crypto..", "pm.vault..", "pm.storage..", "pm.approval..", "pm.sharing..", "pm.browser..")
                    .should().dependOnClassesThat().resideInAnyPackage("pm.tui..", "pm.cli..", "pm.platform..")
                    .because("plan.md §10: Tier 1 is independent of presentation and platform layers");

    /** pm-crypto depends on nothing else in the project. */
    @ArchTest
    static final ArchRule cryptoIsLeaf =
            noClasses().that().resideInAPackage("pm.crypto..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "pm.vault..", "pm.storage..", "pm.approval..", "pm.sharing..", "pm.browser..",
                            "pm.domain..", "pm.tui..", "pm.cli..", "pm.platform..")
                    .because("plan.md §10: pm-crypto is sealed and leaf");

    /** SR-506 / THI01-J, THI05-J. */
    @ArchTest
    static final ArchRule noThreadGroup =
            noClasses().should().dependOnClassesThat().haveFullyQualifiedName("java.lang.ThreadGroup")
                    .because("THI01-J");

    /** Not-applicable CERT families are guarded: no SQL, XML, servlets (IDS00/16/17-J, FIO15-J, MSC08/11-J). */
    @ArchTest
    static final ArchRule noSqlXmlOrServlets =
            noClasses().should().dependOnClassesThat().resideInAnyPackage(
                            "java.sql..", "javax.sql..", "javax.xml..", "org.w3c.dom..", "org.xml.sax..",
                            "jakarta.servlet..", "javax.servlet..")
                    .because("cert-applicability.md: these families are Not applicable and must stay so");

    /** SEC03-J, SEC07-J: no custom class loaders or dynamic loading. */
    @ArchTest
    static final ArchRule noClassLoaders =
            noClasses().should().beAssignableTo(ClassLoader.class)
                    .orShould().dependOnClassesThat().haveNameMatching("java\\.net\\.URLClassLoader")
                    .because("cert-applicability.md: no dynamic class loading");

    /** JNI00-J..JNI04-J: no native methods in v1. */
    @ArchTest
    static final ArchRule noNativeMethods =
            noMethods().should().haveModifier(JavaModifier.NATIVE)
                    .because("cert-applicability.md: JNI family is Not applicable in v1");
}
