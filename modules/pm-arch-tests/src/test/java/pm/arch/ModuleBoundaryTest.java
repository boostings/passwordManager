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

    /**
     * SR-060 / ADR 0013, plan.md §13 M4: SSH private keys are parsed, sent to the agent and exported
     * only in pm.crypto.ssh, and only the CLI drives it. The TUI and every other module never reach it.
     */
    @ArchTest
    static final ArchRule onlyTheCliReachesSshKeys =
            noClasses().that().resideOutsideOfPackages("pm.crypto..", "pm.cli..", "pm.arch..")
                    .should().dependOnClassesThat().resideInAPackage("pm.crypto.ssh..")
                    .because("SR-060: only pm.cli may use the ssh-agent client and key export (ADR 0013)");

    /**
     * SR-060 / ADR 0013: no facade in pm.crypto re-exports SSH key handling to other modules. With
     * {@code exports pm.crypto.ssh to pm.cli}, the compiler already stops every other module,
     * including uses of inlined constants that bytecode rules cannot see.
     */
    @ArchTest
    static final ArchRule noCryptoFacadeOverSshKeys =
            noClasses().that().resideInAPackage("pm.crypto..")
                    .and().resideOutsideOfPackage("pm.crypto.ssh..")
                    .should().dependOnClassesThat().resideInAPackage("pm.crypto.ssh..")
                    .because("SR-060: pm.crypto.ssh is reachable only from pm.cli, not through another pm.crypto package");

    /**
     * SR-402 / SR-080 / ADR 0016, plan.md §13 M6: passkey keys are generated and used for signing
     * only inside pm.crypto.passkey, and only the vault, the domain and the browser bridge reach it.
     * Mirrors {@code exports pm.crypto.passkey to pm.vault, pm.domain, pm.browser}.
     */
    @ArchTest
    static final ArchRule onlyVaultDomainAndBrowserReachPasskeys =
            noClasses().that().resideOutsideOfPackages(
                            "pm.crypto..", "pm.vault..", "pm.domain..", "pm.browser..", "pm.arch..")
                    .should().dependOnClassesThat().resideInAPackage("pm.crypto.passkey..")
                    .because("SR-402: passkey keys are reachable only from pm.vault, pm.domain and pm.browser (ADR 0016)");

    /**
     * SR-080 / ADR 0016: the passkey storage form, the only way the private scalar leaves pm-crypto,
     * is reachable from the vault alone; the browser and domain modules sign but cannot extract.
     * Mirrors {@code exports pm.crypto.passkey.storage to pm.vault}.
     */
    @ArchTest
    static final ArchRule onlyTheVaultReachesPasskeyStorage =
            noClasses().that().resideOutsideOfPackages("pm.crypto.passkey..", "pm.vault..", "pm.arch..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "pm.crypto.passkey.storage..", "pm.crypto.passkey.internal..")
                    .because("SR-080: only pm.vault may read or load the passkey storage form (ADR 0016)");

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
