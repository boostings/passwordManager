package pm.arch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Constant-time comparison rules (SR-016, M1 exit criterion "tags compared with
 * MessageDigest.isEqual"). Structural complement to the Semgrep rule
 * {@code cert.CT-compare.non-constant-time}, which only catches suspicious variable names.
 */
@AnalyzeClasses(packages = "pm", importOptions = ImportOption.DoNotIncludeTests.class)
final class ConstantTimeTest {

    /** SR-016 / MSC61-J: short-circuiting array equality leaks timing on byte-array secrets. */
    @ArchTest
    static final ArchRule noArraysEqualsOnBytes =
            noClasses().that().resideInAPackage("pm..")
                    .should().callMethod(Arrays.class, "equals", byte[].class, byte[].class)
                    .because("SR-016: compare byte arrays with MessageDigest.isEqual, not Arrays.equals");

    /** SR-016 / MSC61-J: same for char-array secrets (passphrases, ADR 0008). */
    @ArchTest
    static final ArchRule noArraysEqualsOnChars =
            noClasses().that().resideInAPackage("pm..")
                    .should().callMethod(Arrays.class, "equals", char[].class, char[].class)
                    .because("SR-016: char[] secrets must not be compared with short-circuiting Arrays.equals");

    /** SR-016 / SR-017 / MSC02-J: constant-time comparison is a pm-crypto service (defense in depth). */
    @ArchTest
    static final ArchRule onlyCryptoCallsIsEqual =
            noClasses().that().resideOutsideOfPackage("pm.crypto..")
                    .should().callMethod(MessageDigest.class, "isEqual", byte[].class, byte[].class)
                    .because("SR-016/SR-017: secret comparison goes through pm-crypto APIs");
}
