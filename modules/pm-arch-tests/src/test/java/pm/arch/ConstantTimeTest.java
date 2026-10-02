package pm.arch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

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

    private static final Set<String> ARRAY_COMPARISONS = Set.of("equals", "mismatch", "compare", "compareUnsigned");
    private static final Set<String> BUFFER_COMPARISONS = Set.of("equals", "compareTo", "mismatch");

    /**
     * Every {@code Arrays.equals}, {@code mismatch}, {@code compare} and {@code compareUnsigned}
     * overload whose first parameter is {@code byte[]} or {@code char[]}, including the
     * {@code (a, aFrom, aTo, b, bFrom, bTo)} range forms.
     */
    private static final DescribedPredicate<JavaMethodCall> ARRAYS_COMPARE_ON_SECRET_ARRAYS =
            DescribedPredicate.describe("Arrays.equals/mismatch/compare(..) on byte[] or char[]", call -> {
                List<JavaClass> params = call.getTarget().getRawParameterTypes();
                return call.getTargetOwner().isEquivalentTo(Arrays.class)
                        && ARRAY_COMPARISONS.contains(call.getName())
                        && !params.isEmpty()
                        && (params.get(0).isEquivalentTo(byte[].class) || params.get(0).isEquivalentTo(char[].class));
            });

    /** {@code ByteBuffer.equals}, {@code compareTo} and {@code mismatch}, on any ByteBuffer subtype. */
    private static final DescribedPredicate<JavaMethodCall> BYTE_BUFFER_COMPARE =
            DescribedPredicate.describe("ByteBuffer.equals/compareTo/mismatch(..)", call ->
                    call.getTargetOwner().isAssignableTo(ByteBuffer.class)
                            && BUFFER_COMPARISONS.contains(call.getName()));

    /**
     * SR-016 / MSC61-J: the range overloads of {@code Arrays.equals} and the {@code mismatch} /
     * {@code compare} families short-circuit too; outside pm-crypto use
     * {@code pm.crypto.ConstantTime.equals}.
     */
    @ArchTest
    static final ArchRule noArraysComparisonOnSecretArraysOutsideCrypto =
            noClasses().that().resideInAPackage("pm..").and().resideOutsideOfPackage("pm.crypto..")
                    .should().callMethodWhere(ARRAYS_COMPARE_ON_SECRET_ARRAYS)
                    .because("SR-016: compare byte[]/char[] with pm.crypto.ConstantTime.equals");

    /** SR-016 / MSC61-J: ByteBuffer comparisons short-circuit at the first differing byte. */
    @ArchTest
    static final ArchRule noByteBufferComparisonOutsideCrypto =
            noClasses().that().resideInAPackage("pm..").and().resideOutsideOfPackage("pm.crypto..")
                    .should().callMethodWhere(BYTE_BUFFER_COMPARE)
                    .because("SR-016: ByteBuffer.equals/compareTo/mismatch are not constant-time");

    /** SR-016 / SR-017 / MSC02-J: constant-time comparison is a pm-crypto service (defense in depth). */
    @ArchTest
    static final ArchRule onlyCryptoCallsIsEqual =
            noClasses().that().resideOutsideOfPackage("pm.crypto..")
                    .should().callMethod(MessageDigest.class, "isEqual", byte[].class, byte[].class)
                    .because("SR-016/SR-017: secret comparison goes through pm-crypto APIs");
}
