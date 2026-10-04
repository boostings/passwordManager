package pm.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pm.crypto.SecretBytes;
import pm.storage.VaultFileStore;
import pm.vault.record.PasskeyRecord;

/**
 * Compile-time proof that a module outside {@code pm.vault} cannot reach a passkey's key or
 * counter (M6.2 review fix, ADR 0016 addendum, SR-085, SR-086). Each case compiles a small
 * {@code module evil { requires pm.vault; }} against the real module jars of pm.vault, pm.crypto
 * and pm.storage, as the adversarial review's proof did, and checks javac refuses it for the
 * expected reason. A control that uses only the public codec compiles, so the setup is sound.
 */
@Tag("T-PK-02")
final class PasskeyOutsideModuleTest {
    private static final String NOT_PUBLIC = "compiler.err.not.def.public.cant.access";
    private static final String NOT_EXPORTED = "compiler.err.package.not.visible";
    private static final String HEADER = """
            package evil;
            import java.util.List;
            import pm.crypto.SecretBytes;
            import pm.vault.record.*;
            final class Main {
                static Object run() throws Exception {
            """;
    private static final String FOOTER = """

                }
            }
            """;

    @TempDir
    Path dir;

    @Test
    void theControlUsingOnlyThePublicCodecCompiles() throws IOException, URISyntaxException {
        assertEquals(Set.of(), errors("return RecordCodec.encodePayload(List.of());"));
    }

    @ParameterizedTest
    @MethodSource("attacks")
    void javacRefusesEveryWayIntoTheKeyOrCounter(String body, String expected) throws IOException, URISyntaxException {
        Set<String> codes = errors(body);
        assertFalse(codes.isEmpty(), body);
        assertTrue(codes.contains(expected), codes + " for " + body);
    }

    static List<Arguments> attacks() {
        return List.of(
                // The review's proof built a record with a chosen key and counter.
                Arguments.of(
                        "return new PasskeyRecord(java.util.UUID.randomUUID(), \"t\", \"example.com\", new byte[16],"
                                + " new byte[1], \"a\", \"b\", SecretBytes.copyOf(new byte[98]), 41,"
                                + " java.time.Instant.EPOCH, java.time.Instant.EPOCH, java.time.Instant.EPOCH);",
                        NOT_PUBLIC),
                Arguments.of(
                        "return RecordCodec.encodeVaultPayload(List.of());", NOT_PUBLIC),
                Arguments.of(
                        "return RecordCodec.decodeVaultPayload(SecretBytes.copyOf(new byte[1]));", NOT_PUBLIC),
                Arguments.of(
                        "return pm.vault.internal.PasskeyRecordAccess.hook();", NOT_EXPORTED),
                Arguments.of(
                        "return pm.crypto.passkey.storage.PasskeyStorage.class;", NOT_EXPORTED));
    }

    /** The javac error codes for {@code body} inside a method of a module that requires pm.vault. */
    private Set<String> errors(String body) throws IOException, URISyntaxException {
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        assertNotNull(javac, "a JDK compiler");
        Path src = Files.createDirectories(dir.resolve("src/evil"));
        Files.writeString(dir.resolve("src/module-info.java"), "module evil { requires pm.vault; }\n",
                StandardCharsets.UTF_8);
        Path main = src.resolve("Main.java");
        Files.writeString(main, HEADER + body + FOOTER, StandardCharsets.UTF_8);
        Path out = Files.createDirectories(dir.resolve("out"));
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager files = javac.getStandardFileManager(diagnostics, Locale.ROOT,
                StandardCharsets.UTF_8)) {
            List<String> options = List.of("--module-path", modulePath(), "-d", out.toString(),
                    "-proc:none", "-implicit:none");
            javac.getTask(null, files, diagnostics, options, null,
                    files.getJavaFileObjects(dir.resolve("src/module-info.java"), main)).call();
        }
        return diagnostics.getDiagnostics().stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
                .map(Diagnostic::getCode).collect(Collectors.toSet());
    }

    /** The class directories or jars of the real modules: pm.vault, pm.crypto, pm.storage, Bouncy Castle. */
    private static String modulePath() throws URISyntaxException {
        StringBuilder path = new StringBuilder();
        Class<?> bouncyCastle;
        try {
            bouncyCastle = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
        } catch (ClassNotFoundException e) {
            throw new AssertionError(e);
        }
        for (Class<?> c : List.of(PasskeyRecord.class, SecretBytes.class, VaultFileStore.class, bouncyCastle)) {
            if (!path.isEmpty()) {
                path.append(java.io.File.pathSeparatorChar);
            }
            path.append(Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI()));
        }
        return path.toString();
    }
}
