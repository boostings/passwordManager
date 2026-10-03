package pm.arch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * M1 exit criterion "KDF always completes; tags compared with {@code MessageDigest.isEqual}"
 * (team sprint plan section 7, Lane A Phase 3). SR-016, MSC61-J.
 *
 * <p><b>Constant-time half (this class).</b> A source-level review over every
 * {@code modules/*}{@code /src/main/java} file, after comments and string literals are blanked:
 * <ul>
 *   <li>no {@code Arrays.equals(..)} or {@code Arrays.mismatch(..)} whose arguments name a key,
 *       tag, MAC, secret, digest, hash, code or token outside {@code pm.crypto} (mirrors the
 *       Semgrep rule {@code cert.CT-compare.non-constant-time} in
 *       {@code tools/cert-rules/semgrep/cert-java.yml}, and widens it to {@code mismatch});</li>
 *   <li>no {@code .equals(..)} whose receiver or arguments name a key, tag, MAC, secret, digest
 *       or hash outside {@code pm.crypto}; such values go through
 *       {@code pm.crypto.ConstantTime.equals};</li>
 *   <li>{@code MessageDigest.isEqual} is referenced only from {@code pm-crypto}'s
 *       {@code pm/crypto} sources, and {@code ConstantTime.java} is one of them.</li>
 * </ul>
 * The scan asserts it read files, including pm-vault's unlock path, so it cannot pass vacuously.
 * The bytecode-level structural rules live in {@link ConstantTimeTest}
 * ({@code noArraysComparisonOnSecretArraysOutsideCrypto},
 * {@code noByteBufferComparisonOutsideCrypto}, {@code onlyCryptoCallsIsEqual}); this class does
 * not repeat them.
 *
 * <p><b>Full-KDF half (proved elsewhere, not duplicated).</b> That a wrong passphrase runs
 * Argon2id exactly once, to completion, with the header's parameters, and fails only afterwards
 * at the AES-KWP unwrap with the same code as a tampered wrap, is proved by
 * {@code pm.vault.slot.SlotCryptoWorkFactorTest} (module pm-vault,
 * {@code modules/pm-vault/src/test/java/pm/vault/slot/SlotCryptoWorkFactorTest.java}), through a
 * counting {@code Stretcher} seam on {@code SlotCrypto.kekFromPassphrase}.
 * {@code VaultService.unlockWithPassphrase} calls that method before any credential-dependent
 * branch: every exit before it (storage read, envelope decode, header range check) depends only
 * on the file, never on the passphrase.
 */
final class ConstantTimeReviewTest {

    private static final String CRYPTO_PKG_DIR = "modules/pm-crypto/src/main/java/pm/crypto/";
    private static final String CONSTANT_TIME = CRYPTO_PKG_DIR + "ConstantTime.java";
    private static final List<String> MUST_SCAN = List.of(
            "modules/pm-vault/src/main/java/pm/vault/VaultService.java",
            "modules/pm-vault/src/main/java/pm/vault/slot/SlotCrypto.java",
            CONSTANT_TIME);
    private static final Set<String> MUST_SCAN_MODULES = Set.of("pm-crypto", "pm-vault", "pm-storage", "pm-cli");

    /** Same word list as the Semgrep rule's {@code $A} regex. */
    private static final Pattern ARRAYS_SECRET_ARG =
            Pattern.compile("(?i).*(tag|mac|key|secret|code|hash|digest|token|sas).*", Pattern.DOTALL);
    /** Receiver or argument names for {@code .equals}: key, tag, MAC, secret, digest, hash. */
    private static final Pattern EQUALS_SECRET_NAME =
            Pattern.compile("(?i).*(key|tag|mac|secret|digest|hash).*", Pattern.DOTALL);

    private static final Pattern ARRAYS_COMPARE =
            Pattern.compile("\\bArrays\\s*\\.\\s*(?:equals|mismatch)\\s*\\(");
    private static final Pattern DOT_EQUALS =
            Pattern.compile("([A-Za-z_$][\\w$]*)\\s*(?:\\(\\s*\\))?\\s*\\.\\s*equals\\s*\\(");
    private static final Pattern IS_EQUAL = Pattern.compile(
            "\\bMessageDigest\\s*\\.\\s*isEqual\\b|import\\s+static\\s+java\\.security\\.MessageDigest\\b");

    private static final String RECEIVER_ARRAYS = "Arrays";
    private static final String LINE_COMMENT = "//";
    private static final String BLOCK_COMMENT_OPEN = "/*";
    private static final String BLOCK_COMMENT_CLOSE = "*/";
    private static final String TEXT_BLOCK = "\"\"\"";
    private static final char OPEN = '(';
    private static final char CLOSE = ')';
    private static final char NEWLINE = '\n';
    private static final char BACKSLASH = '\\';
    private static final char DOUBLE_QUOTE = '"';
    private static final char SINGLE_QUOTE = '\'';
    private static final char SPACE = ' ';

    private static Path repoRoot;
    private static List<Path> sources;

    @BeforeAll
    static void scan() throws IOException {
        repoRoot = findRepoRoot(Path.of("").toAbsolutePath());
        sources = new ArrayList<>();
        try (Stream<Path> modules = Files.list(repoRoot.resolve("modules"))) {
            for (Path module : modules.sorted().toList()) {
                Path main = module.resolve("src/main/java");
                if (!Files.isDirectory(main)) {
                    continue;
                }
                try (Stream<Path> files = Files.walk(main)) {
                    files.filter(p -> p.toString().endsWith(".java")).sorted().forEach(sources::add);
                }
            }
        }
    }

    @Test
    void scanIsNotVacuous() {
        assertTrue(sources.size() > MUST_SCAN.size(), () -> "files scanned: " + sources.size());
        Set<String> scanned = new TreeSet<>();
        Set<String> modules = new TreeSet<>();
        for (Path p : sources) {
            scanned.add(rel(p));
            modules.add(repoRoot.relativize(p).getName(1).toString());
        }
        for (String required : MUST_SCAN) {
            assertTrue(scanned.contains(required), () -> "not scanned: " + required);
        }
        assertTrue(modules.containsAll(MUST_SCAN_MODULES), () -> "modules scanned: " + modules);
    }

    @Test
    void noShortCircuitCompareOfSecretsOutsideCrypto() {
        List<String> findings = new ArrayList<>();
        for (Path p : sources) {
            String rel = rel(p);
            if (!rel.startsWith(CRYPTO_PKG_DIR)) {
                findings.addAll(findShortCircuitCompares(rel, read(p)));
            }
        }
        assertEquals(List.of(), findings,
                "SR-016: compare keys/tags/MACs/digests with pm.crypto.ConstantTime.equals; scanned "
                        + sources.size() + " files");
    }

    @Test
    void messageDigestIsEqualOnlyInsidePmCrypto() {
        Set<String> users = new TreeSet<>();
        for (Path p : sources) {
            if (IS_EQUAL.matcher(blankCommentsAndLiterals(read(p))).find()) {
                users.add(rel(p));
            }
        }
        assertTrue(users.contains(CONSTANT_TIME), () -> "ConstantTime must use MessageDigest.isEqual: " + users);
        List<String> outside = users.stream().filter(u -> !u.startsWith(CRYPTO_PKG_DIR)).toList();
        assertEquals(List.of(), outside, "SR-016/SR-017: MessageDigest.isEqual is pm-crypto only");
    }

    /** The detector itself: a planted tag compare is found; the same text in a comment or literal is not. */
    @Test
    void detectorFindsPlantedCompareAndIgnoresCommentsAndLiterals() {
        String planted = """
                class X {
                  boolean a(byte[] tag, byte[] other) { return java.util.Arrays.equals(tag, other); }
                  int b(byte[] macBytes, byte[] o) { return Arrays.mismatch(o, macBytes); }
                  boolean c(Object wrappedKey, Object o) { return wrappedKey.equals(o); }
                  boolean d(Object o, Object digest) { return o.equals(digest); }
                  boolean e(Object o) { return keyOf().equals(o); }
                }
                """;
        assertEquals(List.of(
                "X.java:2: Arrays.equals/mismatch(tag, other)",
                "X.java:3: Arrays.equals/mismatch(o, macBytes)",
                "X.java:4: wrappedKey.equals(o)",
                "X.java:5: o.equals(digest)",
                "X.java:6: keyOf.equals(o)"), findShortCircuitCompares("X.java", planted));

        String inert = """
                class Y {
                  // Arrays.equals(tag, other)
                  /* key.equals(tag) */
                  String s = "Arrays.equals(tag, other) and MessageDigest.isEqual(a, b)";
                  String e = "escaped \\" key.equals(tag)";
                  char q = '"';
                  String t = \"""
                      key.equals(tag)
                      \""";
                  boolean ok(String name, Object o) { return name.equals(o); }
                }
                """;
        assertEquals(List.of(), findShortCircuitCompares("Y.java", inert));
        assertFalse(IS_EQUAL.matcher(blankCommentsAndLiterals(inert)).find(), "isEqual inside a literal is ignored");
    }

    /** Returns {@code file:line: description} for each short-circuiting compare on a secret name. */
    static List<String> findShortCircuitCompares(String file, String source) {
        String code = blankCommentsAndLiterals(source);
        List<String> out = new ArrayList<>();
        Matcher arrays = ARRAYS_COMPARE.matcher(code);
        while (arrays.find()) {
            String args = argsFrom(code, arrays.end());
            if (ARRAYS_SECRET_ARG.matcher(args).matches()) {
                out.add(file + ":" + lineOf(code, arrays.start()) + ": Arrays.equals/mismatch(" + args + ")");
            }
        }
        Matcher eq = DOT_EQUALS.matcher(code);
        while (eq.find()) {
            String receiver = eq.group(1);
            if (RECEIVER_ARRAYS.equals(receiver)) {
                continue;
            }
            String args = argsFrom(code, eq.end());
            if (EQUALS_SECRET_NAME.matcher(receiver).matches() || EQUALS_SECRET_NAME.matcher(args).matches()) {
                out.add(file + ":" + lineOf(code, eq.start()) + ": " + receiver + ".equals(" + args + ")");
            }
        }
        out.sort(null);
        return out;
    }

    /** Text from {@code start} up to the parenthesis that closes the call, whitespace collapsed. */
    private static String argsFrom(String code, int start) {
        int depth = 1;
        int i = start;
        while (i < code.length() && depth > 0) {
            char c = code.charAt(i);
            if (c == OPEN) {
                depth++;
            } else if (c == CLOSE) {
                depth--;
            }
            i++;
        }
        return code.substring(start, Math.max(start, i - 1)).replaceAll("\\s+", " ").trim();
    }

    private static int lineOf(String code, int index) {
        int line = 1;
        for (int i = 0; i < index; i++) {
            if (code.charAt(i) == NEWLINE) {
                line++;
            }
        }
        return line;
    }

    /**
     * Replaces comment text and string, text-block and char literal contents with spaces, keeping
     * newlines so line numbers survive. Not a full lexer, but exact for well-formed Java.
     */
    static String blankCommentsAndLiterals(String src) {
        StringBuilder sb = new StringBuilder(src.length());
        int n = src.length();
        int i = 0;
        while (i < n) {
            char c = src.charAt(i);
            if (src.startsWith(LINE_COMMENT, i)) {
                int end = src.indexOf(NEWLINE, i);
                i = blank(src, i, end < 0 ? n : end, sb);
            } else if (src.startsWith(BLOCK_COMMENT_OPEN, i)) {
                int end = src.indexOf(BLOCK_COMMENT_CLOSE, i + BLOCK_COMMENT_OPEN.length());
                i = blank(src, i, end < 0 ? n : end + BLOCK_COMMENT_CLOSE.length(), sb);
            } else if (src.startsWith(TEXT_BLOCK, i)) {
                i = blank(src, i, closingTextBlock(src, i + TEXT_BLOCK.length()), sb);
            } else if (c == DOUBLE_QUOTE || c == SINGLE_QUOTE) {
                i = blank(src, i, closingQuote(src, i + 1, c), sb);
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }

    private static int closingTextBlock(String src, int from) {
        int i = from;
        while (i < src.length()) {
            if (src.charAt(i) == BACKSLASH) {
                i += 2;
            } else if (src.startsWith(TEXT_BLOCK, i)) {
                return i + TEXT_BLOCK.length();
            } else {
                i++;
            }
        }
        return src.length();
    }

    private static int closingQuote(String src, int from, char quote) {
        int i = from;
        while (i < src.length()) {
            char c = src.charAt(i);
            if (c == BACKSLASH) {
                i += 2;
            } else if (c == quote || c == NEWLINE) {
                return i + 1;
            } else {
                i++;
            }
        }
        return src.length();
    }

    private static int blank(String src, int from, int to, StringBuilder sb) {
        int stop = Math.min(to, src.length());
        for (int j = from; j < stop; j++) {
            sb.append(src.charAt(j) == NEWLINE ? NEWLINE : SPACE);
        }
        return stop;
    }

    private static Path findRepoRoot(Path start) {
        for (Path p = start; p != null; p = p.getParent()) {
            if (Files.isRegularFile(p.resolve("settings.gradle.kts")) && Files.isDirectory(p.resolve("modules"))) {
                return p;
            }
        }
        throw new IllegalStateException("repo root not found above " + start);
    }

    private static String rel(Path p) {
        return repoRoot.relativize(p).toString().replace('\\', '/');
    }

    private static String read(Path p) {
        try {
            return Files.readString(p, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
