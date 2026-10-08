package pm.browser.host;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Only exactly allowlisted extension origins may talk to the host (SR-301). */
@Tag("T-EXT-02")
class ExtensionAllowlistTest {
    static final String ID = "abcdefghijklmnopabcdefghijklmnop";
    static final String OTHER = "ponmlkjihgfedcbaponmlkjihgfedcba";
    static final String ORIGIN = "chrome-extension://" + ID + "/";

    private final ExtensionAllowlist allow = ExtensionAllowlist.of(List.of(ID));

    @Test
    void anAllowlistedOriginIsAccepted() {
        assertEquals(Optional.of(ID), allow.caller(List.of(ORIGIN)));
        assertEquals(Optional.of(ID), allow.caller(List.of(ORIGIN, "--parent-window=123456")));
    }

    @Test
    void everythingElseIsRefused() {
        for (List<String> args : List.of(
                List.<String>of(),
                List.of("chrome-extension://" + OTHER + "/"),
                List.of("chrome-extension://" + ID.toUpperCase(java.util.Locale.ROOT) + "/"),
                List.of("chrome-extension://" + ID),
                List.of("chrome-extension://" + ID + "/x"),
                List.of("chrome-extension://" + ID + "a/"),
                List.of("moz-extension://" + ID + "/"),
                List.of("https://" + ID + "/"),
                List.of(" " + ORIGIN),
                List.of("chrome-extension://"),
                List.of(ORIGIN, "--parent-window=abc"),
                List.of(ORIGIN, "--other"),
                List.of(ORIGIN, "--parent-window=1", "x"))) {
            assertEquals(Optional.empty(), allow.caller(args), args.toString());
        }
        assertEquals(Optional.empty(), ExtensionAllowlist.of(List.of()).caller(List.of(ORIGIN)));
    }

    @Test
    void badIdsCannotBeAllowlisted() {
        for (String bad : List.of("", "abc", ID + "a", ID.replace('a', 'q'), ID.toUpperCase(java.util.Locale.ROOT))) {
            assertEquals("BAD_EXTENSION_ID",
                    assertThrows(IllegalArgumentException.class, () -> ExtensionAllowlist.of(List.of(bad))).getMessage());
        }
    }

    @Test
    void theFileFormatAllowsCommentsAndBlankLines(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("allowlist");
        Files.writeString(file, "# pm extension\n\n  " + ID + "  \n" + OTHER + "\n", StandardCharsets.UTF_8);
        ExtensionAllowlist read = ExtensionAllowlist.read(file);
        assertEquals(Optional.of(ID), read.caller(List.of(ORIGIN)));
        assertEquals(Optional.of(OTHER), read.caller(List.of("chrome-extension://" + OTHER + "/")));

        Files.writeString(file, "not-an-id\n", StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () -> ExtensionAllowlist.read(file));
    }

    @Test
    void linksDirectoriesAndLargeFilesAreRefused(@TempDir Path dir) throws IOException {
        Path real = dir.resolve("real");
        Files.writeString(real, ID + "\n", StandardCharsets.UTF_8);
        Path link = Files.createSymbolicLink(dir.resolve("link"), real);
        Path big = dir.resolve("big");
        Files.writeString(big, "#".repeat(ExtensionAllowlist.MAX_FILE_BYTES + 1), StandardCharsets.UTF_8);
        for (Path p : List.of(link, dir, big)) {
            assertEquals("UNSAFE_ALLOWLIST",
                    assertThrows(IllegalArgumentException.class, () -> ExtensionAllowlist.read(p)).getMessage());
        }
    }

    /** The install glue (ADR 0014 §8): validate, add once, and write the form {@link ExtensionAllowlist#read} takes. */
    @Test
    void installAddsAnIdOnceAndWritesWhatReadAccepts(@TempDir Path dir) throws IOException {
        assertEquals(true, ExtensionAllowlist.isValidId(ID));
        for (String bad : new String[] {null, "", ID.toUpperCase(java.util.Locale.ROOT), ID + "a", "q" + ID.substring(1)}) {
            assertEquals(false, ExtensionAllowlist.isValidId(bad), String.valueOf(bad));
        }
        ExtensionAllowlist two = allow.with(OTHER).with(ID).with(OTHER);
        assertEquals(List.of(ID, OTHER), two.ids());
        Path file = dir.resolve(ExtensionAllowlist.FILE_NAME);
        Files.writeString(file, two.fileText(), StandardCharsets.UTF_8);
        assertEquals(List.of(ID, OTHER), ExtensionAllowlist.read(file).ids());
        assertEquals('#', two.fileText().charAt(0));
    }

    /** {@code pm browser uninstall --extension-id} and the relay's membership check (ADR 0014 §8). */
    @Test
    void uninstallRemovesOneIdAndTheRelayChecksMembership() {
        ExtensionAllowlist two = allow.with(OTHER);
        assertEquals(List.of(OTHER), two.without(ID).ids());
        assertEquals(two.ids(), two.without("ponmlkjihgfedcbaponmlkjihgfedcbb").ids(), "absent: unchanged");
        assertEquals(List.of(), two.without(ID).without(OTHER).ids());
        assertEquals(true, two.allows(ID));
        assertEquals(false, two.without(ID).allows(ID));
        assertEquals(false, two.allows("not-an-id"));
    }

    @Test
    void anAllowlistTooLargeToReadBackIsNotWritten() {
        ExtensionAllowlist many = ExtensionAllowlist.of(List.of());
        char[] id = ID.toCharArray();
        for (int i = 0; i < ExtensionAllowlist.MAX_FILE_BYTES / (ID.length() + 1); i++) {
            id[0] = (char) ('a' + i % 16);
            id[1] = (char) ('a' + i / 16 % 16);
            many = many.with(String.valueOf(id));
        }
        ExtensionAllowlist full = many;
        assertEquals("ALLOWLIST_FULL",
                assertThrows(IllegalArgumentException.class, full::fileText).getMessage());
    }
}
