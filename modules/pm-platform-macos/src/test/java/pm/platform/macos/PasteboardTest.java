package pm.platform.macos;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * The pasteboard's process handling, driven by stand-in tools ({@code tee} and {@code cat} over a
 * file) so the test never touches the real pasteboard of the machine it runs on.
 */
@DisabledOnOs(OS.WINDOWS)
class PasteboardTest {
    private static final Duration SHORT = Duration.ofMillis(300);

    @TempDir
    Path dir;

    private Pasteboard overFile(Path file) {
        return new Pasteboard(List.of("/usr/bin/tee", file.toString()), List.of("/bin/cat", file.toString()),
                Pasteboard.DEADLINE);
    }

    @Test
    void copiedTextReadsBackByteForByteAndClearLeavesNothing() throws IOException {
        Path file = dir.resolve("board");
        Pasteboard board = overFile(file);
        byte[] text = "pässwörd-✓".getBytes(StandardCharsets.UTF_8);
        assertTrue(board.copy(text));
        assertArrayEquals(text, Files.readAllBytes(file));
        assertArrayEquals(text, board.read().orElseThrow());
        assertTrue(board.clear());
        assertEquals(0, board.read().orElseThrow().length);
    }

    @Test
    void aFailingOrMissingToolIsReportedNotThrown() {
        Pasteboard failing = new Pasteboard(List.of("/usr/bin/false"), List.of("/usr/bin/false"), SHORT);
        assertFalse(failing.copy(new byte[] {1}));
        assertEquals(Optional.empty(), failing.read());
        Pasteboard missing = new Pasteboard(List.of("/nonexistent/pbcopy"), List.of("/nonexistent/pbpaste"), SHORT);
        assertFalse(missing.copy(new byte[] {1}));
        assertFalse(missing.clear());
        assertEquals(Optional.empty(), missing.read());
    }

    @Test
    void aToolThatHangsIsKilledAtTheDeadline() {
        Pasteboard hanging = new Pasteboard(List.of("/bin/sleep", "30"), List.of("/bin/sleep", "30"), SHORT);
        long start = System.nanoTime();
        assertFalse(hanging.copy(new byte[] {1}));
        assertEquals(Optional.empty(), hanging.read());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(10)) < 0,
                "both calls return near their deadline, not when the tool would have finished");
    }

    @Test
    void aToolThatClosesItsInputEarlyFailsTheCopy() {
        Pasteboard closing = new Pasteboard(List.of("/usr/bin/true"), List.of("/usr/bin/true"), SHORT);
        assertFalse(closing.copy(new byte[4 * 1024 * 1024]), "the write breaks on the closed pipe");
    }

    @Test
    void moreTextThanAnySecretIsCutAtTheLimitWithoutStallingTheTool() {
        Pasteboard big = new Pasteboard(List.of("/usr/bin/true"),
                List.of("/usr/bin/head", "-c", "200000", "/dev/zero"), Pasteboard.DEADLINE);
        assertEquals(Pasteboard.MAX_READ, big.read().orElseThrow().length);
    }

    @Test
    @EnabledOnOs(OS.MAC)
    void macOsHasBothTools() {
        assertTrue(Pasteboard.system().isPresent());
    }
}
