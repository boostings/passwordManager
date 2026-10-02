package pm.cli;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import com.googlecode.lanterna.terminal.Terminal;
import com.googlecode.lanterna.terminal.virtual.DefaultVirtualTerminal;
import com.googlecode.lanterna.terminal.virtual.VirtualTerminalListener;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pm.tui.TuiApp;
import pm.tui.VaultPort;
import pm.vault.VaultException;

/**
 * SR-500: the canary passphrase never reaches stdout, stderr or the TUI's terminal, on success or
 * failure paths. The {@code tui} scenario runs the real {@link TuiApp} on a headless terminal: it
 * types the canary into the unlock window, lets the dashboard render a record whose password is
 * also the canary, then ends input. Every flushed frame is checked, not just the last one.
 */
class CanaryTest {
    private static final String CANARY = MainArgsTest.CANARY;
    private static final Instant NOW = Instant.parse("2026-10-02T12:00:00Z");
    private static final TerminalSize TUI_SIZE = new TerminalSize(100, 30);
    private static final String STORED_TITLE = "GitHub";
    private static final int MAX_FRAMES = 50;

    /** One scripted invocation: port factory, console script, args. */
    private record Scenario(Supplier<FakeVaultPort> port, Supplier<FakeConsoleIo> io, List<String> args) {
    }

    private static Arguments scenario(String name, Supplier<FakeVaultPort> port, Supplier<FakeConsoleIo> io,
            String... args) {
        return Arguments.of(Named.of(name, new Scenario(port, io, List.of(args))));
    }

    private static FakeVaultPort populated() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        port.stored.add(FakeVaultPort.login(STORED_TITLE, CANARY, NOW));
        return port;
    }

    static Stream<Arguments> scenarios() {
        return Stream.of(
                scenario("init", FakeVaultPort::new, () -> new FakeConsoleIo().secret(CANARY).secret(CANARY), "init"),
                scenario("init mismatch", FakeVaultPort::new,
                        () -> new FakeConsoleIo().secret(CANARY).secret(CANARY + "!"), "init"),
                scenario("init exists", CanaryTest::populated,
                        () -> new FakeConsoleIo().secret(CANARY).secret(CANARY), "init"),
                scenario("init, recovery key not shown", FakeVaultPort::new,
                        () -> new FakeConsoleIo().secret(CANARY).secret(CANARY).failingOut(), "init"),
                scenario("internal error", () -> populated().buggy(),
                        () -> new FakeConsoleIo().secret(CANARY), "list"),
                scenario("add-login", CanaryTest::populated, () -> new FakeConsoleIo().secret(CANARY)
                        .line("Site").line("bob").secret(CANARY).line("https://x").line("t"), "add-login"),
                scenario("add-login refused", () -> populated().refusingPut(), () -> new FakeConsoleIo().secret(CANARY)
                        .line("Site").line("bob").secret(CANARY).line("https://x").line("t"), "add-login"),
                scenario("list", CanaryTest::populated, () -> new FakeConsoleIo().secret(CANARY), "list"),
                scenario("search", CanaryTest::populated, () -> new FakeConsoleIo().secret(CANARY), "search", "git"),
                scenario("wrong passphrase", () -> new FakeVaultPort().withVault("other"),
                        () -> new FakeConsoleIo().secret(CANARY), "list"),
                scenario("corrupt", () -> populated().failing(VaultException.Code.CORRUPT),
                        () -> new FakeConsoleIo().secret(CANARY), "list"),
                scenario("passphrase as argument", CanaryTest::populated, FakeConsoleIo::new, "list", CANARY),
                scenario("tui", CanaryTest::populated, FakeConsoleIo::new, "tui"));
    }

    @ParameterizedTest
    @MethodSource("scenarios")
    void canaryNeverReachesOutput(Scenario s) {
        FakeVaultPort port = s.port().get();
        FakeConsoleIo io = s.io().get();
        StringBuilder tuiFrames = new StringBuilder();
        Cli cli = new Cli(Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, "/home/alice")::get,
                Clock.fixed(NOW, ZoneOffset.UTC), p -> runRealTui(p, tuiFrames));

        cli.run(s.args().toArray(String[]::new), io, (path, creating) -> port);

        assertFalse(io.outText().contains(CANARY), "stdout leaked the canary");
        assertFalse(io.errText().contains(CANARY), "stderr leaked the canary");
        assertFalse(tuiFrames.toString().contains(CANARY), "TUI terminal leaked the canary");
        assertTrue(io.allSecretsZeroed(), "every readPassword buffer zeroed");
        if (s.args().contains("tui")) {
            assertTrue(tuiFrames.toString().contains(STORED_TITLE), "the TUI unlocked and listed the record");
            assertTrue(port.session().isLocked(), "end of input locked the TUI session");
        }
    }

    /**
     * Unlocks with the canary in the real TUI and ends input once the dashboard has been drawn
     * (or after {@link #MAX_FRAMES} flushes, so a broken unlock fails the assertion, not the build).
     */
    private static void runRealTui(VaultPort port, StringBuilder frames) throws IOException {
        try (DefaultVirtualTerminal terminal = new DefaultVirtualTerminal(TUI_SIZE)) {
            terminal.addVirtualTerminalListener(new FrameRecorder(terminal, frames));
            CANARY.chars().forEach(c -> terminal.addInput(new KeyStroke((char) c, false, false)));
            terminal.addInput(new KeyStroke(KeyType.Enter)); // passphrase box -> Unlock button
            terminal.addInput(new KeyStroke(KeyType.Enter)); // Unlock
            new TuiApp(port, TuiApp.DEFAULT_IDLE_LOCK).run(terminal);
        }
    }

    /**
     * Appends the visible screen to {@code frames} on every flush, and queues end of input once the
     * dashboard shows the stored record. Queuing it up front would let the GUI read every key,
     * including end of input, before it ever draws.
     */
    private static final class FrameRecorder implements VirtualTerminalListener {
        private final DefaultVirtualTerminal terminal;
        private final StringBuilder frames;
        private int flushes;
        private boolean ended;

        FrameRecorder(DefaultVirtualTerminal terminal, StringBuilder frames) {
            this.terminal = terminal;
            this.frames = frames;
        }

        @Override
        public void onFlush() {
            TerminalSize size = terminal.getTerminalSize();
            for (int row = 0; row < size.getRows(); row++) {
                for (int col = 0; col < size.getColumns(); col++) {
                    frames.append(terminal.getCharacter(col, row).getCharacterString());
                }
                frames.append('\n');
            }
            flushes++;
            if (!ended && (frames.indexOf(STORED_TITLE) >= 0 || flushes >= MAX_FRAMES)) {
                ended = true;
                terminal.addInput(new KeyStroke(KeyType.EOF));
            }
        }

        @Override
        public void onBell() {
            // no visible output
        }

        @Override
        public void onClose() {
            // the last frame was recorded on its flush
        }

        @Override
        public void onResized(Terminal resized, TerminalSize newSize) {
            // fixed-size headless terminal
        }
    }
}
