package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.Component;
import com.googlecode.lanterna.gui2.Container;
import com.googlecode.lanterna.gui2.MultiWindowTextGUI;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import com.googlecode.lanterna.screen.TerminalScreen;
import com.googlecode.lanterna.terminal.virtual.DefaultVirtualTerminal;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/**
 * Headless TUI driver: a {@link DefaultVirtualTerminal} under a real {@link TerminalScreen} and
 * {@link MultiWindowTextGUI}, pumped explicitly on the test thread (the GUI uses
 * {@code SameTextGUIThread}, so the thread that builds it is the GUI thread). Time is a manual
 * clock and the idle timer is a {@link FakeTimers}, so nothing sleeps.
 */
final class TuiHarness implements AutoCloseable {
    static final Duration TIMEOUT = Duration.ofMinutes(5);
    private static final int COLUMNS = 110;
    private static final int ROWS = 32;
    private static final int MAX_PUMPS = 100;

    final DefaultVirtualTerminal terminal;
    final FakeVaultPort port;
    final FakeTimers timers = new FakeTimers();
    final ManualClock clock;
    final TuiController controller;
    final PmTheme theme = PmTheme.standard(); // as TuiApp
    private final TerminalScreen screen;
    private final MultiWindowTextGUI gui;
    private final List<String> frames = new ArrayList<>();

    TuiHarness(FakeVaultPort port) throws IOException {
        this(port, ApprovalHost.none());
    }

    TuiHarness(FakeVaultPort port, ApprovalHost host) throws IOException {
        this(port, host, new ManualClock(FakeVaultPort.T0));
    }

    /** With an approval host whose broker shares {@code clock}. */
    TuiHarness(FakeVaultPort port, ApprovalHost host, ManualClock clock) throws IOException {
        this(port, host, clock, SshActions.none(), new TerminalSize(COLUMNS, ROWS));
    }

    /** With ssh-agent actions (M4.4). */
    TuiHarness(FakeVaultPort port, SshActions ssh) throws IOException {
        this(port, ApprovalHost.none(), new ManualClock(FakeVaultPort.T0), ssh, new TerminalSize(COLUMNS, ROWS));
    }

    /** With an approval host on a terminal of {@code size} (M5.4: prompts that must fit). */
    TuiHarness(FakeVaultPort port, ApprovalHost host, ManualClock clock, TerminalSize size) throws IOException {
        this(port, host, clock, SshActions.none(), size);
    }

    private TuiHarness(FakeVaultPort port, ApprovalHost host, ManualClock clock, SshActions ssh, TerminalSize size)
            throws IOException {
        this.terminal = new DefaultVirtualTerminal(size);
        this.port = port;
        this.clock = clock;
        screen = new TerminalScreen(terminal);
        screen.startScreen();
        gui = TuiApp.newGui(screen, theme);
        controller = new TuiController(gui, port, TIMEOUT, timers, clock, theme, host, ssh);
        controller.start();
        pump();
    }

    /** Processes all queued input and GUI tasks, then records the rendered frame. */
    void pump() {
        try {
            int rounds = 0;
            while (gui.getGUIThread().processEventsAndUpdate() && rounds < MAX_PUMPS) {
                rounds++;
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        frames.add(screenText());
    }

    /** Types {@code text} one character at a time, then pumps. */
    void type(String text) {
        text.chars().forEach(c -> terminal.addInput(new KeyStroke((char) c, false, false)));
        pump();
    }

    /** Presses each key in order, then pumps. */
    void press(KeyType... keys) {
        for (KeyType k : keys) {
            terminal.addInput(new KeyStroke(k));
        }
        pump();
    }

    /** Runs the controller's status tick, then pumps. */
    void tick() {
        controller.tick();
        pump();
    }

    /** Presses Ctrl plus {@code letter}, then pumps. */
    void ctrl(char letter) {
        terminal.addInput(new KeyStroke(letter, true, false));
        pump();
    }

    /** Unlocks with {@code credential} through the passphrase button (Enter moves to it). */
    void unlockWith(String credential) {
        type(credential);
        press(KeyType.Enter, KeyType.Enter);
    }

    /** The visible screen, one line per row. */
    String screenText() {
        StringBuilder sb = new StringBuilder();
        TerminalSize size = terminal.getTerminalSize();
        for (int row = 0; row < size.getRows(); row++) {
            for (int col = 0; col < size.getColumns(); col++) {
                sb.append(terminal.getCharacter(col, row).getCharacterString());
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    /** Every line in the terminal's current buffer, including scrollback. */
    String bufferText() {
        StringBuilder sb = new StringBuilder();
        int columns = terminal.getTerminalSize().getColumns();
        terminal.forEachLine(0, terminal.getBufferLineCount() - 1, (row, line) -> {
            for (int col = 0; col < columns; col++) {
                sb.append(line.getCharacterAt(col).getCharacterString());
            }
            sb.append('\n');
        });
        return sb.toString();
    }

    /** The window that currently has focus. */
    Window activeWindow() {
        return gui.getActiveWindow();
    }

    /** Text of every {@link TextBox} in {@code window}, masked boxes included, in layout order. */
    static List<String> boxTexts(Window window) {
        List<String> texts = new ArrayList<>();
        collectBoxTexts(window.getComponent(), texts);
        return texts;
    }

    private static void collectBoxTexts(Component c, List<String> texts) {
        if (c instanceof TextBox box) {
            texts.add(box.getText());
        } else if (c instanceof Container container) {
            container.getChildren().forEach(child -> collectBoxTexts(child, texts));
        }
    }

    /** Every frame rendered since the harness started. */
    List<String> renderedFrames() {
        return frames;
    }

    @Override
    public void close() throws IOException {
        controller.quit();
        screen.stopScreen();
    }

    /** {@link TuiController.IdleTimerFactory} whose expiry is fired by hand. */
    static final class FakeTimers implements TuiController.IdleTimerFactory {
        private final List<Runnable> onLocks = new ArrayList<>();
        private int touchCount;
        private int closeCount;

        @Override
        public TuiController.IdleTimer start(Duration timeout, Runnable onLock) {
            onLocks.add(onLock);
            return new TuiController.IdleTimer() {
                @Override
                public void touch() {
                    touchCount++;
                }

                @Override
                public void close() {
                    closeCount++;
                }
            };
        }

        /** Simulates the expiry of the most recently started timer (as IdleLock would). */
        void fireLatest() {
            onLocks.get(onLocks.size() - 1).run();
        }

        /** Simulates the expiry of the {@code index}-th started timer. */
        void fire(int index) {
            onLocks.get(index).run();
        }

        int started() {
            return onLocks.size();
        }

        int touches() {
            return touchCount;
        }

        int closes() {
            return closeCount;
        }
    }

    /** Clock advanced by hand. */
    static final class ManualClock extends Clock {
        private Instant now;

        ManualClock(Instant start) {
            now = start;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
