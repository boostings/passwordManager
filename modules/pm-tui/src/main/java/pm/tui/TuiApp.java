package pm.tui;

import com.googlecode.lanterna.gui2.MultiWindowTextGUI;
import com.googlecode.lanterna.gui2.TextGUIThread;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.screen.TerminalScreen;
import com.googlecode.lanterna.terminal.Terminal;
import java.io.EOFException;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.locks.LockSupport;
import pm.domain.env.Env;
import pm.vault.VaultService;

/**
 * Lanterna terminal UI: unlock, dashboard with search, record detail with masked secrets, and
 * idle auto-lock (plan.md §13 M1, SR-503, SR-504). Runs a {@link MultiWindowTextGUI} over a
 * {@link TerminalScreen} on the calling thread; the idle timer only posts the lock to that thread.
 */
public final class TuiApp {
    /** Default idle auto-lock timeout (SR-504). */
    public static final Duration DEFAULT_IDLE_LOCK = Duration.ofMinutes(5);

    /** Pause between UI polls when nothing happened, so the loop does not spin. */
    private static final long IDLE_POLL_NANOS = Duration.ofMillis(20).toNanos();

    private final VaultPort port;
    private final Duration idleLock;
    private final ApprovalHost host;
    private final SshActions ssh;

    /** §2 contract constructor; delegates through {@link VaultServiceAdapter}. */
    public TuiApp(VaultService service, Duration idleLock) {
        this(new VaultServiceAdapter(service), idleLock);
    }

    /** Port constructor, used by tests with an in-memory {@link VaultPort}. */
    public TuiApp(VaultPort port, Duration idleLock) {
        this(port, idleLock, ApprovalHost.none());
    }

    /** Port constructor with an approval broker host, which {@link #run} closes when it returns. */
    public TuiApp(VaultPort port, Duration idleLock, ApprovalHost host) {
        this(port, idleLock, host, SshActions.none());
    }

    /** As above, with the ssh-agent actions the CLI provides for SSH key items (M4.4, ADR 0013). */
    public TuiApp(VaultPort port, Duration idleLock, ApprovalHost host, SshActions ssh) {
        this.ssh = Objects.requireNonNull(ssh, "ssh");
        this.port = Objects.requireNonNull(port, "port");
        this.idleLock = Objects.requireNonNull(idleLock, "idleLock");
        this.host = Objects.requireNonNull(host, "host");
    }

    /** Runs the UI on {@code terminal} until the user quits or the terminal reaches end of input. */
    public void run(Terminal terminal) throws IOException {
        Objects.requireNonNull(terminal, "terminal");
        try (ApprovalHost approvals = host;
                var scheduler = IdleLock.newDaemonScheduler();
                Screen screen = new TerminalScreen(terminal)) {
            screen.startScreen();
            PmTheme theme = PmTheme.forEnvironment(Env.system());
            MultiWindowTextGUI gui = newGui(screen, theme);
            TuiController controller = new TuiController(gui, port, idleLock,
                    (timeout, onLock) -> new IdleLockTimer(new IdleLock(timeout, onLock, scheduler)),
                    Clock.systemUTC(), theme, approvals, ssh);
            try {
                loop(gui.getGUIThread(), controller);
            } finally {
                controller.quit(); // closes the session and cancels the timer before scheduler.close()
            }
        }
    }

    /** The window GUI over {@code screen}, themed; shared with the test harness. */
    static MultiWindowTextGUI newGui(Screen screen, PmTheme theme) {
        MultiWindowTextGUI gui = new MultiWindowTextGUI(screen);
        gui.setTheme(theme.cards());
        return gui;
    }

    private static void loop(TextGUIThread guiThread, TuiController controller) throws IOException {
        controller.start();
        try {
            while (!controller.isQuit()) {
                controller.tick();
                if (!guiThread.processEventsAndUpdate()) {
                    LockSupport.parkNanos(IDLE_POLL_NANOS);
                }
            }
        } catch (EOFException endOfInput) {
            controller.quit(); // terminal closed: lock and leave
        }
    }

    /** Production {@link TuiController.IdleTimer} backed by {@link IdleLock} (SR-504). */
    private static final class IdleLockTimer implements TuiController.IdleTimer {
        private final IdleLock idleLockTimer;

        IdleLockTimer(IdleLock idleLockTimer) {
            this.idleLockTimer = idleLockTimer;
        }

        @Override
        public void touch() {
            idleLockTimer.touch();
        }

        @Override
        public void close() {
            idleLockTimer.close();
        }
    }
}
