package pm.tui;

import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.WindowBasedTextGUI;
import com.googlecode.lanterna.gui2.WindowListenerAdapter;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Optional;
import pm.approval.PendingApproval;
import pm.crypto.SecretChars;
import pm.vault.VaultException;

/**
 * Screen flow of the TUI (plan.md §13 M1): unlock, dashboard, record detail and add-login, plus
 * idle auto-lock (SR-504). All methods run on the Lanterna GUI thread, except the idle timer's
 * {@code onLock}, which only posts {@link #lock()} through {@code invokeLater}. Every open
 * {@link InputForm} is tracked and its boxes emptied on unlock, lock, idle-lock and quit, so a
 * typed password never outlives its window in a pm reference (ADR 0008, SR-504).
 */
final class TuiController {

    /** Restartable idle countdown; production wraps {@link IdleLock} (SR-504). */
    interface IdleTimer extends AutoCloseable {
        /** Restarts the countdown. */
        void touch();

        /** Cancels the countdown for good. */
        @Override
        void close();
    }

    /** Starts an {@link IdleTimer} that calls {@code onLock} (from any thread) on expiry. */
    @FunctionalInterface
    interface IdleTimerFactory {
        /** Starts a countdown of {@code timeout}. */
        IdleTimer start(Duration timeout, Runnable onLock);
    }

    private final WindowBasedTextGUI gui;
    private final VaultPort port;
    private final Duration idleTimeout;
    private final IdleTimerFactory timers;
    private final Clock timeSource;
    private final PmTheme pmTheme;
    private final ApprovalHost host;
    private final ActivityListener activityListener = new ActivityListener();
    /** GUI-thread confined: forms shown and not yet cleared by the controller. */
    private final List<InputForm> openForms = new ArrayList<>();

    // GUI-thread confined state.
    private Session session;
    private IdleTimer idleTimer;
    private DashboardWindow dashboard;
    private Instant lastActivity;
    private long sessionGeneration;
    private boolean quitRequested;
    private ApprovalDialog approvalDialog;

    TuiController(WindowBasedTextGUI gui, VaultPort port, Duration idleTimeout,
            IdleTimerFactory timers, Clock clock, PmTheme theme) {
        this(gui, port, idleTimeout, timers, clock, theme, ApprovalHost.none());
    }

    TuiController(WindowBasedTextGUI gui, VaultPort port, Duration idleTimeout,
            IdleTimerFactory timers, Clock clock, PmTheme theme, ApprovalHost host) {
        this.host = Objects.requireNonNull(host, "host");
        this.gui = Objects.requireNonNull(gui, "gui");
        this.port = Objects.requireNonNull(port, "port");
        this.idleTimeout = Objects.requireNonNull(idleTimeout, "idleTimeout");
        this.timers = Objects.requireNonNull(timers, "timers");
        this.timeSource = Objects.requireNonNull(clock, "clock");
        this.pmTheme = Objects.requireNonNull(theme, "theme");
    }

    /** Shows the unlock screen. */
    void start() {
        showForm(new UnlockWindow(this));
    }

    /** Whether the user asked to quit. */
    boolean isQuit() {
        return quitRequested;
    }

    /** Whether a session is currently open. */
    boolean isUnlocked() {
        return session != null;
    }

    /** Clock used for record timestamps and the lock countdown. */
    Clock clock() {
        return timeSource;
    }

    /** Colors and styles shared by every window. */
    PmTheme theme() {
        return pmTheme;
    }

    /**
     * Draws pending changes now, before a long call on this thread (key derivation) blocks the
     * loop, so the user sees why the screen is still.
     */
    void repaintNow() {
        try {
            gui.updateScreen();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Whether {@code key} is Ctrl plus the letter {@code letter}. */
    static boolean isCtrl(KeyStroke key, char letter) {
        return key.getKeyType() == KeyType.Character && key.isCtrlDown()
                && Character.toLowerCase(key.getCharacter()) == letter;
    }

    /** A listener that runs {@code close} on Esc, for dialogs. */
    static WindowListenerAdapter closeOnEscape(Runnable close) {
        return new WindowListenerAdapter() {
            @Override
            public void onInput(Window basePane, KeyStroke key, AtomicBoolean deliverEvent) {
                if (key.getKeyType() == KeyType.Escape) {
                    deliverEvent.set(false);
                    close.run();
                }
            }
        };
    }

    /** Unlocks through the passphrase or recovery-key slot and opens the dashboard. */
    void unlock(SecretChars credential, boolean recoveryKey) throws VaultException {
        Objects.requireNonNull(credential, "credential");
        openDashboard(recoveryKey
                ? port.unlockWithRecoveryKey(credential)
                : port.unlockWithPassphrase(credential));
    }

    private void openDashboard(Session opened) {
        removeAllWindows();
        session = opened;
        long generation = ++sessionGeneration;
        lastActivity = timeSource.instant();
        idleTimer = timers.start(idleTimeout, () -> postLock(generation));
        dashboard = new DashboardWindow(this, opened);
        show(dashboard.window());
        host.unlocked(new GuiThreadReleaser(gui.getGUIThread(),
                () -> Optional.ofNullable(session).map(Session::records)));
        tick();
    }

    /** Shows the oldest waiting approval prompt, one at a time (approval-model §4). */
    private void showNextApproval(Instant now) {
        if (session == null) {
            return;
        }
        if (approvalDialog != null) {
            boolean open = gui.getWindows().contains(approvalDialog.window());
            if (open && !approvalDialog.prompt().isDone()) {
                return;
            }
            if (open) {
                gui.removeWindow(approvalDialog.window()); // timed out or answered elsewhere
            }
            approvalDialog = null;
        }
        host.broker().ifPresent(b -> {
            List<PendingApproval> waiting = b.pending();
            if (!waiting.isEmpty()) {
                approvalDialog = new ApprovalDialog(pmTheme, waiting.get(0), b.servedUser(), now);
                showForm(approvalDialog);
                approvalDialog.animate(now);
            }
        });
    }

    /** Called from the idle timer's thread: hands the lock to the GUI thread. */
    private void postLock(long generation) {
        gui.getGUIThread().invokeLater(() -> {
            if (generation == sessionGeneration) {
                lock();
            }
        });
    }

    /** Records user activity: restarts the idle countdown (SR-504). */
    void activity() {
        if (idleTimer != null) {
            idleTimer.touch();
            lastActivity = timeSource.instant();
        }
    }

    /**
     * Runs once per UI loop: refreshes the "Locked in m:ss" countdown (SR-504) and advances every
     * animation to the clock's current instant.
     */
    void tick() {
        Instant now = timeSource.instant();
        if (dashboard != null) {
            Duration idle = Duration.between(lastActivity, now);
            dashboard.animate(now, idleTimeout.minus(idle), idleTimeout);
        }
        openForms.removeIf(f -> !gui.getWindows().contains(f.window()));
        openForms.forEach(f -> f.animate(now));
        showNextApproval(now);
    }

    /** Locks: closes the session and returns to the unlock screen (SR-504). */
    void lock() {
        endSession();
        removeAllWindows();
        start();
    }

    /** Locks and stops the UI loop. Idempotent. */
    void quit() {
        endSession();
        removeAllWindows();
        quitRequested = true;
    }

    /** Shows {@code form} and tracks it so lock and quit can empty its boxes (ADR 0008). */
    void showForm(InputForm form) {
        openForms.removeIf(f -> !gui.getWindows().contains(f.window()));
        openForms.add(form);
        show(form.window());
    }

    /** Adds {@code window} on top, wiring the activity listener so every key touches the timer. */
    void show(Window window) {
        window.addWindowListener(activityListener);
        gui.addWindow(window);
        gui.setActiveWindow(window);
    }

    private void endSession() {
        host.locked(); // before the session closes: pending prompts are denied, the token withdrawn
        approvalDialog = null;
        clearForms();
        sessionGeneration++;
        if (idleTimer != null) {
            idleTimer.close();
            idleTimer = null;
        }
        if (session != null) {
            session.close();
            session = null;
        }
        dashboard = null;
        lastActivity = null;
    }

    private void removeAllWindows() {
        clearForms();
        for (Window w : List.copyOf(gui.getWindows())) {
            gui.removeWindow(w);
        }
    }

    /** Empties every tracked form, masked boxes included, and forgets it (ADR 0008). */
    private void clearForms() {
        openForms.forEach(InputForm::clearInputs);
        openForms.clear();
    }

    /** Touches the idle timer on every key event that reaches any TUI window. */
    private final class ActivityListener extends WindowListenerAdapter {
        @Override
        public void onInput(Window basePane, KeyStroke keyStroke, AtomicBoolean deliverEvent) {
            activity();
            if (isCtrl(keyStroke, 'x')) { // quit from any screen
                deliverEvent.set(false);
                quit();
            }
        }
    }
}
