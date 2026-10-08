package pm.tui;

import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.WindowBasedTextGUI;
import com.googlecode.lanterna.gui2.WindowListenerAdapter;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
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
import pm.tui.lan.LanAddress;
import pm.tui.lan.LanState;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

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
    private final ApprovalHost approvals;
    private final SshActions sshActions;
    private final ClipboardGuard clipboardGuard;
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
    /** GUI-thread confined: LAN listeners, share windows and open questions, closed on lock. */
    private final List<Runnable> lanWork = new ArrayList<>();
    private InetAddress listenAddress = LanAddress.defaultBind();
    /** LAN state every pm process sees (lan-share.md §5, §8), set up on first use. */
    private LanState lanShared;

    TuiController(WindowBasedTextGUI gui, VaultPort port, Duration idleTimeout,
            IdleTimerFactory timers, Clock clock, PmTheme theme) {
        this(gui, port, idleTimeout, timers, clock, theme, ApprovalHost.none());
    }

    TuiController(WindowBasedTextGUI gui, VaultPort port, Duration idleTimeout,
            IdleTimerFactory timers, Clock clock, PmTheme theme, ApprovalHost host) {
        this(gui, port, idleTimeout, timers, clock, theme, host, SshActions.none());
    }

    TuiController(WindowBasedTextGUI gui, VaultPort port, Duration idleTimeout,
            IdleTimerFactory timers, Clock clock, PmTheme theme, ApprovalHost host, SshActions ssh) {
        this(gui, port, idleTimeout, timers, clock, theme, host, ssh,
                new ClipboardGuard(Clipboard.none(), ClipboardGuard.DEFAULT_CLEAR_AFTER));
    }

    TuiController(WindowBasedTextGUI gui, VaultPort port, Duration idleTimeout, IdleTimerFactory timers,
            Clock clock, PmTheme theme, ApprovalHost host, SshActions ssh, ClipboardGuard clipboard) {
        this.clipboardGuard = Objects.requireNonNull(clipboard, "clipboard");
        this.sshActions = Objects.requireNonNull(ssh, "ssh");
        this.approvals = Objects.requireNonNull(host, "host");
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

    /** ssh-agent actions for SSH key items (M4.4); {@link SshActions#none()} when not wired. */
    SshActions ssh() {
        return sshActions;
    }

    /** Copies passwords and clears them off the clipboard again (SR-503). */
    ClipboardGuard clipboard() {
        return clipboardGuard;
    }

    /** The approval host, for audit entries of LAN shares. */
    ApprovalHost host() {
        return approvals;
    }

    /** Where LAN windows listen (lan-share.md §3); a private address by default. */
    InetAddress lanBind() {
        return listenAddress;
    }

    /**
     * Removed-device markers (next to the vault file) and the pairing lockout (run directory) when
     * the approval host knows the vault file, otherwise for this process only.
     *
     * @return empty if a state directory exists but cannot be used safely; LAN steps then refuse
     */
    Optional<LanState> lanState() {
        if (lanShared == null) {
            try {
                lanShared = approvals.lanState().orElseGet(LanState::memory);
            } catch (IOException e) {
                return Optional.empty();
            }
        }
        return Optional.of(lanShared);
    }

    /** Reloads the dashboard table, keeping the search, after an item arrived or left. */
    void refreshDashboard() {
        if (dashboard != null) {
            dashboard.reload();
        }
    }

    /** After an item was added, changed or deleted: reloads the table and shows {@code message}. */
    void changed(String message) {
        if (dashboard != null) {
            dashboard.reload();
            dashboard.toast(message);
        }
    }

    /** Opens the card of {@code item}, with Reveal, Copy, Edit and Delete (M7.8). */
    void openRecord(VaultRecord item) {
        if (session != null) {
            showForm(new RecordDetailWindow(this, item));
        }
    }

    /** Opens the edit dialog of a login or Wi-Fi network. */
    void openEdit(VaultRecord item) {
        if (session == null) {
            return;
        }
        if (item instanceof LoginRecord) {
            showForm(LoginDialog.edit(this, session, LoginRecord.class.cast(item)));
        } else if (item instanceof WifiRecord) {
            showForm(WifiDialog.edit(this, session, WifiRecord.class.cast(item)));
        }
    }

    /** Asks to delete {@code item}; {@code onRemoved} runs once it is out of the session. */
    void openDelete(VaultRecord item, Runnable onRemoved) {
        if (session != null) {
            showForm(new DeleteDialog(this, session, item, onRemoved));
        }
    }

    /** Opens the new Wi-Fi network dialog. */
    void openWifiAdd() {
        if (session != null) {
            showForm(WifiDialog.add(this, session));
        }
    }

    /** Opens the passphrase change dialog (SR-130). */
    void openPassphraseChange() {
        if (session != null) {
            showForm(new PassphraseDialog(this, session));
        }
    }

    /** Test hook: listen on {@code address} instead (loopback in tests). */
    void useLanBind(InetAddress address) {
        listenAddress = Objects.requireNonNull(address, "address");
    }

    /**
     * Runs {@code task} on a new daemon thread: LAN steps block on the network and must not hold
     * up the GUI thread. The task reaches the GUI only through {@link #post}.
     */
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-037: TPS00-J one short-lived thread per LAN step the user starts
    void background(Runnable task) {
        Thread worker = new Thread(task, "pm-lan");
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * Runs {@code task} on the GUI thread, unless the session it was posted from has ended by then:
     * nothing from before a lock ever touches the next session.
     */
    void post(Runnable task) {
        long generation = sessionGeneration;
        gui.getGUIThread().invokeLater(() -> {
            if (generation == sessionGeneration && session != null) {
                task.run();
            }
        });
    }

    /**
     * Runs {@code stop} when the session ends: it closes a listener, revokes a share window or
     * answers an open question with no. It must not throw.
     */
    void track(Runnable stop) {
        lanWork.add(Objects.requireNonNull(stop, "stop"));
    }

    /** Forgets {@code stop} once its work ended by itself. */
    void untrack(Runnable stop) {
        lanWork.remove(stop);
    }

    /** Opens the Devices screen (lan-share.md §5 to §8). */
    void openDevices() {
        if (session != null) {
            showForm(new DevicesWindow(this, session));
        }
    }

    /** Opens the share dialog for {@code item}. */
    void openShare(pm.vault.record.VaultRecord item) {
        if (session != null) {
            showForm(new ShareDialog(this, session, item));
        }
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
        approvals.unlocked(new GuiThreadReleaser(gui.getGUIThread(),
                () -> Optional.ofNullable(session).map(Session::records)));
        approvals.browser(new GuiThreadBrowserVault(gui.getGUIThread(), () -> Optional.ofNullable(session),
                timeSource, this::refreshDashboard));
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
            if (open && approvalDialog.isNotice()
                    && approvals.broker().map(b -> b.pending().isEmpty()).orElse(true)) {
                return; // "too small, denied" stays until closed or the next prompt arrives
            }
            if (open) {
                gui.removeWindow(approvalDialog.window()); // timed out or answered elsewhere
            }
            approvalDialog = null;
        }
        approvals.broker().ifPresent(b -> {
            List<PendingApproval> waiting = b.pending();
            if (!waiting.isEmpty()) {
                PendingApproval next = waiting.get(0);
                if (!approvals.stillAsked(next.request())) {
                    next.deny(); // its extension was taken off the allowlist: never shown (ADR 0014 §8)
                    return;
                }
                approvalDialog = new ApprovalDialog(pmTheme, next, b.servedUser(), now,
                        () -> gui.getScreen().getTerminalSize(), approvals.peer(next.request()));
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
        clipboardGuard.tick(now);
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

    /** For tests: the most recently shown form of {@code type} that is still on screen. */
    <T extends InputForm> T shownForm(Class<T> type) {
        openForms.removeIf(f -> !gui.getWindows().contains(f.window()));
        return openForms.stream().filter(type::isInstance).map(type::cast).reduce((a, b) -> b).orElseThrow();
    }

    /** Adds {@code window} on top, wiring the activity listener so every key touches the timer. */
    void show(Window window) {
        window.addWindowListener(activityListener);
        gui.addWindow(window);
        gui.setActiveWindow(window);
    }

    private void endSession() {
        approvals.locked(); // before the session closes: pending prompts are denied, the token withdrawn
        approvalDialog = null;
        closeLanWork(); // revokes open share windows and stops listeners before the session closes
        clearForms();
        clipboardGuard.clearNow(); // SR-503: a copied password does not outlive the session
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

    private void closeLanWork() {
        List<Runnable> stops = List.copyOf(lanWork);
        lanWork.clear();
        stops.forEach(Runnable::run);
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
