package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.table.Table;
import com.googlecode.lanterna.gui2.table.TableModel;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import pm.approval.AuditEvent;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.sharing.pair.Lockout;
import pm.sharing.pair.PairedDevice;
import pm.sharing.pair.PairingException;
import pm.sharing.pair.SasPrompt;
import pm.sharing.share.OfferPrompt;
import pm.sharing.share.ReceivedShares;
import pm.sharing.share.ShareException;
import pm.sharing.wire.Message;
import pm.tui.lan.Devices;
import pm.tui.lan.LanAddress;
import pm.tui.lan.LanException;
import pm.tui.lan.LanState;
import pm.tui.lan.Local;
import pm.tui.lan.Pairing;
import pm.tui.lan.Receiving;
import pm.tui.lan.SharePayload;
import pm.vault.VaultException;
import pm.vault.record.TrustedDeviceRecord;
import pm.vault.record.VaultRecord;

/**
 * The Devices screen (M3.6, lan-share.md §5 to §8): this device's name and fingerprint, the paired
 * devices, and the steps that need no item: pair (wait here, or connect to an address the other
 * screen shows), receive one share from a paired device, and remove a device with the "rotate these
 * secrets" checklist. Network steps run on a worker ({@link LanJob}); the pairing code and every
 * offer are shown here and need an explicit Yes. One step runs at a time; Esc, lock and quit stop
 * it. Every text from the network or the vault passes {@link DisplaySafe#text(String)} (SR-501).
 */
final class DevicesWindow implements InputForm {
    static final String TITLE = "Devices";
    static final String PAIR_HERE = "Pair (wait here)";
    static final String PAIR_WITH = "Pair with address";
    static final String RECEIVE_BUTTON = "Receive";
    static final String REMOVE_BUTTON = "Remove";
    static final String YES = "Yes";
    static final String NO = "No";
    static final String CLOSE = "Close";
    static final String ADDRESS_LABEL = "Other device (ip:port):";
    static final String HINT = "⇥ next   esc close";
    static final String THIS_DEVICE = "This device: ";
    static final String NO_DEVICES = "No paired devices yet. Choose Pair here and Pair with address on the other one.";
    static final String WAITING = "Waiting for the other device at ";
    static final String CONNECTING = "Connecting…";
    static final String PAIR_CODE = "Pairing code: ";
    static final String COMPARE = "Choose Yes only if both screens show the same code.";
    static final String PAIRED = "Paired: ";
    static final String NOT_PAIRED = "Nothing was paired.";
    static final String PAIR_FAILED = "Pairing did not complete: ";
    static final String OFFER_FROM = "Offer from ";
    static final String ACCEPT = "Choose Yes to add it to this vault.";
    static final String RECEIVED = "Received: ";
    static final String NOT_RECEIVED = "Nothing was received.";
    static final String UNREACHABLE = "Could not connect: not paired, wrong address, or the window is closed.";
    static final String BAD_ADDRESS = "Type the address the other screen shows, as ip:port.";
    static final String BUSY = "Another step is still running; press Esc to stop it.";
    static final String SELECT_DEVICE = "Select a device first.";
    static final String REMOVE_ASK = "Remove this device? It can no longer connect, and share windows open to it close: ";
    static final String ANSWER_FIRST = "Answer the open question first.";
    static final String STATE_FAILED = "The owner-only LAN state directories could not be used, so nothing was changed.";
    static final String REMOVED = "Removed: ";
    static final String ROTATE = "Rotate these secrets, which were offered to it: ";
    static final String ROTATE_NONE = "No items in this vault were offered to it.";
    static final String AUDIT_FAILED = "The audit log could not be written, so nothing was changed.";
    static final String LAN_FAILED = "The network port or this device's key could not be used.";

    private static final String[] COLUMNS = {"Name", "Fingerprint", "Paired"};
    private static final int FIELD_COLUMNS = 30;
    private static final String GAP = "  ";
    private static final DateTimeFormatter PAIRED_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.ROOT).withZone(ZoneOffset.UTC);

    private final TuiController controller;
    private final Session session;
    private final Clock clock;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final Label self = new Label("");
    private final Table<String> table = new Table<>(COLUMNS);
    private final TextBox addressBox = new TextBox(new TerminalSize(FIELD_COLUMNS, 1));
    private final Label status = new Label("");
    private final Panel yesNo = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
    private final Button yesButton = PmTheme.pill(YES, () -> answered(true));
    private final Notice notice;
    private final List<TrustedDeviceRecord> shown = new ArrayList<>();
    /**
     * GUI-thread confined: questions in the order asked. Only the first is on screen, and Yes and
     * No answer only that one, so an answer can never reach a question that was not showing.
     */
    private final Deque<Question> questions = new ArrayDeque<>();
    /** GUI-thread confined: the running step. */
    private LanJob job;

    /**
     * One question: its text, what its answer does, and whether it was abandoned (its step stopped
     * or timed out), in which case it leaves the queue unanswered.
     */
    private record Question(String text, Consumer<Boolean> onAnswer, BooleanSupplier abandoned) {}

    DevicesWindow(TuiController controller, Session session) {
        this.controller = controller;
        this.session = session;
        this.clock = controller.clock();
        PmTheme theme = controller.theme();
        this.notice = new Notice(theme);
        self.setForegroundColor(theme.color(PmTheme.Tone.BRIGHT));
        status.setForegroundColor(theme.color(PmTheme.Tone.TEXT));
        addressBox.setInputFilter(DisplaySafe.rejectUnsafe(
                () -> notice.error(Messages.UNSAFE_CHARACTER, clock.instant())));

        Panel address = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(1));
        address.addComponent(UnlockWindow.dim(theme, ADDRESS_LABEL));
        address.addComponent(addressBox);

        Panel actions = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        actions.addComponent(PmTheme.pill(PAIR_HERE, this::pairHere));
        actions.addComponent(PmTheme.pill(PAIR_WITH, this::pairWith));
        actions.addComponent(PmTheme.pill(RECEIVE_BUTTON, this::receive));
        actions.addComponent(PmTheme.pill(REMOVE_BUTTON, this::askRemove));
        actions.addComponent(PmTheme.pill(CLOSE, this::dismiss));

        yesNo.addComponent(yesButton);
        yesNo.addComponent(PmTheme.pill(NO, () -> answered(false)));
        yesNo.setVisible(false);

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL).setSpacing(0));
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(self);
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(table);
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(address);
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(actions);
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(status);
        content.addComponent(yesNo);
        content.addComponent(notice.label());
        content.addComponent(UnlockWindow.dim(theme, HINT));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(addressBox);
        basicWindow.addWindowListener(TuiController.closeOnEscape(this::dismiss));
        refresh();
    }

    @Override
    public Window window() {
        return basicWindow;
    }

    @Override
    public void clearInputs() {
        addressBox.setText("");
        notice.clear();
    }

    @Override
    public void animate(Instant now) {
        notice.animate(now);
    }

    /** Reloads this device's line and the paired devices. */
    void refresh() {
        Optional<String> identity = Devices.identityRecord(session)
                .map(r -> DisplaySafe.text(r.title()) + GAP + Devices.fingerprint(r).orElse("?"));
        self.setText(THIS_DEVICE + identity.orElse("(created on first pairing)"));
        shown.clear();
        shown.addAll(Devices.trusted(session));
        TableModel<String> model = new TableModel<>(COLUMNS);
        shown.forEach(d -> model.addRow(DisplaySafe.text(d.title()), d.fingerprint(),
                PAIRED_FORMAT.format(d.pairedAt())));
        table.setTableModel(model);
        if (shown.isEmpty()) {
            status.setText(NO_DEVICES);
        }
    }

    private void dismiss() {
        stopJob();
        clearInputs();
        basicWindow.close();
    }

    private void stopJob() {
        if (job != null) {
            controller.untrack(job);
            job.run();
            job = null;
        }
        showQuestion();
    }

    // ---- questions ---------------------------------------------------------------------------

    /** Queues a question; it shows once every earlier one is answered. */
    private void question(String text, Consumer<Boolean> onAnswer, BooleanSupplier abandoned) {
        questions.addLast(new Question(text, onAnswer, abandoned));
        showQuestion();
    }

    /** Answers the question on screen, and only that one. */
    private void answered(boolean yes) {
        dropAbandoned();
        Question shownQuestion = questions.pollFirst();
        if (shownQuestion != null) {
            shownQuestion.onAnswer().accept(yes);
        }
        showQuestion();
    }

    /** Shows the first question still waiting, or hides Yes and No. */
    private void showQuestion() {
        dropAbandoned();
        Question next = questions.peekFirst();
        if (next == null) {
            yesNo.setVisible(false);
            return;
        }
        status.setText(next.text());
        yesNo.setVisible(true);
        basicWindow.setFocusedInteractable(yesButton);
    }

    /** Questions answered elsewhere (a stopped step, a timeout) leave the queue. */
    private void dropAbandoned() {
        questions.removeIf(q -> q.abandoned().getAsBoolean());
    }

    /** Refuses a new step or question while one waits for Yes or No. */
    private boolean idleQuestions() {
        dropAbandoned();
        if (questions.isEmpty()) {
            return true;
        }
        notice.error(ANSWER_FIRST, clock.instant());
        return false;
    }

    /** From a worker: asks on this window, waiting for Yes or No. */
    private boolean ask(LanJob running, String text) {
        return running.ask(f -> question(text, f::complete, f::isDone));
    }

    // ---- steps -------------------------------------------------------------------------------

    /** Starts a step: refuses while another runs, then tracks it so lock and Esc stop it. */
    private Optional<LanJob> start() {
        if (!idleQuestions()) {
            return Optional.empty();
        }
        if (job != null && !job.isStopped()) {
            notice.error(BUSY, clock.instant());
            return Optional.empty();
        }
        notice.clear();
        job = new LanJob(controller);
        controller.track(job);
        return Optional.of(job);
    }

    /** From a worker: the step ended; forget it on the GUI thread. */
    private void finished(LanJob done, Runnable then) {
        controller.post(() -> {
            controller.untrack(done);
            if (done.equals(job)) {
                job = null;
            }
            then.run();
            showQuestion(); // a question still waiting keeps the status line: it is what Yes answers
        });
    }

    private Optional<Local> local() {
        try {
            return Optional.of(Devices.local(session, defaultName(), clock));
        } catch (CryptoException e) {
            notice.error(LAN_FAILED, clock.instant());
        } catch (VaultException e) {
            notice.error(Messages.of(e.code()), clock.instant());
        }
        return Optional.empty();
    }

    private static String defaultName() {
        String user = System.getProperty("user.name", "");
        return user.isBlank() ? Devices.FALLBACK_NAME : "pm " + user;
    }

    private Optional<InetSocketAddress> address() {
        try {
            return Optional.of(LanAddress.parse(addressBox.getText().strip()));
        } catch (LanException e) {
            notice.error(BAD_ADDRESS, clock.instant());
            return Optional.empty();
        }
    }

    private SasPrompt sasPrompt(LanJob running) {
        return (sas, peerName, peerFingerprint) -> ask(running, PAIR_CODE + sas + GAP + "("
                + DisplaySafe.text(peerName) + GAP + peerFingerprint + ")  " + COMPARE);
    }

    /** The shared LAN state; a notice and empty if its directories cannot be used. */
    private Optional<LanState> lanState() {
        Optional<LanState> state = controller.lanState();
        if (state.isEmpty()) {
            notice.error(STATE_FAILED, clock.instant());
        }
        return state;
    }

    @SuppressWarnings("PMD.CloseResource") // CE-035: the listener is closed by stopListening when the step stops or cannot start
    private void pairHere() {
        Optional<LanState> state = lanState();
        if (state.isEmpty()) {
            return;
        }
        Optional<Local> opened = local();
        if (opened.isEmpty()) {
            return;
        }
        Local me = opened.get();
        Pairing.Listener listener;
        try {
            listener = Pairing.Listener.open(me, clock, controller.lanBind());
        } catch (IOException | CryptoException e) {
            me.close();
            notice.error(LAN_FAILED, clock.instant());
            return;
        }
        Optional<LanJob> started = start();
        if (started.isEmpty()) {
            stopListening(listener);
            me.close();
            return;
        }
        LanJob running = started.get();
        running.onStop(() -> stopListening(listener));
        Instant deadline = clock.instant().plus(Pairing.DEFAULT_WINDOW);
        Lockout lockout = state.get().lockout(clock.instant());
        refresh();
        status.setText(WAITING + LanAddress.show(listener.address(), listener.port()) + " until "
                + PAIRED_FORMAT.format(deadline));
        controller.background(() -> {
            Optional<PairedDevice> paired;
            try (me) {
                paired = listener.await(lockout, sasPrompt(running), deadline, code -> {
                    state.get().save(lockout, clock.instant()); // every failure counts for the next pairing too (SR-203)
                    controller.post(() -> notice.error(PAIR_FAILED + code.name(), clock.instant()));
                });
            } finally {
                stopListening(listener);
                state.get().save(lockout, clock.instant());
            }
            finished(running, () -> pinned(running, paired, state.get()));
        });
    }

    private void pairWith() {
        Optional<InetSocketAddress> peer = address();
        if (peer.isEmpty()) {
            return;
        }
        Optional<LanState> state = lanState();
        if (state.isEmpty()) {
            return;
        }
        Optional<Local> opened = local();
        if (opened.isEmpty()) {
            return;
        }
        Local me = opened.get();
        Optional<LanJob> started = start();
        if (started.isEmpty()) {
            me.close();
            return;
        }
        LanJob running = started.get();
        Lockout lockout = state.get().lockout(clock.instant());
        status.setText(CONNECTING);
        controller.background(() -> {
            Optional<PairedDevice> paired = Optional.empty();
            String failure = "";
            try (Local identity = me) {
                paired = Optional.of(Pairing.initiate(identity, peer.get(), clock, lockout, sasPrompt(running)));
            } catch (PairingException e) {
                failure = PAIR_FAILED + e.code().name();
            } catch (IOException | CryptoException e) {
                failure = UNREACHABLE;
            } finally {
                state.get().save(lockout, clock.instant());
            }
            Optional<PairedDevice> result = paired;
            String error = failure;
            finished(running, () -> {
                if (!error.isEmpty()) {
                    notice.error(error, clock.instant());
                }
                pinned(running, result, state.get());
            });
        });
    }

    /** On the GUI thread: pins a confirmed device, unless the step was stopped meanwhile. */
    @SuppressWarnings("PMD.CloseResource") // CE-035: the pinned record is the session's (ADR 0008)
    private void pinned(LanJob running, Optional<PairedDevice> paired, LanState state) {
        if (paired.isEmpty() || running.isStopped()) {
            status.setText(NOT_PAIRED);
            return;
        }
        try {
            TrustedDeviceRecord device = Devices.pin(session, paired.get(), clock.instant());
            state.pinned(device.rawPublicKey());
            audit("pair", device.title(), "PAIRED");
            refresh();
            status.setText(PAIRED + DisplaySafe.text(device.title()) + GAP + device.fingerprint());
        } catch (VaultException e) {
            notice.error(Messages.of(e.code()), clock.instant());
        }
    }

    private void receive() {
        Optional<InetSocketAddress> sender = address();
        if (sender.isEmpty()) {
            return;
        }
        Optional<Local> opened = local();
        if (opened.isEmpty()) {
            return;
        }
        Local me = opened.get();
        Optional<LanJob> started = start();
        if (started.isEmpty()) {
            me.close();
            return;
        }
        LanJob running = started.get();
        List<TrustedDeviceRecord> trusted = List.copyOf(shown);
        ReceivedShares applied = Devices.receivedShares(session, clock.instant());
        status.setText(CONNECTING);
        OfferPrompt prompt = (offer, fingerprint) -> ask(running, OFFER_FROM
                + trusted.stream().filter(d -> d.fingerprint().equals(fingerprint)).findFirst()
                        .map(d -> DisplaySafe.text(d.title())).orElse("?")
                + GAP + fingerprint + ": " + DisplaySafe.text(offer.summary()) + ". " + ACCEPT);
        controller.background(() -> {
            String outcome;
            try (Local identity = me) {
                Message.ShareOffer got = Receiving.receive(identity, sender.get(), trusted, clock, applied,
                        prompt, (offer, fingerprint, payload) -> applyOnGui(running, offer, fingerprint, payload));
                outcome = RECEIVED + DisplaySafe.text(got.summary());
            } catch (ShareException e) {
                outcome = NOT_RECEIVED + " (" + e.code().name() + ")";
            } catch (LanException e) {
                outcome = UNREACHABLE;
            }
            String text = outcome;
            finished(running, () -> {
                status.setText(text);
                controller.refreshDashboard();
            });
        });
    }

    /** From the worker: applies a received payload on the GUI thread, where the session lives. */
    private boolean applyOnGui(LanJob running, Message.ShareOffer offer, String fingerprint, byte[] payload) {
        try (SecretBytes copy = SecretBytes.copyOf(payload)) {
            return running.onGui(() -> {
                boolean ok = copy.apply(bytes -> SharePayload.apply(session, offer, fingerprint, bytes,
                        clock.instant()));
                if (ok) {
                    audit("share", "received", "RECEIVED");
                }
                return ok;
            });
        }
    }

    @SuppressWarnings("PMD.CloseResource") // CE-035: the device record is the session's (ADR 0008)
    private void askRemove() {
        int index = table.getSelectedRow();
        if (index < 0 || index >= shown.size()) {
            notice.error(SELECT_DEVICE, clock.instant());
            return;
        }
        if (!idleQuestions()) {
            return;
        }
        TrustedDeviceRecord device = shown.get(index);
        question(REMOVE_ASK + DisplaySafe.text(device.title()) + GAP + device.fingerprint(), yes -> {
            if (yes) {
                remove(device);
            }
        }, () -> false);
    }

    /**
     * Removes {@code device} (lan-share.md §8): audited first, then marked removed for every pm
     * process (so share windows already open to it, here or elsewhere, release nothing more), then
     * taken off the trust list in the vault. A failed step leaves the device as it was.
     */
    private void remove(TrustedDeviceRecord device) {
        Optional<LanState> state = lanState();
        if (state.isEmpty()) {
            return;
        }
        List<String> rotate = Devices.sharedWith(session, device).stream().map(DevicesWindow::itemLine).toList();
        String name = DisplaySafe.text(device.title());
        if (!audit("revoke", device.title(), "REMOVED")) {
            notice.error(AUDIT_FAILED, clock.instant());
            return;
        }
        byte[] key = device.rawPublicKey();
        try {
            state.get().removed(key);
        } catch (IOException e) {
            notice.error(STATE_FAILED, clock.instant());
            return;
        }
        try {
            Devices.remove(session, device);
        } catch (VaultException e) {
            state.get().pinned(key);
            notice.error(Messages.of(e.code()), clock.instant());
            return;
        }
        refresh();
        status.setText(REMOVED + name + ". " + (rotate.isEmpty() ? ROTATE_NONE : ROTATE + String.join(", ", rotate)));
    }

    private boolean audit(String kind, String subject, String decision) {
        return controller.host().audit(new AuditEvent(kind, Optional.empty(), Optional.of("TUI"),
                Optional.of(System.getProperty("user.name", "")), Optional.of(subject), Optional.empty(), -1,
                Optional.of(decision), Optional.of("pm devices")));
    }

    private static void stopListening(Pairing.Listener listener) {
        try {
            listener.close();
        } catch (IOException e) {
            // the port is closed or gone; either way it accepts nothing more
            Objects.requireNonNull(e);
        }
    }

    /** For tests: the status line. */
    String statusText() {
        return status.getText();
    }

    /** For tests: whether a question waits for Yes or No. */
    boolean asking() {
        return yesNo.isVisible();
    }

    /** For tests: queues a question the way a worker step asks one; the future gets its answer. */
    CompletableFuture<Boolean> queueQuestion(String text) {
        CompletableFuture<Boolean> answer = new CompletableFuture<>();
        question(text, answer::complete, answer::isDone);
        return answer;
    }

    /** For tests: answers the open question. */
    void answer(boolean yes) {
        answered(yes);
    }

    /** For tests: selects the {@code index}-th device. */
    void select(int index) {
        table.setSelectedRow(index);
    }

    /** For tests: types {@code text} into the address box. */
    void address(String text) {
        addressBox.setText(text);
    }

    /** For tests: the action buttons, by label. */
    void press(String label) {
        switch (label) {
            case PAIR_HERE -> pairHere();
            case PAIR_WITH -> pairWith();
            case RECEIVE_BUTTON -> receive();
            case REMOVE_BUTTON -> askRemove();
            default -> dismiss();
        }
    }

    /** One line of the rotate checklist. */
    static String itemLine(VaultRecord r) {
        return SharePayload.typeName(r) + ": " + DisplaySafe.text(r.title());
    }
}
