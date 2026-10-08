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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import pm.approval.AuditEvent;
import pm.crypto.CryptoException;
import pm.sharing.wire.Message;
import pm.tui.lan.BrowserWindow;
import pm.tui.lan.Devices;
import pm.tui.lan.LanAddress;
import pm.tui.lan.LanException;
import pm.tui.lan.LanState;
import pm.tui.lan.Local;
import pm.tui.lan.SendWindow;
import pm.tui.lan.SharePayload;
import pm.vault.VaultException;
import pm.vault.record.TrustedDeviceRecord;
import pm.vault.record.VaultRecord;

/**
 * Shares the selected item (M3.6, lan-share.md §6, ADR 0010 Amendment 2): to a paired device, or as
 * a one-time browser link. Nothing is offered before the user approves the summary here, the way
 * the TUI approves an {@code env run}; the approval is audited first and a failed audit refuses
 * the share. While the window is open its address, share id and closing time are shown with a
 * Revoke button; Esc, lock and quit revoke it too. A browser share shows the URL, the certificate
 * fingerprint and the residual-risk warnings.
 */
final class ShareDialog implements InputForm {
    static final String TITLE = "Share";
    static final String TO_DEVICE = "Send to device";
    static final String BROWSER = "Browser link";
    static final String APPROVE = "Approve";
    static final String DENY = "Deny";
    static final String REVOKE_BUTTON = "Revoke";
    static final String CLOSE = "Close";
    static final String TTL_LABEL = "Window (e.g. 10m):";
    static final String HINT = "⇥ next   esc close (revokes an open window)";
    static final String ITEM = "Item: ";
    static final String NO_DEVICES = "No paired devices: pair one on the Devices screen (Ctrl+D), or use a browser link.";
    static final String ASK_DEVICE = "Share %s with %s (%s) for %s?";
    static final String ASK_BROWSER = "Share %s as a browser link for %s?";
    static final String OPEN = "Open. On the other device choose Receive with ";
    static final String SHARE_ID = "Share id: ";
    static final String CLOSES = "Closes at ";
    static final String URL = "Link (holds the key; give it only to the recipient): ";
    static final String FINGERPRINT = "Certificate SHA-256 for the recipient to compare: ";
    static final String DELIVERED = "Delivered; the window is closed.";
    static final String EXPIRED = "The window expired; nothing was sent.";
    static final String REVOKED = "Revoked; nothing more will be sent.";
    static final String DENIED = "Not approved; nothing was shared.";
    static final String SELECT_DEVICE = "Select a paired device first.";
    static final String BAD_TTL = "The window is a whole number of s, m or h, at most 24h.";
    static final String NOT_SHAREABLE = "This item cannot be shared this way.";
    static final String AUDIT_FAILED = "The audit log could not be written, so nothing was shared.";
    static final String LAN_FAILED = "The network port or this device's key could not be used.";
    static final String BUSY = "A window is already open; revoke it or wait for it to close.";
    static final String DEVICE_GONE = "That device is no longer paired; nothing was shared.";
    static final String STATE_FAILED = "The owner-only LAN state directories could not be used, so nothing was shared.";

    private static final String[] COLUMNS = {"Device", "Fingerprint"};
    private static final String DEFAULT_TTL = "10m";
    private static final int TTL_COLUMNS = 8;
    private static final Duration POLL = Duration.ofMillis(100);
    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ROOT).withZone(ZoneOffset.UTC);

    private final TuiController controller;
    private final Session session;
    private final VaultRecord item;
    private final Clock clock;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final Table<String> table = new Table<>(COLUMNS);
    private final TextBox ttlBox = new TextBox(new TerminalSize(TTL_COLUMNS, 1), DEFAULT_TTL);
    private final Label status = new Label("");
    private final Panel approval = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
    private final Button approveButton = PmTheme.pill(APPROVE, () -> decided(true));
    private final Button revokeButton = PmTheme.pill(REVOKE_BUTTON, this::revoke);
    private final Notice notice;
    private final List<TrustedDeviceRecord> devices = new ArrayList<>();
    /** GUI-thread confined: what Approve does, and the open window's stop. */
    private Runnable approved = () -> { };
    private LanJob open;

    ShareDialog(TuiController controller, Session session, VaultRecord item) {
        this.controller = controller;
        this.session = session;
        this.item = item;
        this.clock = controller.clock();
        PmTheme theme = controller.theme();
        this.notice = new Notice(theme);
        status.setForegroundColor(theme.color(PmTheme.Tone.TEXT));
        ttlBox.setInputFilter(DisplaySafe.rejectUnsafe(
                () -> notice.error(Messages.UNSAFE_CHARACTER, clock.instant())));
        devices.addAll(Devices.trusted(session));
        TableModel<String> model = new TableModel<>(COLUMNS);
        devices.forEach(d -> model.addRow(DisplaySafe.text(d.title()), d.fingerprint()));
        table.setTableModel(model);

        Label summary = new Label(ITEM + DisplaySafe.text(SharePayload.summary(item)));
        summary.setForegroundColor(theme.color(PmTheme.Tone.BRIGHT));
        Panel ttl = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(1));
        ttl.addComponent(UnlockWindow.dim(theme, TTL_LABEL));
        ttl.addComponent(ttlBox);
        Panel actions = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        actions.addComponent(PmTheme.pill(TO_DEVICE, this::toDevice));
        actions.addComponent(PmTheme.pill(BROWSER, this::toBrowser));
        actions.addComponent(revokeButton);
        actions.addComponent(PmTheme.pill(CLOSE, this::dismiss));
        revokeButton.setVisible(false);
        approval.addComponent(approveButton);
        approval.addComponent(PmTheme.pill(DENY, () -> decided(false)));
        approval.setVisible(false);

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL).setSpacing(0));
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(summary);
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(devices.isEmpty() ? UnlockWindow.dim(theme, NO_DEVICES) : table);
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(ttl);
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(actions);
        content.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        content.addComponent(status);
        content.addComponent(approval);
        content.addComponent(notice.label());
        content.addComponent(UnlockWindow.dim(theme, HINT));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(content);
        basicWindow.addWindowListener(TuiController.closeOnEscape(this::dismiss));
    }

    @Override
    public Window window() {
        return basicWindow;
    }

    @Override
    public void clearInputs() {
        ttlBox.setText(DEFAULT_TTL);
        notice.clear();
    }

    @Override
    public void animate(Instant now) {
        notice.animate(now);
    }

    private void dismiss() {
        revoke();
        clearInputs();
        basicWindow.close();
    }

    private void revoke() {
        if (open != null) {
            controller.untrack(open);
            open.run();
            open = null;
        }
    }

    private void decided(boolean yes) {
        Runnable go = approved;
        approved = () -> { };
        approval.setVisible(false);
        if (yes) {
            go.run();
        } else {
            status.setText(DENIED);
        }
    }

    private void ask(String text, Runnable onApprove) {
        status.setText(text);
        approved = onApprove;
        approval.setVisible(true);
        basicWindow.setFocusedInteractable(approveButton);
    }

    private Optional<Duration> ttl() {
        try {
            return Optional.of(LanAddress.ttl(ttlBox.getText().strip()));
        } catch (LanException e) {
            notice.error(BAD_TTL, clock.instant());
            return Optional.empty();
        }
    }

    private boolean idle() {
        if (open != null && !open.isStopped()) {
            notice.error(BUSY, clock.instant());
            return false;
        }
        notice.clear();
        return true;
    }

    @SuppressWarnings("PMD.CloseResource") // CE-035: the device record is the session's (ADR 0008)
    private void toDevice() {
        int index = table.getSelectedRow();
        if (!idle()) {
            return;
        }
        if (index < 0 || index >= devices.size()) {
            notice.error(SELECT_DEVICE, clock.instant());
            return;
        }
        Optional<Duration> window = ttl();
        if (window.isEmpty()) {
            return;
        }
        TrustedDeviceRecord device = devices.get(index);
        ask(String.format(Locale.ROOT, ASK_DEVICE, DisplaySafe.text(SharePayload.summary(item)),
                DisplaySafe.text(device.title()), device.fingerprint(), window.get()),
                () -> sendToDevice(device, window.get()));
    }

    @SuppressWarnings("PMD.CloseResource") // CE-035: records are the session's; watch closes the window, which closes its Local
    private void sendToDevice(TrustedDeviceRecord device, Duration ttl) {
        Optional<LanState> state = controller.lanState();
        if (state.isEmpty()) {
            notice.error(STATE_FAILED, clock.instant());
            return;
        }
        if (!audit("approval", "ALLOWED_ONCE")) {
            notice.error(controller.host().auditFailure(AUDIT_FAILED), clock.instant());
            return;
        }
        SendWindow window;
        try (SharePayload.Prepared prepared = SharePayload.prepare(item)) {
            // The list on screen may be stale: re-read the device, and offer nothing to one removed since.
            Optional<TrustedDeviceRecord> current = Devices.recordShare(session, device, item.id(), clock.instant());
            if (current.isEmpty()) {
                notice.error(DEVICE_GONE, clock.instant());
                return;
            }
            Local self = Devices.local(session, Devices.FALLBACK_NAME, clock);
            window = SendWindow.open(self, current.get(), prepared, ttl, clock, controller.lanBind(),
                    state.get().stillTrusted());
        } catch (LanException e) {
            notice.error(switch (e.code()) {
                case NETWORK -> LAN_FAILED;
                case NO_SUCH_DEVICE -> DEVICE_GONE;
                default -> NOT_SHAREABLE;
            }, clock.instant());
            return;
        } catch (CryptoException e) {
            notice.error(LAN_FAILED, clock.instant());
            return;
        } catch (VaultException e) {
            notice.error(Messages.of(e.code()), clock.instant());
            return;
        }
        status.setText(OPEN + window.address() + "\n" + SHARE_ID + window.id() + "\n" + CLOSES
                + TIME.format(window.expires()));
        watch(window::await, window::revoke, window::close);
    }

    private void toBrowser() {
        if (!idle()) {
            return;
        }
        Optional<Duration> window = ttl();
        if (window.isEmpty()) {
            return;
        }
        if (SharePayload.kindOf(item) == Message.Kind.PROJECT) {
            notice.error(NOT_SHAREABLE, clock.instant());
            return;
        }
        ask(String.join("\n", BrowserWindow.WARNINGS) + "\n" + String.format(Locale.ROOT, ASK_BROWSER,
                DisplaySafe.text(SharePayload.summary(item)), window.get()), () -> sendToBrowser(window.get()));
    }

    @SuppressWarnings("PMD.CloseResource") // CE-035: watch closes the window when it ends
    private void sendToBrowser(Duration ttl) {
        if (!audit("approval", "ALLOWED_ONCE")) {
            notice.error(controller.host().auditFailure(AUDIT_FAILED), clock.instant());
            return;
        }
        BrowserWindow window;
        try {
            window = BrowserWindow.open(item, ttl, clock, controller.lanBind());
        } catch (LanException e) {
            notice.error(e.code() == LanException.Code.NETWORK ? LAN_FAILED : NOT_SHAREABLE, clock.instant());
            return;
        }
        status.setText(String.join("\n", BrowserWindow.WARNINGS) + "\n" + URL + window.url() + "\n" + FINGERPRINT
                + window.certificateFingerprint() + "\n" + SHARE_ID + window.id() + "\n" + CLOSES
                + TIME.format(window.expires()));
        watch(window::await, window::revoke, window::close);
    }

    /** A window's wait, as the worker needs it. */
    @FunctionalInterface
    interface Await {
        SendWindow.Outcome await(Duration timeout) throws InterruptedException;
    }

    /** Tracks an open window and waits for it on a worker; Revoke, Esc and lock stop it. */
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-037: re-asserting the interrupt flag is not thread creation
    private void watch(Await window, Runnable revoke, Runnable close) {
        LanJob job = new LanJob(controller);
        job.onStop(revoke);
        open = job;
        controller.track(job);
        revokeButton.setVisible(true);
        basicWindow.setFocusedInteractable(revokeButton);
        controller.background(() -> {
            SendWindow.Outcome outcome = SendWindow.Outcome.REVOKED;
            try {
                outcome = window.await(POLL);
                while (outcome == SendWindow.Outcome.OPEN) {
                    outcome = window.await(POLL);
                }
            } catch (InterruptedException e) {
                revoke.run();
                Thread.currentThread().interrupt();
            } finally {
                close.run();
            }
            SendWindow.Outcome ended = outcome;
            audit("share", ended.name());
            controller.post(() -> ended(job, ended));
        });
    }

    private void ended(LanJob job, SendWindow.Outcome outcome) {
        controller.untrack(job);
        if (job.equals(open)) {
            open = null;
        }
        revokeButton.setVisible(false);
        status.setText(switch (outcome) {
            case DELIVERED -> DELIVERED;
            case REVOKED -> REVOKED;
            default -> EXPIRED;
        });
    }

    private boolean audit(String kind, String decision) {
        return controller.host().audit(new AuditEvent(kind, Optional.empty(), Optional.of("TUI"),
                Optional.of(System.getProperty("user.name", "")), Optional.of(item.title()), Optional.empty(), -1,
                Optional.of(decision), Optional.of("pm share")));
    }

    /** For tests: the status text. */
    String statusText() {
        return status.getText();
    }

    /** For tests: selects the {@code index}-th device. */
    void select(int index) {
        table.setSelectedRow(index);
    }

    /** For tests: presses a button by label. */
    void press(String label) {
        switch (label) {
            case TO_DEVICE -> toDevice();
            case BROWSER -> toBrowser();
            case APPROVE -> decided(true);
            case DENY -> decided(false);
            case REVOKE_BUTTON -> revoke();
            default -> dismiss();
        }
    }

    /** For tests: whether a window is open. */
    boolean windowOpen() {
        return open != null;
    }
}
