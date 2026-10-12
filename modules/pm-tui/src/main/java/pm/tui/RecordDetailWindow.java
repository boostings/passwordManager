package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.WindowListenerAdapter;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import pm.crypto.SecretBoundary;
import pm.crypto.SecretBytes;
import pm.vault.record.LoginRecord;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.ProjectRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * A record's card (SR-503). Secret fields show {@link Messages#SECRET_MASK}. A login's or Wi-Fi
 * network's password can be revealed for {@link #REVEAL_FOR}, after which it is masked again, as it
 * is on Hide, Close, lock and quit; a password with control or invisible characters is never
 * revealed (m77-004). Copy puts it on the clipboard, which {@link ClipboardGuard} clears again.
 * Edit (logins and Wi-Fi networks), Share and Delete (any item) open their own dialogs. Each button
 * also answers to its first letter, and Ctrl+S shares, as on the dashboard. The window title and
 * every label pass through {@link DisplaySafe#text(String)} (SR-501).
 */
final class RecordDetailWindow implements InputForm {
    static final String CLOSE = "Close";
    static final String REVEAL = "Reveal";
    static final String HIDE = "Hide";
    static final String COPY = "Copy";
    static final String EDIT = "Edit";
    static final String DELETE = "Delete";
    static final String SHARE = "Share";
    static final String HINT_SECRET = "c copy   r reveal   e edit   s share   d delete   esc close";
    static final String HINT = "s share   d delete   esc close";
    /** How long a revealed password stays on screen. */
    static final Duration REVEAL_FOR = Duration.ofSeconds(15);

    private static final String TYPE_LABEL = "Type:";
    private static final String PASSWORD_LABEL = "Password:";
    private static final int GRID_COLUMNS = 2;
    private static final int SIDE_MARGIN = 3;
    private static final int GAP = 3;

    private final TuiController controller;
    private final VaultRecord shownRecord;
    private final PmTheme theme;
    private final BasicWindow basicWindow;
    private final Notice notice;
    private final List<Label> secretCells = new ArrayList<>();
    private final Button revealButton = PmTheme.pill(REVEAL, this::toggleReveal);
    private Instant revealedUntil;

    RecordDetailWindow(TuiController controller, VaultRecord shownRecord) {
        this.controller = controller;
        this.shownRecord = shownRecord;
        this.theme = controller.theme();
        this.notice = new Notice(theme);
        basicWindow = new BasicWindow(DisplaySafe.text(shownRecord.title()));
        GridLayout layout = new GridLayout(GRID_COLUMNS);
        layout.setHorizontalSpacing(GAP);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        Panel grid = new Panel(layout);
        for (List<String> field : fields(shownRecord)) {
            Label name = UnlockWindow.dim(theme, DisplaySafe.text(field.get(0)));
            grid.addComponent(name, GridLayout.createLayoutData(
                    GridLayout.Alignment.BEGINNING, GridLayout.Alignment.BEGINNING));
            Label value = value(theme, field);
            if (PASSWORD_LABEL.equals(field.get(0))) {
                secretCells.add(value);
            }
            // The values take the spare width, so the labels sit right beside them.
            grid.addComponent(value, GridLayout.createLayoutData(
                    GridLayout.Alignment.BEGINNING, GridLayout.Alignment.BEGINNING, true, false));
        }
        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        Button close = PmTheme.pill(CLOSE, this::closeCard);
        Button first = close;
        if (secret().isPresent()) {
            first = PmTheme.pill(COPY, this::copyPassword);
            buttons.addComponent(first);
            buttons.addComponent(revealButton);
            buttons.addComponent(PmTheme.pill(EDIT, this::openEdit));
        }
        buttons.addComponent(PmTheme.pill(SHARE, this::openShare));
        buttons.addComponent(PmTheme.pill(DELETE, this::askDelete));
        buttons.addComponent(close);
        // Buttons and hints sit below the field grid, not in it, so their width never widens the label column.
        GridLayout footerLayout = new GridLayout(1);
        footerLayout.setLeftMarginSize(SIDE_MARGIN);
        footerLayout.setRightMarginSize(SIDE_MARGIN);
        footerLayout.setBottomMarginSize(1);
        Panel footer = new Panel(footerLayout);
        footer.addComponent(buttons, GridLayout.createLayoutData(GridLayout.Alignment.END,
                GridLayout.Alignment.CENTER, true, false));
        footer.addComponent(notice.label(), GridLayout.createHorizontallyFilledLayoutData(1));
        footer.addComponent(UnlockWindow.dim(theme, secret().isPresent() ? HINT_SECRET : HINT),
                GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.CENTER, true, false));
        Panel card = new Panel(new LinearLayout(Direction.VERTICAL).setSpacing(1));
        card.addComponent(grid);
        card.addComponent(footer, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(card);
        basicWindow.setFocusedInteractable(first);
        basicWindow.addWindowListener(TuiController.closeOnEscape(this::closeCard));
        basicWindow.addWindowListener(new Letters());
    }

    /** The Lanterna window. */
    @Override
    public Window window() {
        return basicWindow;
    }

    /** Masks the password again: lock, idle lock and quit call this (ADR 0008). */
    @Override
    public void clearInputs() {
        mask();
        notice.clear();
    }

    /** Masks a revealed password once {@link #REVEAL_FOR} has passed. */
    @Override
    public void animate(Instant now) {
        notice.animate(now);
        if (revealedUntil != null && !now.isBefore(revealedUntil)) {
            mask();
        }
    }

    /** Whether the password is on screen, for tests. */
    boolean revealed() {
        return revealedUntil != null;
    }

    /** The password of a login or Wi-Fi network; empty for every other item. */
    private Optional<SecretBytes> secret() {
        if (shownRecord instanceof LoginRecord) {
            return Optional.of(LoginRecord.class.cast(shownRecord).password());
        } else if (shownRecord instanceof WifiRecord) {
            return Optional.of(WifiRecord.class.cast(shownRecord).password());
        }
        return Optional.empty();
    }

    @SuppressWarnings("PMD.CloseResource") // CE-088: the password is the session's record's (ADR 0008)
    private void toggleReveal() {
        if (revealedUntil != null) {
            mask();
            return;
        }
        Instant now = controller.clock().instant();
        SecretBytes stored = secret().orElseThrow();
        if (stored.length() == 0) {
            show(Messages.NO_PASSWORD.toCharArray(), now);
            return;
        }
        Optional<char[]> chars = DisplaySafe.revealable(stored);
        if (chars.isEmpty()) {
            notice.error(Messages.REVEAL_UNPRINTABLE, now);
            return;
        }
        show(chars.get(), now);
    }

    @SecretBoundary(reason = "Reveal: Lanterna 3.1.3 Labels hold their text only as immutable Strings, so the "
            + "revealed password is a String until it is masked again and the String is collected; the "
            + "char[] is zeroed here (ADR 0008, R-003)")
    private void show(char[] chars, Instant now) {
        try {
            String shown = String.valueOf(chars);
            secretCells.forEach(cell -> {
                cell.setText(shown);
                cell.setForegroundColor(theme.color(PmTheme.Tone.BRIGHT));
            });
        } finally {
            Arrays.fill(chars, '\0');
        }
        revealedUntil = now.plus(REVEAL_FOR);
        revealButton.setLabel(HIDE);
    }

    private void mask() {
        secretCells.forEach(cell -> {
            cell.setText(Messages.SECRET_MASK);
            cell.setForegroundColor(theme.color(PmTheme.Tone.MUTED));
        });
        revealedUntil = null;
        revealButton.setLabel(REVEAL);
    }

    @SuppressWarnings("PMD.CloseResource") // CE-088: the password is the session's record's (ADR 0008)
    private void copyPassword() {
        Instant now = controller.clock().instant();
        SecretBytes stored = secret().orElseThrow();
        if (stored.length() == 0) {
            notice.error(Messages.NOTHING_TO_COPY, now);
            return;
        }
        switch (controller.clipboard().copy(stored, now)) {
            case COPIED -> notice.done(Messages.copied(controller.clipboard().clearAfter()), now);
            case UNAVAILABLE -> notice.error(Messages.COPY_UNAVAILABLE, now);
            case FAILED -> notice.error(Messages.COPY_FAILED, now);
        }
    }

    private void openEdit() {
        closeCard();
        controller.openEdit(shownRecord);
    }

    private void openShare() {
        closeCard();
        controller.openShare(shownRecord);
    }

    /** The card closes as soon as the item is out of the session: its secrets are closed then. */
    private void askDelete() {
        controller.openDelete(shownRecord, this::closeCard);
    }

    private void closeCard() {
        clearInputs();
        basicWindow.close();
    }

    /** Letter shortcuts for the buttons; the card has no text box, so no letter is ever typed. */
    private final class Letters extends WindowListenerAdapter {
        @Override
        public void onInput(Window basePane, KeyStroke key, AtomicBoolean deliverEvent) {
            if (TuiController.isCtrl(key, 's')) {
                deliverEvent.set(false);
                openShare();
                return;
            }
            if (key.getKeyType() != KeyType.Character || key.isCtrlDown() || key.isAltDown()) {
                return;
            }
            boolean secret = secret().isPresent();
            Runnable action = switch (Character.toLowerCase(key.getCharacter())) {
                case 'c' -> secret ? RecordDetailWindow.this::copyPassword : null;
                case 'r' -> secret ? RecordDetailWindow.this::toggleReveal : null;
                case 'e' -> secret ? RecordDetailWindow.this::openEdit : null;
                case 's' -> RecordDetailWindow.this::openShare;
                case 'd' -> RecordDetailWindow.this::askDelete;
                default -> null;
            };
            if (action != null) {
                deliverEvent.set(false);
                action.run();
            }
        }
    }

    /** The value cell: masked secrets recede, the type gets its color, the rest is plain text. */
    private static Label value(PmTheme theme, List<String> field) {
        String text = DisplaySafe.text(field.get(1));
        Label label = new Label(text);
        if (text.contains(Messages.SECRET_MASK)) {
            label.setForegroundColor(theme.color(PmTheme.Tone.MUTED));
        } else if (TYPE_LABEL.equals(field.get(0))) {
            label.setForegroundColor(theme.color(PmTheme.Tone.CYAN));
        } else {
            label.setForegroundColor(theme.color(PmTheme.Tone.BRIGHT));
        }
        return label;
    }

    /**
     * Label/value pairs; secret fields map to the mask without touching the secret. Dispatch uses
     * {@code Class.cast} rather than pattern bindings: PMD CloseResource reports every
     * {@code AutoCloseable} binding, and Error Prone rejects an instanceof followed by a cast.
     */
    static List<List<String>> fields(VaultRecord r) {
        if (r instanceof LoginRecord) {
            return loginFields(LoginRecord.class.cast(r));
        } else if (r instanceof WifiRecord) {
            return wifiFields(WifiRecord.class.cast(r));
        } else if (r instanceof SshKeyRecord) {
            return sshFields(SshKeyRecord.class.cast(r));
        } else if (r instanceof PasskeyRecord) {
            return passkeyFields(PasskeyRecord.class.cast(r));
        }
        return projectFields(ProjectRecord.class.cast(r));
    }

    /** RP ID, account name and counter only: never the credential ID, user handle or key (ADR 0016). */
    private static List<List<String>> passkeyFields(PasskeyRecord p) {
        return List.of(
                List.of("Type:", DashboardWindow.typeName(p)),
                List.of("Title:", p.title()),
                List.of("Site:", p.rpId()),
                List.of("Account:", p.accountName()),
                List.of("Sign count:", Long.toString(p.signCount())));
    }

    private static List<List<String>> loginFields(LoginRecord l) {
        return List.of(
                List.of("Type:", DashboardWindow.typeName(l)),
                List.of("Title:", l.title()),
                List.of("Username:", l.username()),
                List.of(PASSWORD_LABEL, Messages.SECRET_MASK),
                List.of("URLs:", String.join(", ", l.urls())),
                List.of("Tags:", String.join(", ", l.tags())));
    }

    private static List<List<String>> wifiFields(WifiRecord w) {
        return List.of(
                List.of("Type:", DashboardWindow.typeName(w)),
                List.of("Title:", w.title()),
                List.of("SSID:", w.ssid()),
                List.of("Security:", w.security()),
                List.of(PASSWORD_LABEL, Messages.SECRET_MASK));
    }

    private static List<List<String>> sshFields(SshKeyRecord k) {
        return List.of(
                List.of("Type:", DashboardWindow.typeName(k)),
                List.of("Title:", k.title()),
                List.of("Key type:", k.keyType()),
                List.of("Fingerprint:", k.fingerprint()),
                List.of("Private key:", Messages.SECRET_MASK),
                List.of("Hosts:", String.join(", ", k.hosts())));
    }

    private static List<List<String>> projectFields(ProjectRecord p) {
        return List.of(
                List.of("Type:", DashboardWindow.typeName(p)),
                List.of("Title:", p.title()),
                List.of("Path:", p.canonicalPath()),
                List.of("Git remote:", p.gitRemote()),
                List.of("Variables:", String.join(", ", p.variables().keySet().stream()
                        .sorted().map(name -> name + "=" + Messages.SECRET_MASK).toList())));
    }
}
