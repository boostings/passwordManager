package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Component;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;

/**
 * Add-login dialog: title, username, masked password, comma-separated URLs and tags. OK runs
 * {@link Session#put} then {@link Session#save}; the password goes {@code char[]} to
 * {@link SecretChars} to {@link SecretBytes} without a {@code String} (ADR 0008). Failures show a
 * catalogue message only (SR-501). The visible fields refuse control and formatting characters as
 * they are typed (SR-501), and every box, masked or not, is emptied on OK, Cancel, lock and quit
 * (ADR 0008, SR-504).
 */
final class AddLoginDialog implements InputForm {
    static final String TITLE = "Add login";
    static final String OK = "OK";
    static final String CANCEL = "Cancel";
    static final String TAGS_LABEL = "Tags (comma-separated):";
    static final String REQUIRED = " *";
    static final String HINT = "⇥ next field   esc cancel";

    private static final int FIELD_COLUMNS = 40;
    private static final int GRID_COLUMNS = 2;
    private static final int SIDE_MARGIN = 3;
    private static final Pattern COMMA = Pattern.compile(",");

    private final Session session;
    private final Clock clock;
    private final Runnable onSaved;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final TextBox titleBox = textBox();
    private final TextBox usernameBox = textBox();
    private final TextBox passwordBox = MaskedInput.newBox(FIELD_COLUMNS);
    private final TextBox urlsBox = textBox();
    private final TextBox tagsBox = textBox();
    private final Notice notice;

    AddLoginDialog(Session session, Clock clock, PmTheme theme, Runnable onSaved) {
        this.session = session;
        this.clock = clock;
        this.onSaved = onSaved;
        this.notice = new Notice(theme);

        GridLayout layout = new GridLayout(GRID_COLUMNS);
        layout.setHorizontalSpacing(2);
        layout.setVerticalSpacing(1);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        Panel grid = new Panel(layout);
        Panel titleLabel = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(0));
        titleLabel.addComponent(UnlockWindow.dim(theme, "Title:"));
        Label required = new Label(REQUIRED);
        required.setForegroundColor(theme.color(PmTheme.Tone.RED));
        titleLabel.addComponent(required);
        addRow(grid, titleLabel, titleBox);
        addRow(grid, UnlockWindow.dim(theme, "Username:"), usernameBox);
        addRow(grid, UnlockWindow.dim(theme, "Password:"), passwordBox);
        addRow(grid, UnlockWindow.dim(theme, "URLs (comma-separated):"), urlsBox);
        addRow(grid, UnlockWindow.dim(theme, TAGS_LABEL), tagsBox);
        for (TextBox visible : List.of(titleBox, usernameBox, urlsBox, tagsBox)) {
            visible.setInputFilter(DisplaySafe.rejectUnsafe(
                    () -> notice.error(Messages.UNSAFE_CHARACTER, clock.instant())));
        }

        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        buttons.addComponent(PmTheme.pill(OK, this::submit));
        buttons.addComponent(PmTheme.pill(CANCEL, this::dismiss));

        GridLayout footerLayout = new GridLayout(1);
        footerLayout.setLeftMarginSize(SIDE_MARGIN);
        footerLayout.setRightMarginSize(SIDE_MARGIN);
        footerLayout.setBottomMarginSize(1);
        Panel footer = new Panel(footerLayout);
        footer.addComponent(new EmptySpace());
        footer.addComponent(buttons, UnlockWindow.centered());
        footer.addComponent(notice.label(), UnlockWindow.centered());
        footer.addComponent(UnlockWindow.dim(theme, HINT), UnlockWindow.centered());

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(grid);
        content.addComponent(footer, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(titleBox);
        basicWindow.addWindowListener(TuiController.closeOnEscape(this::dismiss));
    }

    private static void addRow(Panel grid, Component label, TextBox box) {
        grid.addComponent(label, GridLayout.createLayoutData(
                GridLayout.Alignment.END, GridLayout.Alignment.CENTER));
        grid.addComponent(box);
    }

    /** The Lanterna window. */
    @Override
    public Window window() {
        return basicWindow;
    }

    /**
     * Empties every field, including the masked password box (ADR 0008). Lanterna keeps text as
     * immutable {@code String}s, so this drops the dialog's reference; it cannot zero the String.
     */
    @Override
    public void clearInputs() {
        for (TextBox box : List.of(titleBox, usernameBox, passwordBox, urlsBox, tagsBox)) {
            box.setText("");
        }
        notice.clear();
    }

    @Override
    public void animate(Instant now) {
        notice.animate(now);
    }

    private static TextBox textBox() {
        return new TextBox(new TerminalSize(FIELD_COLUMNS, 1));
    }

    /** Cancel: wipes the fields, then closes (ADR 0008). */
    private void dismiss() {
        clearInputs();
        basicWindow.close();
    }

    private void submit() {
        String title = titleBox.getText().strip();
        if (title.isEmpty()) {
            showError(Messages.TITLE_REQUIRED, titleBox);
            return;
        }
        try (SecretChars typed = SecretChars.takeOwnership(MaskedInput.drain(passwordBox))) {
            storeNew(title, typed.toUtf8());
        } catch (IllegalArgumentException e) {
            showError(Messages.INVALID_INPUT, passwordBox); // unpaired surrogate in the password
        }
    }

    /** Builds the login around {@code passwordBytes}, zeroing it if a field is rejected. */
    private void storeNew(String title, SecretBytes passwordBytes) {
        Instant now = clock.instant();
        try {
            store(new LoginRecord(UUID.randomUUID(), title, usernameBox.getText().strip(),
                    passwordBytes, list(urlsBox), "", list(tagsBox), now, now, now));
        } catch (IllegalArgumentException e) {
            passwordBytes.close();
            showError(Messages.INVALID_INPUT, titleBox);
        }
    }

    /**
     * Puts then saves {@code added}. If {@code put} throws, the record's password is zeroed and
     * an {@link IllegalStateException} wrapping the failure propagates; on a save failure the record is taken back out and zeroed (ADR
     * 0008, SR-501).
     */
    private void store(LoginRecord added) {
        try {
            session.put(added);
        } catch (RuntimeException e) {
            added.close();
            throw new IllegalStateException("session put failed", e); // fixed text only (SR-501)
        }
        try {
            session.save();
        } catch (VaultException e) {
            session.remove(added.id());
            added.close();
            showError(Messages.of(e.code()), passwordBox);
            return;
        }
        clearInputs();
        basicWindow.close();
        onSaved.run();
    }

    private static List<String> list(TextBox box) {
        return COMMA.splitAsStream(box.getText()).map(String::strip).filter(s -> !s.isEmpty())
                .toList();
    }

    private void showError(String message, TextBox focus) {
        notice.error(message, clock.instant());
        basicWindow.setFocusedInteractable(focus);
    }
}
