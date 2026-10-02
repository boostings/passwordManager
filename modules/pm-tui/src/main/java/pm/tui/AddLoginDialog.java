package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
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
 * catalogue message only (SR-501).
 */
final class AddLoginDialog {
    static final String TITLE = "Add login";
    static final String OK = "OK";
    static final String CANCEL = "Cancel";
    static final String TAGS_LABEL = "Tags (comma-separated):";

    private static final int FIELD_COLUMNS = 40;
    private static final int GRID_COLUMNS = 2;
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
    private final Label errorLabel = new Label("");

    AddLoginDialog(Session session, Clock clock, Runnable onSaved) {
        this.session = session;
        this.clock = clock;
        this.onSaved = onSaved;

        Panel grid = new Panel(new GridLayout(GRID_COLUMNS));
        grid.addComponent(new Label("Title:"));
        grid.addComponent(titleBox);
        grid.addComponent(new Label("Username:"));
        grid.addComponent(usernameBox);
        grid.addComponent(new Label("Password:"));
        grid.addComponent(passwordBox);
        grid.addComponent(new Label("URLs (comma-separated):"));
        grid.addComponent(urlsBox);
        grid.addComponent(new Label(TAGS_LABEL));
        grid.addComponent(tagsBox);

        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL));
        buttons.addComponent(new Button(OK, this::submit));
        buttons.addComponent(new Button(CANCEL, basicWindow::close));

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(grid);
        content.addComponent(buttons);
        content.addComponent(errorLabel);

        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(titleBox);
    }

    /** The Lanterna window. */
    Window window() {
        return basicWindow;
    }

    private static TextBox textBox() {
        return new TextBox(new TerminalSize(FIELD_COLUMNS, 1));
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

    /** Puts then saves {@code added}; on a save failure the record is taken back out. */
    private void store(LoginRecord added) {
        session.put(added);
        try {
            session.save();
        } catch (VaultException e) {
            session.remove(added.id());
            added.close();
            showError(Messages.of(e.code()), passwordBox);
            return;
        }
        basicWindow.close();
        onSaved.run();
    }

    private static List<String> list(TextBox box) {
        return COMMA.splitAsStream(box.getText()).map(String::strip).filter(s -> !s.isEmpty())
                .toList();
    }

    private void showError(String message, TextBox focus) {
        errorLabel.setText(message);
        basicWindow.setFocusedInteractable(focus);
    }
}
