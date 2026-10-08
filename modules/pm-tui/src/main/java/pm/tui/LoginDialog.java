package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.record.LoginRecord;

/**
 * Add or edit a login: title, username, masked password, comma-separated URLs and tags. OK puts
 * the record and saves ({@link RecordStore}); the password goes {@code char[]} to
 * {@link SecretChars} to {@link SecretBytes} without a {@code String} (ADR 0008). Editing keeps the
 * password when its box is left empty, keeps the notes and the creation and last-used times, and
 * writes back a field shown with replacement characters (SR-501) only if the user changed it.
 * Failures show a catalogue message only (SR-501). The visible fields refuse control and
 * formatting characters as they are typed, and every box, masked or not, is emptied on OK, Cancel,
 * lock and quit (ADR 0008, SR-504).
 */
final class LoginDialog implements InputForm {
    static final String TITLE = "Add login";
    static final String EDIT_TITLE = "Edit login";
    static final String TAGS_LABEL = "Tags (comma-separated):";
    static final String KEEP_PASSWORD = "Leave the password empty to keep the current one.";

    private static final Pattern COMMA = Pattern.compile(",");
    private static final String LIST_JOIN = ", ";

    private final TuiController controller;
    private final Session session;
    private final Optional<LoginRecord> editing;
    private final BasicWindow basicWindow;
    private final TextBox titleBox = FormLayout.textBox();
    private final TextBox usernameBox = FormLayout.textBox();
    private final TextBox passwordBox = MaskedInput.newBox(FormLayout.FIELD_COLUMNS);
    private final TextBox urlsBox = FormLayout.textBox();
    private final TextBox tagsBox = FormLayout.textBox();
    private final Notice notice;

    private LoginDialog(TuiController controller, Session session, Optional<LoginRecord> editing) {
        this.controller = controller;
        this.session = session;
        this.editing = editing;
        PmTheme theme = controller.theme();
        this.notice = new Notice(theme);
        basicWindow = new BasicWindow(editing.isPresent() ? EDIT_TITLE : TITLE);

        Panel grid = FormLayout.grid();
        FormLayout.row(grid, FormLayout.requiredLabel(theme, "Title:"), titleBox);
        FormLayout.row(grid, FormLayout.label(theme, "Username:"), usernameBox);
        FormLayout.row(grid, FormLayout.label(theme, editing.isPresent() ? "New password:" : "Password:"), passwordBox);
        FormLayout.row(grid, FormLayout.label(theme, "URLs (comma-separated):"), urlsBox);
        FormLayout.row(grid, FormLayout.label(theme, TAGS_LABEL), tagsBox);
        FormLayout.visibleTextOnly(() -> notice.error(Messages.UNSAFE_CHARACTER, controller.clock().instant()),
                titleBox, usernameBox, urlsBox, tagsBox);
        editing.ifPresent(this::fill);

        FormLayout.dialog(basicWindow, theme, grid, editing.isPresent() ? KEEP_PASSWORD : "", notice,
                List.of(PmTheme.pill(FormLayout.OK, this::submit), PmTheme.pill(FormLayout.CANCEL, this::dismiss)),
                titleBox, this::dismiss);
    }

    /** The dialog for a new login. */
    static LoginDialog add(TuiController controller, Session session) {
        return new LoginDialog(controller, session, Optional.empty());
    }

    /** The dialog that edits {@code old}. */
    static LoginDialog edit(TuiController controller, Session session, LoginRecord old) {
        return new LoginDialog(controller, session, Optional.of(old));
    }

    private void fill(LoginRecord old) {
        titleBox.setText(DisplaySafe.text(old.title()));
        usernameBox.setText(DisplaySafe.text(old.username()));
        urlsBox.setText(DisplaySafe.text(String.join(LIST_JOIN, old.urls())));
        tagsBox.setText(DisplaySafe.text(String.join(LIST_JOIN, old.tags())));
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

    /** Cancel: wipes the fields, then closes (ADR 0008). */
    private void dismiss() {
        clearInputs();
        basicWindow.close();
    }

    @SuppressWarnings("PMD.CloseResource") // CE-088: build owns the password (it closes it or the record does)
    private void submit() {
        String title = FormLayout.edited(titleBox, editing.map(LoginRecord::title));
        if (title.isEmpty()) {
            showError(Messages.TITLE_REQUIRED, titleBox);
            return;
        }
        try (SecretChars typed = SecretChars.takeOwnership(MaskedInput.drain(passwordBox))) {
            SecretBytes password = typed.length() == 0 && editing.isPresent()
                    ? editing.get().password().apply(SecretBytes::copyOf)
                    : typed.toUtf8();
            build(title, password);
        } catch (IllegalArgumentException e) {
            showError(Messages.INVALID_INPUT, passwordBox); // unpaired surrogate in the password
        }
    }

    /** Builds the login around {@code password}, zeroing it if a field is rejected, and stores it. */
    private void build(String title, SecretBytes password) {
        Instant now = controller.clock().instant();
        String username = FormLayout.edited(usernameBox, editing.map(LoginRecord::username));
        List<String> urls = list(urlsBox, editing.map(LoginRecord::urls));
        List<String> tags = list(tagsBox, editing.map(LoginRecord::tags));
        Optional<String> failure;
        try {
            failure = editing.isPresent()
                    ? RecordStore.replace(session, editing.get(), new LoginRecord(editing.get().id(), title, username,
                            password, urls, editing.get().notes(), tags, editing.get().created(), now,
                            editing.get().lastUsed()))
                    : RecordStore.add(session, new LoginRecord(UUID.randomUUID(), title, username, password, urls,
                            "", tags, now, now, now));
        } catch (IllegalArgumentException e) {
            password.close();
            showError(Messages.INVALID_INPUT, titleBox);
            return;
        }
        if (failure.isPresent()) {
            showError(failure.get(), passwordBox);
            return;
        }
        dismiss();
        controller.changed(editing.isPresent() ? Messages.CHANGES_SAVED : Messages.SAVED);
    }

    /** The box's comma-separated items; when editing and unchanged, the stored list itself. */
    private static List<String> list(TextBox box, Optional<List<String>> old) {
        Optional<String> joined = old.map(values -> String.join(LIST_JOIN, values));
        String typed = FormLayout.edited(box, joined);
        if (joined.isPresent() && joined.get().equals(typed)) {
            return old.get();
        }
        return COMMA.splitAsStream(typed).map(String::strip).filter(s -> !s.isEmpty()).toList();
    }

    private void showError(String message, TextBox focus) {
        notice.error(message, controller.clock().instant());
        basicWindow.setFocusedInteractable(focus);
    }
}
