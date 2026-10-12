package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import pm.vault.record.SshKeyRecord;

/**
 * Import an SSH private key file as an SSH key item, as {@code pm ssh import} does: the file is
 * read and parsed behind {@link SshActions#importKey} in {@code pm.cli} (SR-060), only an
 * unencrypted Ed25519 or ECDSA P-256 key is taken, and a key whose fingerprint is already stored
 * is refused. The path and title are not secret; the key text never reaches a text box.
 */
final class SshImportDialog implements InputForm {
    static final String TITLE = "Import SSH key";
    static final String DEFAULT_PATH = "~/.ssh/id_ed25519";
    static final String NOTE = "Copies the private key into the vault; the file is left as it is.";

    private final TuiController controller;
    private final Session session;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final TextBox pathBox = FormLayout.textBox();
    private final TextBox titleBox = FormLayout.textBox();
    private final Notice notice;

    SshImportDialog(TuiController controller, Session session) {
        this.controller = controller;
        this.session = session;
        PmTheme theme = controller.theme();
        this.notice = new Notice(theme);
        pathBox.setText(DEFAULT_PATH);
        pathBox.setCaretPosition(DEFAULT_PATH.length()); // typing edits the end, Backspace clears it

        Panel grid = FormLayout.grid();
        FormLayout.row(grid, FormLayout.requiredLabel(theme, "Key file:"), pathBox);
        FormLayout.row(grid, FormLayout.label(theme, "Title:"), titleBox);
        FormLayout.visibleTextOnly(() -> notice.error(Messages.UNSAFE_CHARACTER, controller.clock().instant()),
                pathBox, titleBox);
        FormLayout.dialog(basicWindow, theme, grid, NOTE, notice,
                List.of(PmTheme.pill("Import", this::submit), PmTheme.pill(FormLayout.CANCEL, this::dismiss)),
                pathBox, this::dismiss);
    }

    @Override
    public Window window() {
        return basicWindow;
    }

    @Override
    public void clearInputs() {
        pathBox.setText("");
        titleBox.setText("");
        notice.clear();
    }

    @Override
    public void animate(Instant now) {
        notice.animate(now);
    }

    private void dismiss() {
        clearInputs();
        basicWindow.close();
    }

    @SuppressWarnings("PMD.CloseResource") // CE-088: the session owns the key once added; RecordStore closes a refused one
    private void submit() {
        String path = pathBox.getText().strip();
        if (path.isEmpty()) {
            showError(Messages.KEY_FILE_REQUIRED, pathBox);
            return;
        }
        SshActions.Imported imported = controller.ssh().importKey(path, titleBox.getText());
        if (imported.problem().isPresent()) {
            showError(Messages.of(imported.problem().get()), pathBox);
            return;
        }
        SshKeyRecord item = imported.key().orElseThrow();
        String fingerprint = item.fingerprint(); // public SHA256 fingerprint, as pm ssh import compares it
        boolean duplicate = session.records().stream().filter(SshKeyRecord.class::isInstance)
                .map(SshKeyRecord.class::cast).anyMatch(stored -> stored.fingerprint().equals(fingerprint));
        if (duplicate) {
            item.close();
            showError(Messages.SSH_KEY_EXISTS, pathBox);
            return;
        }
        Optional<String> failure;
        try {
            failure = RecordStore.add(session, item);
        } catch (IllegalStateException e) {
            showError(Messages.INVALID_INPUT, pathBox);
            return;
        }
        if (failure.isPresent()) {
            showError(failure.get(), pathBox);
            return;
        }
        dismiss();
        controller.changed(imported.sharedFile() ? Messages.SSH_SAVED_SHARED_FILE : Messages.SSH_SAVED);
    }

    private void showError(String message, TextBox focus) {
        notice.error(message, controller.clock().instant());
        basicWindow.setFocusedInteractable(focus);
    }
}
