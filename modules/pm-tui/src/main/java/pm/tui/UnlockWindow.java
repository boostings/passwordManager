package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import java.util.List;
import pm.crypto.SecretChars;
import pm.vault.VaultException;

/**
 * Unlock screen: one masked field, unlock with the passphrase or with the recovery key (ADR 0004).
 * The typed value is drained to {@code char[]} and the box cleared at once (ADR 0008); failures
 * show a fixed catalogue message only (SR-501). A value typed but never submitted is wiped by
 * {@link #clearInputs()} on quit (ADR 0008).
 */
final class UnlockWindow implements InputForm {
    static final String TITLE = "Unlock vault";
    static final String UNLOCK = "Unlock";
    static final String RECOVERY = "Use recovery key";
    static final String QUIT = "Quit";

    private static final int FIELD_COLUMNS = 40;

    private final TuiController controller;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final TextBox credentialBox = MaskedInput.newBox(FIELD_COLUMNS);
    private final Label errorLabel = new Label("");

    UnlockWindow(TuiController controller) {
        this.controller = controller;
        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL));
        buttons.addComponent(new Button(UNLOCK, () -> submit(false)));
        buttons.addComponent(new Button(RECOVERY, () -> submit(true)));
        buttons.addComponent(new Button(QUIT, controller::quit));

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(new Label("Passphrase or recovery key:"));
        content.addComponent(credentialBox);
        content.addComponent(buttons);
        content.addComponent(errorLabel);

        basicWindow.setHints(List.of(Window.Hint.CENTERED));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(credentialBox);
    }

    /** The Lanterna window. */
    @Override
    public Window window() {
        return basicWindow;
    }

    /** Empties the masked credential box (ADR 0008). */
    @Override
    public void clearInputs() {
        credentialBox.setText("");
    }

    private void submit(boolean recoveryKey) {
        char[] typed = MaskedInput.drain(credentialBox);
        if (typed.length == 0) {
            showError(Messages.EMPTY_CREDENTIAL);
            return;
        }
        try (SecretChars credential = SecretChars.takeOwnership(typed)) {
            controller.unlock(credential, recoveryKey);
        } catch (VaultException e) {
            showError(Messages.of(e.code()));
        }
    }

    private void showError(String message) {
        errorLabel.setText(message);
        basicWindow.setFocusedInteractable(credentialBox);
    }
}
