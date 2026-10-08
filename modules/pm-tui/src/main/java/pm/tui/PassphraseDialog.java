package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import pm.approval.AuditEvent;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.VaultException;

/**
 * Changes the master passphrase (SR-130, ADR 0004 addendum), as {@code pm passphrase} does: the
 * current passphrase or the recovery key, then the new passphrase twice. The session checks the
 * current one against the vault file first, so an unattended unlocked app cannot be used to lock
 * its owner out. The change is written to the audit log afterwards like the CLI's ({@code slot},
 * {@code PASSPHRASE_CHANGED}); if that fails, the dialog says the change was made but not logged.
 * All three boxes are masked and emptied on OK, Cancel, lock and quit (ADR 0008). The key
 * derivation blocks the GUI thread for a moment; the notice says why first, as unlocking does.
 */
final class PassphraseDialog implements InputForm {
    static final String TITLE = "Change passphrase";
    static final String AUDIT_KIND = "slot";
    static final String AUDIT_DECISION = "PASSPHRASE_CHANGED";

    private final TuiController controller;
    private final Session session;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final TextBox currentBox = MaskedInput.newBox(FormLayout.FIELD_COLUMNS);
    private final TextBox freshBox = MaskedInput.newBox(FormLayout.FIELD_COLUMNS);
    private final TextBox repeatBox = MaskedInput.newBox(FormLayout.FIELD_COLUMNS);
    private final Notice notice;

    PassphraseDialog(TuiController controller, Session session) {
        this.controller = controller;
        this.session = session;
        PmTheme theme = controller.theme();
        this.notice = new Notice(theme);
        Panel grid = FormLayout.grid();
        FormLayout.row(grid, FormLayout.requiredLabel(theme, "Current or recovery key:"), currentBox);
        FormLayout.row(grid, FormLayout.requiredLabel(theme, "New passphrase:"), freshBox);
        FormLayout.row(grid, FormLayout.requiredLabel(theme, "Repeat new passphrase:"), repeatBox);
        FormLayout.dialog(basicWindow, theme, grid, Messages.OLD_BACKUPS, notice,
                List.of(PmTheme.pill(FormLayout.OK, this::submit), PmTheme.pill(FormLayout.CANCEL, this::dismiss)),
                currentBox, this::dismiss);
    }

    @Override
    public Window window() {
        return basicWindow;
    }

    /** Empties all three masked boxes (ADR 0008). */
    @Override
    public void clearInputs() {
        for (TextBox box : List.of(currentBox, freshBox, repeatBox)) {
            box.setText("");
        }
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

    private void submit() {
        try (SecretChars current = SecretChars.takeOwnership(MaskedInput.drain(currentBox));
                SecretChars fresh = SecretChars.takeOwnership(MaskedInput.drain(freshBox));
                SecretChars repeat = SecretChars.takeOwnership(MaskedInput.drain(repeatBox))) {
            problem(current, fresh, repeat).ifPresentOrElse(this::showError, () -> change(current, fresh));
        } catch (IllegalArgumentException e) {
            showError(Messages.INVALID_INPUT); // an unpaired surrogate in a passphrase
        }
    }

    /** What is wrong with the typed values before anything runs, if anything. */
    private static Optional<String> problem(SecretChars current, SecretChars fresh, SecretChars repeat) {
        if (current.length() == 0) {
            return Optional.of(Messages.CURRENT_REQUIRED);
        }
        if (fresh.length() == 0 || repeat.length() == 0) {
            return Optional.of(Messages.NEW_PASSPHRASE_REQUIRED);
        }
        try (SecretBytes first = fresh.toUtf8(); SecretBytes second = repeat.toUtf8()) {
            return first.equals(second) ? Optional.empty() : Optional.of(Messages.PASSPHRASE_MISMATCH); // constant time
        }
    }

    private void change(SecretChars current, SecretChars fresh) {
        notice.busy(Messages.CHANGING_PASSPHRASE, controller.clock().instant());
        controller.repaintNow();
        try {
            session.changePassphrase(current, fresh);
        } catch (VaultException e) {
            showError(switch (e.code()) {
                case WRONG_CREDENTIAL -> Messages.CURRENT_WRONG;
                case PASSPHRASE_CHANGED_UNCONFIRMED -> Messages.CHANGE_UNCONFIRMED;
                case PASSPHRASE_CHANGE_UNKNOWN -> Messages.CHANGE_UNKNOWN;
                default -> Messages.of(e.code());
            });
            return;
        }
        if (!audited()) {
            showError(controller.host().auditFailure(Messages.CHANGE_AUDIT_FAILED));
            return;
        }
        dismiss();
        controller.changed(Messages.PASSPHRASE_CHANGED);
    }

    /** The audit entry {@code pm passphrase} writes, from the TUI (approval-model §7). */
    private boolean audited() {
        return controller.host().audit(new AuditEvent(AUDIT_KIND, Optional.empty(), Optional.of("TUI"),
                Optional.of(System.getProperty("user.name", "")), Optional.empty(), Optional.empty(), -1,
                Optional.of(AUDIT_DECISION), Optional.of("pm tui")));
    }

    private void showError(String message) {
        notice.error(message, controller.clock().instant());
        basicWindow.setFocusedInteractable(currentBox);
    }
}
