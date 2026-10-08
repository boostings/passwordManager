package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LayoutData;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.WindowListenerAdapter;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import pm.crypto.SecretChars;
import pm.vault.VaultException;

/**
 * Unlock screen: one masked field, unlock with the passphrase or with the recovery key (ADR 0004).
 * The typed value is drained to {@code char[]} and the box cleared at once (ADR 0008); failures
 * show a fixed catalogue message only (SR-501). A value typed but never submitted is wiped by
 * {@link #clearInputs()} on quit (ADR 0008). The card carries the animated {@link Banner}.
 */
final class UnlockWindow implements InputForm {
    static final String TITLE = "Unlock vault";
    static final String UNLOCK = "Unlock";
    static final String RECOVERY = "Use recovery key";
    static final String QUIT = "Quit";
    static final String TAGLINE = "your passwords, on your machine";
    static final String PROMPT = "Passphrase or recovery key";
    static final String HINT = "⏎ unlock   ⇥ next   ^X quit";

    private static final int FIELD_COLUMNS = 40;
    private static final int SIDE_MARGIN = 3;

    private final TuiController controller;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final TextBox credentialBox = MaskedInput.newBox(FIELD_COLUMNS);
    private final Banner banner;
    private final Notice notice;

    UnlockWindow(TuiController controller) {
        this.controller = controller;
        PmTheme theme = controller.theme();
        banner = new Banner(theme);
        notice = new Notice(theme);

        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        buttons.addComponent(PmTheme.pill(UNLOCK, () -> submit(false)));
        buttons.addComponent(PmTheme.pill(RECOVERY, () -> submit(true)));
        buttons.addComponent(PmTheme.pill(QUIT, controller::quit));

        GridLayout layout = new GridLayout(1);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        layout.setBottomMarginSize(1);
        Panel content = new Panel(layout);
        content.addComponent(banner, centered());
        content.addComponent(dim(theme, TAGLINE), centered());
        content.addComponent(new EmptySpace());
        content.addComponent(new Label(PROMPT));
        content.addComponent(credentialBox);
        content.addComponent(new EmptySpace());
        content.addComponent(buttons, centered());
        content.addComponent(notice.label(), centered());
        content.addComponent(dim(theme, HINT), centered());

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(credentialBox);
        basicWindow.addWindowListener(new EnterUnlocks());
    }

    static Label dim(PmTheme theme, String text) {
        Label label = new Label(text);
        label.setForegroundColor(theme.color(PmTheme.Tone.DIM));
        return label;
    }

    static LayoutData centered() {
        return GridLayout.createLayoutData(
                GridLayout.Alignment.CENTER, GridLayout.Alignment.BEGINNING, true, false);
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

    @Override
    public void animate(Instant now) {
        banner.animate(now);
        notice.animate(now);
    }

    private void submit(boolean recoveryKey) {
        char[] typed = MaskedInput.drain(credentialBox);
        if (typed.length == 0) {
            showError(Messages.EMPTY_CREDENTIAL);
            return;
        }
        try (SecretChars credential = SecretChars.takeOwnership(typed)) {
            notice.busy(Messages.UNLOCKING, controller.clock().instant());
            controller.repaintNow(); // key derivation blocks this thread; show why first
            controller.unlock(credential, recoveryKey);
        } catch (VaultException e) {
            showError(Messages.of(e.code()));
        }
    }

    /** Enter in the box unlocks, as the hint says; a one-line box would only move the focus on. */
    private final class EnterUnlocks extends WindowListenerAdapter {
        @Override
        public void onInput(Window basePane, KeyStroke key, AtomicBoolean deliverEvent) {
            if (key.getKeyType() == KeyType.Enter && credentialBox.isFocused()) {
                deliverEvent.set(false);
                submit(false);
            }
        }
    }

    private void showError(String message) {
        notice.error(message, controller.clock().instant());
        basicWindow.setFocusedInteractable(credentialBox);
    }
}
