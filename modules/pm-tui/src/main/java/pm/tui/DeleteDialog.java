package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Window;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import pm.vault.VaultException;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;

/**
 * Asks before deleting an item, as {@code pm rm} does; Cancel has the focus. For an SSH key it
 * says that the key stays in a running ssh-agent. Delete takes the item out of the session, which
 * zeroes it (ADR 0008), and saves. If the save fails, the item is already gone from the session:
 * the dialog stays open to try again, and locking instead keeps the item, since the file still
 * holds it.
 */
final class DeleteDialog implements InputForm {
    static final String TITLE = "Delete item";
    static final String DELETE = "Delete";
    static final String CANCEL = "Cancel";

    private final TuiController controller;
    private final Session session;
    private final UUID id;
    private final Runnable onRemoved;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final Notice notice;

    DeleteDialog(TuiController controller, Session session, VaultRecord item, Runnable onRemoved) {
        this.controller = controller;
        this.session = session;
        this.id = item.id();
        this.onRemoved = onRemoved;
        PmTheme theme = controller.theme();
        this.notice = new Notice(theme);

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(new EmptySpace());
        Label question = new Label("Delete " + DashboardWindow.typeName(item) + " “"
                + DisplaySafe.text(item.title()) + "”?");
        question.setForegroundColor(theme.color(PmTheme.Tone.BRIGHT));
        content.addComponent(question);
        content.addComponent(UnlockWindow.dim(theme, Messages.DELETE_CANNOT_UNDO));
        if (item instanceof SshKeyRecord) {
            Label agent = new Label(Messages.DELETE_SSH_AGENT);
            agent.setForegroundColor(theme.color(PmTheme.Tone.AMBER));
            content.addComponent(agent);
        }
        content.addComponent(new EmptySpace());
        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        Button cancel = PmTheme.pill(CANCEL, basicWindow::close);
        buttons.addComponent(PmTheme.pill(DELETE, this::confirm));
        buttons.addComponent(cancel);
        content.addComponent(buttons, LinearLayout.createLayoutData(LinearLayout.Alignment.Center));
        content.addComponent(notice.label());
        content.addComponent(UnlockWindow.dim(theme, "⇥ next button   esc cancel"),
                LinearLayout.createLayoutData(LinearLayout.Alignment.Center));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(cancel);
        basicWindow.addWindowListener(TuiController.closeOnEscape(basicWindow::close));
    }

    @Override
    public Window window() {
        return basicWindow;
    }

    /** Nothing is typed here. */
    @Override
    public void clearInputs() {
        notice.clear();
    }

    @Override
    public void animate(Instant now) {
        notice.animate(now);
    }

    /** Removes (a retry finds it already removed) and saves. */
    private void confirm() {
        if (session.remove(id)) {
            onRemoved.run();
        }
        try {
            session.save();
        } catch (VaultException e) {
            controller.refreshDashboard();
            notice.error(Messages.DELETE_NOT_SAVED, controller.clock().instant());
            return;
        }
        basicWindow.close();
        controller.changed(Messages.DELETED);
    }
}
