package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Window;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;

/**
 * The dashboard's tools menu (Ctrl+T, plan.md §13 M4.4): the generator, the offline health view
 * and ssh-agent actions on the selected SSH key item. Each choice closes the menu and opens its
 * window through the controller, so forms are tracked and cleared on lock (ADR 0008).
 */
final class ToolsMenu {
    static final String TITLE = "Tools";
    static final String GENERATE = "Generate password";
    static final String HEALTH = "Password health";
    static final String SSH = "SSH agent (selected key)";
    static final String CLOSE = "Close";

    private final TuiController controller;
    private final Session session;
    private final Supplier<Optional<VaultRecord>> selected;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final Notice notice;

    ToolsMenu(TuiController controller, Session session, Supplier<Optional<VaultRecord>> selected) {
        this.controller = controller;
        this.session = session;
        this.selected = selected;
        PmTheme theme = controller.theme();
        this.notice = new Notice(theme);

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(new EmptySpace());
        Button first = PmTheme.pill(GENERATE, this::openGenerate);
        for (Button b : List.of(first, PmTheme.pill(HEALTH, this::openHealth), PmTheme.pill(SSH, this::openSsh),
                PmTheme.pill(CLOSE, basicWindow::close))) {
            content.addComponent(b, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));
        }
        content.addComponent(notice.label());
        content.addComponent(UnlockWindow.dim(theme, "↑↓ choose   ⏎ open   esc close"));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(first);
        basicWindow.addWindowListener(TuiController.closeOnEscape(basicWindow::close));
    }

    /** The Lanterna window. */
    Window window() {
        return basicWindow;
    }

    void openGenerate() {
        basicWindow.close();
        controller.showForm(new GenerateDialog(controller.theme(), controller.clock()));
    }

    void openHealth() {
        basicWindow.close();
        controller.show(new HealthWindow(session.records(), controller.clock(), controller.theme()).window());
    }

    void openSsh() {
        Optional<VaultRecord> record = selected.get().filter(SshKeyRecord.class::isInstance);
        if (record.isEmpty()) {
            notice.error(Messages.SELECT_SSH_KEY, controller.clock().instant());
            notice.animate(controller.clock().instant());
            return;
        }
        basicWindow.close();
        controller.show(new SshAgentDialog(SshKeyRecord.class.cast(record.get()), controller.ssh(),
                controller.theme()).window());
    }
}
