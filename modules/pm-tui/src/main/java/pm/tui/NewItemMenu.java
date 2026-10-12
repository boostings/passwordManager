package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Window;
import java.util.List;

/**
 * What Ctrl+N adds (M7.15): a login, a Wi-Fi network or an imported SSH key, each through its own
 * form. Passkeys and projects cannot be typed in: v1 is not a passkey authenticator (ADR 0016
 * addendum), and a project's variables come from {@code pm env import} in its folder, so those two
 * choices say so instead.
 */
final class NewItemMenu {
    static final String TITLE = "New item";
    static final String LOGIN = "Login (website or app password)";
    static final String WIFI = "Wi-Fi network";
    static final String SSH = "SSH key (import a key file)";
    static final String PASSKEY = "Passkey";
    static final String PROJECT = "Project secrets (.env)";
    static final String CLOSE = "Close";
    static final String PASSKEY_INFO = "Not in this version: pm does not yet sign in to websites with passkeys"
            + " (ADR 0016). Save the site as a login for now.";
    static final String PROJECT_INFO = "In the project's folder run: pm env import .env  (pm env run starts a"
            + " program with them).";
    private static final int INFO_COLUMNS = 44;

    private final TuiController controller;
    private final Session session;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final Label info = new Label("");

    NewItemMenu(TuiController controller, Session session) {
        this.controller = controller;
        this.session = session;
        PmTheme theme = controller.theme();
        info.setForegroundColor(theme.color(PmTheme.Tone.TEXT));

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(new EmptySpace());
        Button first = PmTheme.pill(LOGIN, this::openLogin);
        for (Button b : List.of(first, PmTheme.pill(WIFI, this::openWifi), PmTheme.pill(SSH, this::openSsh),
                PmTheme.pill(PASSKEY, () -> explain(PASSKEY_INFO)), PmTheme.pill(PROJECT, () -> explain(PROJECT_INFO)),
                PmTheme.pill(CLOSE, basicWindow::close))) {
            content.addComponent(b, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));
        }
        content.addComponent(info);
        content.addComponent(UnlockWindow.dim(theme, " ↑↓ choose   ⏎ open   esc close "),
                LinearLayout.createLayoutData(LinearLayout.Alignment.Center));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(Padded.of(content));
        basicWindow.setFocusedInteractable(first);
        basicWindow.addWindowListener(TuiController.closeOnEscape(basicWindow::close));
    }

    /** The Lanterna window. */
    Window window() {
        return basicWindow;
    }

    void openLogin() {
        basicWindow.close();
        controller.showForm(LoginDialog.add(controller, session));
    }

    void openWifi() {
        basicWindow.close();
        controller.openWifiAdd();
    }

    void openSsh() {
        basicWindow.close();
        controller.showForm(new SshImportDialog(controller, session));
    }

    private void explain(String text) {
        info.setText("\n" + Padded.wrap(text, INFO_COLUMNS));
    }
}
