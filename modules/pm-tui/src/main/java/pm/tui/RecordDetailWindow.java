package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Window;
import java.util.List;
import pm.vault.record.LoginRecord;
import pm.vault.record.ProjectRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * Read-only record detail. Secret fields are always shown as {@link Messages#SECRET_MASK} and are
 * never read: reveal and clipboard copy are out of scope for M1 (planned for M4, SR-503). The
 * window title and every label pass through {@link DisplaySafe#text(String)} (SR-501).
 */
final class RecordDetailWindow {
    static final String CLOSE = "Close";
    static final String HINT = "esc close";

    private static final String TYPE_LABEL = "Type:";
    private static final int GRID_COLUMNS = 2;
    private static final int SIDE_MARGIN = 3;
    private static final int GAP = 3;

    private final BasicWindow basicWindow;

    RecordDetailWindow(VaultRecord shownRecord, PmTheme theme) {
        basicWindow = new BasicWindow(DisplaySafe.text(shownRecord.title()));
        GridLayout layout = new GridLayout(GRID_COLUMNS);
        layout.setHorizontalSpacing(GAP);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        layout.setBottomMarginSize(1);
        Panel grid = new Panel(layout);
        for (List<String> field : fields(shownRecord)) {
            Label name = UnlockWindow.dim(theme, DisplaySafe.text(field.get(0)));
            grid.addComponent(name, GridLayout.createLayoutData(
                    GridLayout.Alignment.END, GridLayout.Alignment.BEGINNING));
            grid.addComponent(value(theme, field));
        }
        Button close = PmTheme.pill(CLOSE, basicWindow::close);
        grid.addComponent(new EmptySpace(), GridLayout.createHorizontallyFilledLayoutData(GRID_COLUMNS));
        grid.addComponent(UnlockWindow.dim(theme, HINT), GridLayout.createLayoutData(
                GridLayout.Alignment.END, GridLayout.Alignment.CENTER));
        grid.addComponent(close, GridLayout.createLayoutData(
                GridLayout.Alignment.END, GridLayout.Alignment.CENTER));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(grid);
        basicWindow.setFocusedInteractable(close);
        basicWindow.addWindowListener(TuiController.closeOnEscape(basicWindow::close));
    }

    /** The value cell: masked secrets recede, the type gets its color, the rest is plain text. */
    private static Label value(PmTheme theme, List<String> field) {
        String text = DisplaySafe.text(field.get(1));
        Label label = new Label(text);
        if (text.contains(Messages.SECRET_MASK)) {
            label.setForegroundColor(theme.color(PmTheme.Tone.MUTED));
        } else if (TYPE_LABEL.equals(field.get(0))) {
            label.setForegroundColor(theme.color(PmTheme.Tone.CYAN));
        } else {
            label.setForegroundColor(theme.color(PmTheme.Tone.BRIGHT));
        }
        return label;
    }

    /** The Lanterna window. */
    Window window() {
        return basicWindow;
    }

    /**
     * Label/value pairs; secret fields map to the mask without touching the secret. Dispatch uses
     * {@code Class.cast} rather than pattern bindings: PMD CloseResource reports every
     * {@code AutoCloseable} binding, and Error Prone rejects an instanceof followed by a cast.
     */
    static List<List<String>> fields(VaultRecord r) {
        if (r instanceof LoginRecord) {
            return loginFields(LoginRecord.class.cast(r));
        } else if (r instanceof WifiRecord) {
            return wifiFields(WifiRecord.class.cast(r));
        } else if (r instanceof SshKeyRecord) {
            return sshFields(SshKeyRecord.class.cast(r));
        }
        return projectFields(ProjectRecord.class.cast(r));
    }

    private static List<List<String>> loginFields(LoginRecord l) {
        return List.of(
                List.of("Type:", DashboardWindow.typeName(l)),
                List.of("Title:", l.title()),
                List.of("Username:", l.username()),
                List.of("Password:", Messages.SECRET_MASK),
                List.of("URLs:", String.join(", ", l.urls())),
                List.of("Tags:", String.join(", ", l.tags())));
    }

    private static List<List<String>> wifiFields(WifiRecord w) {
        return List.of(
                List.of("Type:", DashboardWindow.typeName(w)),
                List.of("Title:", w.title()),
                List.of("SSID:", w.ssid()),
                List.of("Security:", w.security()),
                List.of("Password:", Messages.SECRET_MASK));
    }

    private static List<List<String>> sshFields(SshKeyRecord k) {
        return List.of(
                List.of("Type:", DashboardWindow.typeName(k)),
                List.of("Title:", k.title()),
                List.of("Key type:", k.keyType()),
                List.of("Fingerprint:", k.fingerprint()),
                List.of("Private key:", Messages.SECRET_MASK),
                List.of("Hosts:", String.join(", ", k.hosts())));
    }

    private static List<List<String>> projectFields(ProjectRecord p) {
        return List.of(
                List.of("Type:", DashboardWindow.typeName(p)),
                List.of("Title:", p.title()),
                List.of("Path:", p.canonicalPath()),
                List.of("Git remote:", p.gitRemote()),
                List.of("Variables:", String.join(", ", p.variables().keySet().stream()
                        .sorted().map(name -> name + "=" + Messages.SECRET_MASK).toList())));
    }
}
