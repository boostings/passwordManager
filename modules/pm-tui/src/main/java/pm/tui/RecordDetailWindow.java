package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
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
 * never read: reveal and clipboard copy are out of scope for M1 (planned for M4, SR-503).
 */
final class RecordDetailWindow {
    static final String CLOSE = "Close";

    private static final int GRID_COLUMNS = 2;

    private final BasicWindow basicWindow;

    RecordDetailWindow(VaultRecord shownRecord) {
        basicWindow = new BasicWindow(shownRecord.title());
        Panel grid = new Panel(new GridLayout(GRID_COLUMNS));
        for (List<String> field : fields(shownRecord)) {
            grid.addComponent(new Label(field.get(0)));
            grid.addComponent(new Label(field.get(1)));
        }
        Button close = new Button(CLOSE, basicWindow::close);
        grid.addComponent(close);

        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(grid);
        basicWindow.setFocusedInteractable(close);
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
