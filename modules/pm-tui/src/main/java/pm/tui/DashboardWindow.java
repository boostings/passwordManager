package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.table.Table;
import com.googlecode.lanterna.gui2.table.TableModel;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import pm.vault.record.LoginRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * Dashboard: record table (Type | Title | Username/SSID | Updated) filtered live by a search box
 * through {@link Session#search(String)}, and a "Locked in m:ss" status bar (SR-504). Only
 * non-secret fields ever reach the table (SR-503, ADR 0008).
 */
final class DashboardWindow {
    static final String TITLE = "Vault";
    static final String ADD_LOGIN = "Add login";
    static final String LOCK = "Lock";
    static final String QUIT = "Quit";
    private static final String[] COLUMNS = {"Type", "Title", "Username/SSID", "Updated"};

    private static final int SEARCH_COLUMNS = 40;
    private static final DateTimeFormatter UPDATED_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.ROOT).withZone(ZoneOffset.UTC);

    private final TuiController controller;
    private final Session session;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final TextBox searchBox = new TextBox(new TerminalSize(SEARCH_COLUMNS, 1));
    private final Table<String> table = new Table<>(COLUMNS);
    private final Label statusLabel = new Label("");
    private final List<VaultRecord> shown = new ArrayList<>();

    DashboardWindow(TuiController controller, Session session) {
        this.controller = controller;
        this.session = session;

        Panel search = new Panel(new LinearLayout(Direction.HORIZONTAL));
        search.addComponent(new Label("Search:"));
        search.addComponent(searchBox);
        searchBox.setTextChangeListener((text, byUser) -> refresh(text));
        table.setSelectAction(this::openSelected);

        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL));
        buttons.addComponent(new Button(ADD_LOGIN, this::openAddLogin));
        buttons.addComponent(new Button(LOCK, controller::lock));
        buttons.addComponent(new Button(QUIT, controller::quit));

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(search);
        content.addComponent(table);
        content.addComponent(buttons);
        content.addComponent(statusLabel);

        basicWindow.setHints(List.of(Window.Hint.EXPANDED));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(searchBox);
        refresh("");
    }

    /** The Lanterna window. */
    Window window() {
        return basicWindow;
    }

    /** Sets the status bar text. */
    void setStatus(String text) {
        if (!text.equals(statusLabel.getText())) {
            statusLabel.setText(text);
        }
    }

    /** Reloads the table: all records for a blank query, otherwise {@code session.search(query)}. */
    void refresh(String query) {
        List<VaultRecord> records = query.isBlank() ? session.records() : session.search(query.strip());
        shown.clear();
        shown.addAll(records);
        TableModel<String> model = new TableModel<>(COLUMNS);
        records.stream().map(DashboardWindow::row).forEach(model::addRow);
        table.setTableModel(model);
    }

    /** Non-secret table cells for {@code r}. */
    static List<String> row(VaultRecord r) {
        return List.of(typeName(r), r.title(), account(r), UPDATED_FORMAT.format(r.updated()));
    }

    /** Display name of the record type. */
    static String typeName(VaultRecord r) {
        if (r instanceof LoginRecord) {
            return "Login";
        } else if (r instanceof WifiRecord) {
            return "Wi-Fi";
        } else if (r instanceof SshKeyRecord) {
            return "SSH key";
        }
        return "Project";
    }

    /** Username for logins, SSID for Wi-Fi, empty otherwise. Never a secret field. */
    private static String account(VaultRecord r) {
        if (r instanceof LoginRecord) {
            return LoginRecord.class.cast(r).username();
        } else if (r instanceof WifiRecord) {
            return WifiRecord.class.cast(r).ssid();
        }
        return "";
    }

    private void openSelected() {
        int index = table.getSelectedRow();
        if (index >= 0 && index < shown.size()) {
            controller.show(new RecordDetailWindow(shown.get(index)).window());
        }
    }

    private void openAddLogin() {
        controller.show(new AddLoginDialog(session, controller.clock(),
                () -> refresh(searchBox.getText())).window());
    }
}
