package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.BorderLayout;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LayoutData;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.WindowListenerAdapter;
import com.googlecode.lanterna.gui2.table.Table;
import com.googlecode.lanterna.gui2.table.TableModel;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import pm.vault.record.DeviceRecord;
import pm.vault.record.LoginRecord;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * Full-screen dashboard: a header with the item count and the idle-lock countdown (SR-504), a
 * search box that filters the record table live through {@link Session#search(String)}, empty
 * states, and a footer of key hints with a toast slot. Only non-secret fields ever reach the
 * table (SR-503, ADR 0008), and each cell passes through {@link DisplaySafe#text(String)} first
 * (SR-501). Shortcuts: Ctrl+N add login, Ctrl+T tools (generator, health, ssh-agent; M4.4),
 * Ctrl+S share the selected item, Ctrl+D devices (M3.6), Ctrl+L lock, Esc clears the search; Ctrl+X quits
 * everywhere (see {@link TuiController}).
 */
final class DashboardWindow {
    static final String TITLE = "Vault";
    static final String BRAND = "◆ pm";
    static final String SEARCH_LABEL = "Search";
    static final List<List<String>> KEY_HINTS = List.of(
            List.of("↑↓", "select"), List.of("⏎", "open"), List.of("^N", "new login"),
            List.of("^T", "tools"), List.of("^S", "share"), List.of("^D", "devices"), List.of("^L", "lock"),
            List.of("esc", "clear search"), List.of("^X", "quit"));
    private static final String[] COLUMNS = {"Type", "Title", "Username/SSID", "Updated"};
    private static final String SEPARATOR = "  ·  ";
    private static final String CHECK = "✓ ";
    private static final String METER_CELL = "━";

    private static final int SEARCH_COLUMNS = 48;
    private static final int METER_CELLS = 16;
    private static final double HALF = 0.5;
    private static final double PULSE_DEPTH = 0.45;
    private static final Duration URGENT = Duration.ofSeconds(30);
    private static final Duration PULSE = Duration.ofSeconds(1);
    private static final Duration ROW_STAGGER = Duration.ofMillis(45);
    private static final Duration ROW_FADE = Duration.ofMillis(260);
    private static final Duration TOAST_LIFETIME = Duration.ofMillis(2800);
    private static final Duration TOAST_FADE = Duration.ofMillis(700);
    private static final long FRAME_MILLIS = 40;
    private static final DateTimeFormatter UPDATED_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.ROOT).withZone(ZoneOffset.UTC);

    private final TuiController controller;
    private final Session session;
    private final PmTheme theme;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final Strip header;
    private final Strip footer;
    private final TextBox searchBox = new TextBox(new TerminalSize(SEARCH_COLUMNS, 1));
    private final Table<String> table = new Table<>(COLUMNS);
    private final RecordCellRenderer cells;
    private final Panel emptyState = new Panel(new LinearLayout(Direction.VERTICAL));
    private final Label emptyTitle = new Label("");
    private final Label emptyHint = new Label("");
    private final List<VaultRecord> shown = new ArrayList<>();
    private int total;
    private final Instant revealStart;
    private boolean revealing = true;
    private Instant toastAt;
    private Instant now;

    DashboardWindow(TuiController controller, Session session) {
        this.controller = controller;
        this.session = session;
        this.theme = controller.theme();
        header = new Strip(theme.color(PmTheme.Tone.CARD));
        footer = new Strip(theme.color(PmTheme.Tone.CARD));
        cells = new RecordCellRenderer(theme);
        now = controller.clock().instant();
        revealStart = now;

        Panel search = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(1));
        search.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        search.addComponent(UnlockWindow.dim(theme, SEARCH_LABEL));
        search.addComponent(searchBox);
        searchBox.setTextChangeListener((text, byUser) -> refresh(text));
        searchBox.setInputFilter(DisplaySafe.rejectUnsafe(() -> { })); // SR-501: dropped silently

        table.setTableCellRenderer(cells);
        table.setTableHeaderRenderer(new RecordCellRenderer.Header());
        table.setSelectAction(this::openSelected);

        emptyTitle.setForegroundColor(theme.color(PmTheme.Tone.TEXT));
        emptyHint.setForegroundColor(theme.color(PmTheme.Tone.DIM));
        emptyState.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        emptyState.addComponent(emptyTitle, LinearLayout.createLayoutData(LinearLayout.Alignment.Center));
        emptyState.addComponent(emptyHint, LinearLayout.createLayoutData(LinearLayout.Alignment.Center));

        Panel top = new Panel(new LinearLayout(Direction.VERTICAL).setSpacing(0));
        top.addComponent(header, fill());
        top.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        top.addComponent(search);
        top.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        Panel body = new Panel(new LinearLayout(Direction.VERTICAL));
        body.addComponent(table, grow());
        body.addComponent(emptyState, fill());

        Panel content = new Panel(new BorderLayout());
        content.addComponent(top, BorderLayout.Location.TOP);
        content.addComponent(body, BorderLayout.Location.CENTER);
        content.addComponent(footer, BorderLayout.Location.BOTTOM);

        basicWindow.setTheme(theme.screen());
        basicWindow.setHints(List.of(Window.Hint.FULL_SCREEN, Window.Hint.NO_DECORATIONS));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(searchBox);
        basicWindow.addWindowListener(new Shortcuts());
        refresh("");
    }

    private static LayoutData fill() {
        return LinearLayout.createLayoutData(LinearLayout.Alignment.Fill);
    }

    private static LayoutData grow() {
        return LinearLayout.createLayoutData(LinearLayout.Alignment.Fill, LinearLayout.GrowPolicy.CanGrow);
    }

    /** The Lanterna window. */
    Window window() {
        return basicWindow;
    }

    /** Header plus footer text, for tests. */
    String barText() {
        return header.text() + "\n" + footer.text();
    }

    /** Reloads the table: all records for a blank query, otherwise {@code session.search(query)}. */
    void refresh(String query) {
        List<VaultRecord> all = session.records().stream().filter(r -> !DeviceRecord.isInternal(r)).toList();
        List<VaultRecord> records = query.isBlank() ? all : session.search(query.strip());
        total = all.size();
        shown.clear();
        shown.addAll(records);
        TableModel<String> model = new TableModel<>(COLUMNS);
        records.stream().map(DashboardWindow::row).forEach(model::addRow);
        table.setTableModel(model);

        boolean empty = records.isEmpty();
        table.setLayoutData(empty ? fill() : grow());
        emptyState.setVisible(empty);
        emptyTitle.setText(query.isBlank() ? Messages.EMPTY_VAULT : Messages.NO_MATCHES);
        emptyHint.setText(query.isBlank() ? Messages.EMPTY_VAULT_HINT : Messages.NO_MATCHES_HINT);
    }

    /**
     * Advances every animation to {@code at}: the header countdown and its draining meter, which
     * shifts green to amber to red and pulses in the last 30 seconds (SR-504); the staggered row
     * fade-in; and the footer toast. Quantised to frames so an idle screen is not redrawn.
     */
    void animate(Instant at, Duration remaining, Duration timeout) {
        now = at;
        header.set(headerLeft(), lockMeter(remaining, timeout, at));
        footer.set(hints(), toast(at));
        long sinceReveal = Duration.between(revealStart, at).toMillis();
        long revealEnd = ROW_FADE.toMillis() + ROW_STAGGER.toMillis() * shown.size();
        if (revealing) {
            revealing = sinceReveal <= revealEnd;
            cells.setReveal(revealing ? row -> PmTheme.easeOut(PmTheme.progress(
                    revealStart.plus(ROW_STAGGER.multipliedBy(row)), at, ROW_FADE)) : row -> 1);
            table.invalidate();
        }
    }

    /** Shows the "saved" toast in the footer; it fades out by itself. */
    void toastSaved() {
        toastAt = now;
    }

    private List<Strip.Span> headerLeft() {
        List<Strip.Span> spans = new java.util.ArrayList<>(List.of(
                Strip.Span.bold(BRAND.substring(0, 1), theme.color(PmTheme.Tone.VIOLET)),
                Strip.Span.bold(BRAND.substring(1), theme.color(PmTheme.Tone.BRIGHT)),
                Strip.Span.of(SEPARATOR, theme.color(PmTheme.Tone.BORDER)),
                Strip.Span.of(TITLE, theme.color(PmTheme.Tone.TEXT)),
                Strip.Span.of(SEPARATOR, theme.color(PmTheme.Tone.BORDER)),
                Strip.Span.of(Messages.items(shown.size(), total), theme.color(PmTheme.Tone.MUTED))));
        // Why the browser extension is not served here (ADR 0014 §8), if it is not.
        controller.host().browserNote().ifPresent(note -> {
            spans.add(Strip.Span.of(SEPARATOR, theme.color(PmTheme.Tone.BORDER)));
            spans.add(Strip.Span.of(note, theme.color(PmTheme.Tone.AMBER)));
        });
        return spans;
    }

    private List<Strip.Span> lockMeter(Duration remaining, Duration timeout, Instant at) {
        double fraction = PmTheme.clamp((double) remaining.toMillis() / Math.max(1, timeout.toMillis()));
        int color = fraction > HALF
                ? PmTheme.blend(PmTheme.Tone.AMBER.rgb, PmTheme.Tone.GREEN.rgb, (fraction - HALF) / HALF)
                : PmTheme.blend(PmTheme.Tone.RED.rgb, PmTheme.Tone.AMBER.rgb, fraction / HALF);
        if (remaining.compareTo(URGENT) < 0) {
            long phase = (at.toEpochMilli() / FRAME_MILLIS * FRAME_MILLIS) % PULSE.toMillis();
            double wave = HALF + HALF * Math.cos(2 * Math.PI * phase / PULSE.toMillis());
            color = PmTheme.blend(color, PmTheme.Tone.BRIGHT.rgb, wave * PULSE_DEPTH);
        }
        int filled = (int) Math.ceil(fraction * METER_CELLS);
        return List.of(
                Strip.Span.of(Messages.lockedIn(remaining) + "  ", theme.rgb(color)),
                Strip.Span.of(METER_CELL.repeat(filled), theme.rgb(color)),
                Strip.Span.of(METER_CELL.repeat(METER_CELLS - filled), theme.color(PmTheme.Tone.BORDER)));
    }

    private List<Strip.Span> hints() {
        List<Strip.Span> spans = new ArrayList<>();
        for (List<String> hint : KEY_HINTS) {
            spans.add(Strip.Span.bold(hint.get(0), theme.color(PmTheme.Tone.CYAN)));
            spans.add(Strip.Span.of(" " + hint.get(1) + "   ", theme.color(PmTheme.Tone.DIM)));
        }
        return spans;
    }

    private List<Strip.Span> toast(Instant at) {
        if (toastAt == null) {
            return List.of();
        }
        Duration age = Duration.between(toastAt, at);
        if (age.compareTo(TOAST_LIFETIME) >= 0) {
            toastAt = null;
            return List.of();
        }
        double fade = PmTheme.progress(toastAt.plus(TOAST_LIFETIME.minus(TOAST_FADE)), at, TOAST_FADE);
        return List.of(Strip.Span.bold(CHECK + Messages.SAVED,
                theme.mix(PmTheme.Tone.GREEN, PmTheme.Tone.CARD, fade)));
    }

    /** Non-secret table cells for {@code r}, made terminal-safe (SR-501, SR-503). */
    static List<String> row(VaultRecord r) {
        return List.of(typeName(r), DisplaySafe.text(r.title()), DisplaySafe.text(account(r)),
                UPDATED_FORMAT.format(r.updated()));
    }

    /** Display name of the record type. */
    static String typeName(VaultRecord r) {
        if (r instanceof LoginRecord) {
            return "Login";
        } else if (r instanceof WifiRecord) {
            return "Wi-Fi";
        } else if (r instanceof SshKeyRecord) {
            return "SSH key";
        } else if (r instanceof PasskeyRecord) {
            return "Passkey";
        }
        return "Project";
    }

    /**
     * Username for logins, SSID for Wi-Fi, account name and RP ID for passkeys, empty otherwise.
     * Never a secret field.
     */
    private static String account(VaultRecord r) {
        if (r instanceof LoginRecord) {
            return LoginRecord.class.cast(r).username();
        } else if (r instanceof WifiRecord) {
            return WifiRecord.class.cast(r).ssid();
        } else if (r instanceof PasskeyRecord) {
            return PasskeyRecord.class.cast(r).accountName() + " @ " + PasskeyRecord.class.cast(r).rpId();
        }
        return "";
    }

    private void openSelected() {
        int index = table.getSelectedRow();
        if (index >= 0 && index < shown.size()) {
            controller.show(new RecordDetailWindow(shown.get(index), theme).window());
        }
    }

    private void openAddLogin() {
        controller.showForm(new AddLoginDialog(session, controller.clock(), theme, () -> {
            refresh(searchBox.getText());
            toastSaved();
        }));
    }

    /** Opens the tools menu over the dashboard; SSH actions apply to the selected row (M4.4). */
    private void openTools() {
        controller.show(new ToolsMenu(controller, session, () -> {
            int index = table.getSelectedRow();
            return index >= 0 && index < shown.size() ? java.util.Optional.of(shown.get(index))
                    : java.util.Optional.empty();
        }).window());
    }

    /** Dashboard keys; consumed so they never reach the search box as text. */
    private final class Shortcuts extends WindowListenerAdapter {
        @Override
        public void onInput(Window basePane, KeyStroke key, AtomicBoolean deliverEvent) {
            if (TuiController.isCtrl(key, 'n')) {
                deliverEvent.set(false);
                openAddLogin();
            } else if (TuiController.isCtrl(key, 't')) {
                deliverEvent.set(false);
                openTools();
            } else if (TuiController.isCtrl(key, 'd')) {
                deliverEvent.set(false);
                controller.openDevices();
            } else if (TuiController.isCtrl(key, 's')) {
                deliverEvent.set(false);
                int index = table.getSelectedRow();
                if (index >= 0 && index < shown.size()) {
                    controller.openShare(shown.get(index));
                }
            } else if (TuiController.isCtrl(key, 'l')) {
                deliverEvent.set(false);
                controller.lock();
            } else if (key.getKeyType() == KeyType.Escape) {
                deliverEvent.set(false);
                searchBox.setText("");
                basicWindow.setFocusedInteractable(searchBox);
            }
        }
    }
}
