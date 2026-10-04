package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Window;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import pm.domain.health.HealthCheck;
import pm.domain.health.HealthReport;
import pm.domain.health.ReuseGroup;
import pm.vault.record.VaultRecord;

/**
 * Password health view (plan.md §13 M4.4, ADR 0012): weak, reused and old passwords from the
 * offline {@link HealthCheck}, by record title (terminal-safe, SR-501) with the rating and the
 * reason, never a password. The TUI never runs the breach check: it needs the network, so it stays
 * an explicit {@code pm health --breach} in a terminal (SR-078), and the view says so.
 */
final class HealthWindow {
    static final String TITLE = "Password health";
    static final String CLOSE = "Close";
    static final String HINT = "esc close";
    /** Rows shown per section; the rest are counted. */
    static final int MAX_ROWS = 8;

    private static final int SIDE_MARGIN = 3;
    private static final String BULLET = "  • ";

    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final List<String> shownLines = new ArrayList<>();

    HealthWindow(List<VaultRecord> records, Clock clock, PmTheme theme) {
        HealthReport report = new HealthCheck(clock).run(records);
        Map<UUID, String> titles = new HashMap<>();
        records.forEach(r -> titles.put(r.id(), DisplaySafe.text(r.title())));

        GridLayout layout = new GridLayout(1);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        layout.setBottomMarginSize(1);
        Panel body = new Panel(layout);
        add(body, theme, PmTheme.Tone.TEXT, String.format(Locale.ROOT, "%d passwords checked", report.checked()));
        if (report.isClean()) {
            add(body, theme, PmTheme.Tone.GREEN, Messages.HEALTH_CLEAN);
        }
        section(body, theme, "Weak", report.weak().stream()
                .map(w -> titles.get(w.id()) + "  " + w.estimate().strength().name().toLowerCase(Locale.ROOT)
                        + String.format(Locale.ROOT, ", ~%.0f bits", w.estimate().bits()))
                .toList());
        section(body, theme, "Reused", report.reused().stream()
                .map(ReuseGroup::ids)
                .map(ids -> ids.stream().map(titles::get).collect(Collectors.joining(", ")))
                .toList());
        section(body, theme, "Not changed in a year", report.old().stream()
                .map(o -> titles.get(o.id()) + String.format(Locale.ROOT, "  %d days", o.age().toDays()))
                .toList());
        body.addComponent(new EmptySpace());
        body.addComponent(UnlockWindow.dim(theme, Messages.BREACH_HINT));

        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        var close = PmTheme.pill(CLOSE, basicWindow::close);
        buttons.addComponent(UnlockWindow.dim(theme, HINT));
        buttons.addComponent(close);
        body.addComponent(new EmptySpace());
        body.addComponent(buttons, GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.CENTER));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(body);
        basicWindow.setFocusedInteractable(close);
        basicWindow.addWindowListener(TuiController.closeOnEscape(basicWindow::close));
    }

    private void section(Panel body, PmTheme theme, String heading, List<String> rows) {
        if (rows.isEmpty()) {
            return;
        }
        body.addComponent(new EmptySpace());
        add(body, theme, PmTheme.Tone.AMBER, heading + " (" + rows.size() + ")");
        rows.stream().limit(MAX_ROWS).forEach(row -> add(body, theme, PmTheme.Tone.BRIGHT, BULLET + row));
        if (rows.size() > MAX_ROWS) {
            add(body, theme, PmTheme.Tone.DIM, String.format(Locale.ROOT, "%s…and %d more", BULLET,
                    rows.size() - MAX_ROWS));
        }
    }

    private void add(Panel body, PmTheme theme, PmTheme.Tone tone, String text) {
        Label label = new Label(text);
        label.setForegroundColor(theme.color(tone));
        body.addComponent(label);
        shownLines.add(text);
    }

    /** The Lanterna window. */
    Window window() {
        return basicWindow;
    }

    /** Every text line of the report, for tests. */
    List<String> lines() {
        return List.copyOf(shownLines);
    }
}
