package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Component;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Interactable;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import java.util.List;
import java.util.Optional;

/** The layout every input dialog shares: a label/field grid, then buttons, a notice and a key hint. */
final class FormLayout {
    static final String OK = "OK";
    static final String CANCEL = "Cancel";
    static final String REQUIRED = " *";
    static final String HINT = "⇥ next field   esc cancel";
    static final int FIELD_COLUMNS = 40;

    private static final int GRID_COLUMNS = 2;
    private static final int SIDE_MARGIN = 3;

    private FormLayout() {
    }

    /** An empty label/field grid. */
    static Panel grid() {
        GridLayout layout = new GridLayout(GRID_COLUMNS);
        layout.setHorizontalSpacing(2);
        layout.setVerticalSpacing(1);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        return new Panel(layout);
    }

    /** A one-line text box of the standard width. */
    static TextBox textBox() {
        return new TextBox(new TerminalSize(FIELD_COLUMNS, 1));
    }

    /** Adds {@code label} and {@code field} as one row. */
    static void row(Panel grid, Component label, Component field) {
        grid.addComponent(label, GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.CENTER));
        grid.addComponent(field);
    }

    /** A dim label. */
    static Label label(PmTheme theme, String text) {
        return UnlockWindow.dim(theme, text);
    }

    /** A dim label followed by a red asterisk. */
    static Panel requiredLabel(PmTheme theme, String text) {
        Panel panel = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(0));
        panel.addComponent(UnlockWindow.dim(theme, text));
        Label star = new Label(REQUIRED);
        star.setForegroundColor(theme.color(PmTheme.Tone.RED));
        panel.addComponent(star);
        return panel;
    }

    /** Refuses control and formatting characters as they are typed into each of {@code boxes} (SR-501). */
    static void visibleTextOnly(Runnable onRejected, TextBox... boxes) {
        for (TextBox box : boxes) {
            box.setInputFilter(DisplaySafe.rejectUnsafe(onRejected));
        }
    }

    /**
     * Sets up {@code window} as a centered modal dialog: the grid, then {@code note} (if not
     * empty), the buttons, the notice and the hint; Esc runs {@code onEscape}.
     */
    static void dialog(BasicWindow window, PmTheme theme, Panel grid, String note, Notice notice,
            List<Button> buttons, Interactable focus, Runnable onEscape) {
        Panel buttonRow = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        buttons.forEach(buttonRow::addComponent);

        GridLayout footerLayout = new GridLayout(1);
        footerLayout.setLeftMarginSize(SIDE_MARGIN);
        footerLayout.setRightMarginSize(SIDE_MARGIN);
        footerLayout.setBottomMarginSize(1);
        Panel footer = new Panel(footerLayout);
        footer.addComponent(new EmptySpace());
        if (!note.isEmpty()) {
            footer.addComponent(UnlockWindow.dim(theme, note), UnlockWindow.centered());
        }
        footer.addComponent(buttonRow, UnlockWindow.centered());
        footer.addComponent(notice.label(), UnlockWindow.centered());
        footer.addComponent(UnlockWindow.dim(theme, HINT), UnlockWindow.centered());

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(grid);
        content.addComponent(footer, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        window.setTheme(theme.cards());
        window.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        window.setComponent(content);
        window.setFocusedInteractable(focus);
        window.addWindowListener(TuiController.closeOnEscape(onEscape));
    }

    /**
     * The box's text, stripped. When editing and the box still shows {@code old} as it was
     * displayed, {@code old} itself, so a replacement character shown in place of an unsafe one
     * (SR-501) is never saved over the stored value.
     */
    static String edited(TextBox box, Optional<String> old) {
        String typed = box.getText().strip();
        return old.filter(value -> DisplaySafe.text(value).strip().equals(typed)).orElse(typed);
    }
}
