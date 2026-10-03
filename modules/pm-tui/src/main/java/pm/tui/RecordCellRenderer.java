package pm.tui;

import com.googlecode.lanterna.SGR;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.TextGUIGraphics;
import com.googlecode.lanterna.gui2.table.DefaultTableCellRenderer;
import com.googlecode.lanterna.gui2.table.DefaultTableHeaderRenderer;
import com.googlecode.lanterna.gui2.table.Table;
import java.util.Map;
import java.util.function.IntToDoubleFunction;

/**
 * Dashboard table cells: a violet bar marks the selected row, each record type has its own color
 * dot, and secondary columns recede. Rows fade in on a stagger when the dashboard opens; the fade
 * level per row comes from {@link #setReveal}. Cells only ever hold {@link DisplaySafe} text.
 */
final class RecordCellRenderer extends DefaultTableCellRenderer<String> {
    static final String MARKER = "▌ ";
    static final String NO_MARKER = "  ";
    static final String DOT = "● ";

    private static final int PADDING = 4;
    private static final int TYPE_COLUMN = 0;
    private static final int TITLE_COLUMN = 1;
    private static final int ACCOUNT_COLUMN = 2;
    private static final Map<String, PmTheme.Tone> TYPE_TONES = Map.of(
            "Login", PmTheme.Tone.BLUE, "Wi-Fi", PmTheme.Tone.GREEN,
            "SSH key", PmTheme.Tone.AMBER, "Project", PmTheme.Tone.VIOLET);

    private final PmTheme theme;
    private IntToDoubleFunction reveal = row -> 1;

    RecordCellRenderer(PmTheme theme) {
        this.theme = theme;
    }

    /** Opacity per row, 0 (invisible) to 1 (fully drawn). */
    void setReveal(IntToDoubleFunction revealByRow) {
        reveal = revealByRow;
    }

    /** Column headers, indented over the row marker and dot, padded like the cells. */
    static final class Header extends DefaultTableHeaderRenderer<String> {
        @Override
        public TerminalSize getPreferredSize(Table<String> table, String label, int index) {
            int extra = index == TYPE_COLUMN ? MARKER.length() + DOT.length() : 0;
            return super.getPreferredSize(table, label, index).withRelativeColumns(extra + PADDING);
        }

        @Override
        public void drawHeader(Table<String> table, String label, int index, TextGUIGraphics graphics) {
            var definition = table.getThemeDefinition();
            graphics.applyThemeStyle(definition.getCustom("HEADER", definition.getNormal()));
            graphics.putString(index == TYPE_COLUMN ? MARKER.length() + DOT.length() : 0, 0, label);
        }
    }

    @Override
    public TerminalSize getPreferredSize(Table<String> table, String cell, int columnIndex, int rowIndex) {
        TerminalSize size = super.getPreferredSize(table, cell, columnIndex, rowIndex);
        int extra = columnIndex == TYPE_COLUMN ? MARKER.length() + DOT.length() : 0;
        return size.withRelativeColumns(extra + PADDING);
    }

    @Override
    protected void applyStyle(Table<String> table, String cell, int columnIndex, int rowIndex,
            boolean isSelected, TextGUIGraphics graphics) {
        PmTheme.Tone background = background(table, isSelected);
        graphics.setBackgroundColor(theme.color(background));
        graphics.setForegroundColor(theme.rgb(PmTheme.blend(background.rgb,
                tone(columnIndex, isSelected).rgb, reveal.applyAsDouble(rowIndex))));
        graphics.clearModifiers();
        if (isSelected && columnIndex == TITLE_COLUMN) {
            graphics.enableModifiers(SGR.BOLD);
        }
    }

    private static PmTheme.Tone background(Table<String> table, boolean isSelected) {
        if (!isSelected) {
            return PmTheme.Tone.SURFACE;
        }
        return table.isFocused() ? PmTheme.Tone.SELECTION : PmTheme.Tone.RAISED;
    }

    private static PmTheme.Tone tone(int columnIndex, boolean isSelected) {
        return switch (columnIndex) {
            case TYPE_COLUMN -> PmTheme.Tone.TEXT;
            case TITLE_COLUMN -> isSelected ? PmTheme.Tone.BRIGHT : PmTheme.Tone.TEXT;
            case ACCOUNT_COLUMN -> PmTheme.Tone.MUTED;
            default -> PmTheme.Tone.DIM;
        };
    }

    @Override
    protected void render(Table<String> table, String cell, int columnIndex, int rowIndex,
            boolean isSelected, TextGUIGraphics graphics) {
        if (columnIndex != TYPE_COLUMN) {
            graphics.putString(0, 0, cell);
            return;
        }
        double shown = reveal.applyAsDouble(rowIndex);
        PmTheme.Tone background = background(table, isSelected);
        var text = graphics.getForegroundColor();
        if (isSelected) {
            graphics.setForegroundColor(theme.rgb(PmTheme.blend(background.rgb, PmTheme.Tone.VIOLET.rgb, shown)));
        }
        graphics.putString(0, 0, isSelected ? MARKER : NO_MARKER);
        PmTheme.Tone typeTone = TYPE_TONES.getOrDefault(cell, PmTheme.Tone.TEXT);
        graphics.setForegroundColor(theme.rgb(PmTheme.blend(background.rgb, typeTone.rgb, shown)));
        graphics.putString(MARKER.length(), 0, DOT);
        graphics.setForegroundColor(text);
        graphics.putString(MARKER.length() + DOT.length(), 0, cell);
    }
}
