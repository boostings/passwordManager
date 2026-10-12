package pm.tui;

import com.googlecode.lanterna.gui2.Component;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Panel;

/** Side padding for a window's content, and word wrapping for status text of fixed width. */
final class Padded {
    private static final int SIDE = 2;

    private Padded() {
    }

    /** {@code content} with two columns of space on each side and one row below. */
    static Panel of(Component content) {
        GridLayout layout = new GridLayout(1);
        layout.setLeftMarginSize(SIDE);
        layout.setRightMarginSize(SIDE);
        layout.setBottomMarginSize(1);
        Panel panel = new Panel(layout);
        panel.addComponent(content, GridLayout.createHorizontallyFilledLayoutData(1));
        return panel;
    }

    /**
     * {@code text} broken into lines of at most {@code columns} characters at spaces; a word longer
     * than a line is left whole. Existing line breaks are kept.
     */
    static String wrap(String text, int columns) {
        StringBuilder out = new StringBuilder();
        for (String paragraph : text.split("\n", -1)) {
            if (out.length() > 0) {
                out.append('\n');
            }
            int lineLength = 0;
            for (String word : paragraph.split(" ", -1)) {
                if (word.isEmpty()) {
                    continue;
                }
                if (lineLength > 0 && lineLength + 1 + word.length() > columns) {
                    out.append('\n');
                    lineLength = 0;
                } else if (lineLength > 0) {
                    out.append(' ');
                    lineLength++;
                }
                out.append(word);
                lineLength += word.length();
            }
        }
        return out.toString();
    }
}
