package pm.tui;

import com.googlecode.lanterna.SGR;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TerminalTextUtils;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.AbstractComponent;
import com.googlecode.lanterna.gui2.ComponentRenderer;
import com.googlecode.lanterna.gui2.TextGUIGraphics;
import java.util.List;
import java.util.Objects;

/**
 * One full-width line of colored text runs, some flush left and some flush right: the dashboard
 * header and footer. Text must already be catalogue text or {@link DisplaySafe} output (SR-501).
 * Setting the same spans again is free, so the animation tick can call {@link #set} every frame.
 */
final class Strip extends AbstractComponent<Strip> {
    /** A run of text in one color. */
    record Span(String text, TextColor color, boolean bold) {
        Span {
            Objects.requireNonNull(text, "text");
            Objects.requireNonNull(color, "color");
        }

        static Span of(String text, TextColor color) {
            return new Span(text, color, false);
        }

        static Span bold(String text, TextColor color) {
            return new Span(text, color, true);
        }

        int width() {
            return TerminalTextUtils.getColumnWidth(text);
        }
    }

    private static final int MARGIN = 1;

    private final TextColor background;
    private List<Span> left = List.of();
    private List<Span> right = List.of();

    Strip(TextColor background) {
        this.background = Objects.requireNonNull(background, "background");
    }

    /** Replaces the runs; repaints only if something changed. */
    void set(List<Span> newLeft, List<Span> newRight) {
        if (!newLeft.equals(left) || !newRight.equals(right)) {
            left = List.copyOf(newLeft);
            right = List.copyOf(newRight);
            invalidate();
        }
    }

    /** All text on the strip, left runs then right runs. */
    String text() {
        StringBuilder sb = new StringBuilder();
        left.forEach(s -> sb.append(s.text()));
        right.forEach(s -> sb.append(s.text()));
        return sb.toString();
    }

    private static int width(List<Span> spans) {
        return spans.stream().mapToInt(Span::width).sum();
    }

    @Override
    protected ComponentRenderer<Strip> createDefaultRenderer() {
        return new ComponentRenderer<>() {
            @Override
            public TerminalSize getPreferredSize(Strip strip) {
                return new TerminalSize(width(strip.left) + width(strip.right) + MARGIN * 3, 1);
            }

            @Override
            public void drawComponent(TextGUIGraphics graphics, Strip strip) {
                graphics.setBackgroundColor(strip.background);
                graphics.fill(' ');
                draw(graphics, MARGIN, strip.left);
                draw(graphics, graphics.getSize().getColumns() - MARGIN - width(strip.right), strip.right);
            }
        };
    }

    private void draw(TextGUIGraphics graphics, int startColumn, List<Span> spans) {
        int column = startColumn;
        for (Span span : spans) {
            graphics.setForegroundColor(span.color());
            graphics.setBackgroundColor(background);
            graphics.clearModifiers();
            if (span.bold()) {
                graphics.enableModifiers(SGR.BOLD);
            }
            graphics.putString(column, 0, span.text());
            column += span.width();
        }
    }
}
