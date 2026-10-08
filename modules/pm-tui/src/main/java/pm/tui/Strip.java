package pm.tui;

import com.googlecode.lanterna.SGR;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TerminalTextUtils;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.AbstractComponent;
import com.googlecode.lanterna.gui2.ComponentRenderer;
import com.googlecode.lanterna.gui2.TextGUIGraphics;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * One full-width line of colored text runs, some flush left and some flush right: the dashboard
 * header and footer. The right runs always show in full (the idle-lock countdown, SR-504); when the
 * line is too narrow, the left runs are cut off with an ellipsis before them. Text must already be
 * catalogue text or {@link DisplaySafe} output (SR-501).
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
    /** The least space between the left runs and the right runs. */
    private static final int GAP = 2;
    private static final String ELLIPSIS = "…";

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
                int rightStart = graphics.getSize().getColumns() - MARGIN - width(strip.right);
                int gap = strip.right.isEmpty() ? 0 : GAP;
                draw(graphics, MARGIN, clip(strip.left, rightStart - gap - MARGIN));
                draw(graphics, rightStart, strip.right);
            }
        };
    }

    /** {@code spans} cut to {@code columns}, ending in an ellipsis if anything was cut. */
    static List<Span> clip(List<Span> spans, int columns) {
        if (width(spans) <= columns) {
            return spans;
        }
        List<Span> kept = new ArrayList<>();
        int room = columns - TerminalTextUtils.getColumnWidth(ELLIPSIS);
        for (Span span : spans) {
            if (room <= 0) {
                break;
            }
            String text = TerminalTextUtils.fitString(span.text(), room);
            kept.add(new Span(text, span.color(), span.bold()));
            room -= TerminalTextUtils.getColumnWidth(text);
            if (!text.equals(span.text())) {
                break;
            }
        }
        if (columns > 0) {
            Span last = kept.isEmpty() ? spans.get(0) : kept.get(kept.size() - 1);
            kept.add(new Span(ELLIPSIS, last.color(), last.bold()));
        }
        return kept;
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
