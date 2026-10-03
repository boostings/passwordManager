package pm.tui;

import com.googlecode.lanterna.SGR;
import com.googlecode.lanterna.gui2.Label;
import java.time.Duration;
import java.time.Instant;

/**
 * A one-line message under a form: errors flash bright and settle to red, progress shows in the
 * accent color. Text is catalogue text only (SR-501).
 */
final class Notice {
    static final String ERROR_MARK = "✗ ";
    static final String BUSY_MARK = "◐ ";

    private static final Duration SETTLE = Duration.ofMillis(600);

    private final PmTheme theme;
    private final Label line = new Label("");
    private PmTheme.Tone tone = PmTheme.Tone.RED;
    private Instant shownAt;

    Notice(PmTheme theme) {
        this.theme = theme;
        line.addStyle(SGR.BOLD);
    }

    Label label() {
        return line;
    }

    /** Shows {@code message} as an error that flashes, starting at {@code now}. */
    void error(String message, Instant now) {
        show(ERROR_MARK + message, PmTheme.Tone.RED, now);
    }

    /** Shows {@code message} as work in progress, in the accent color. */
    void busy(String message, Instant now) {
        show(BUSY_MARK + message, PmTheme.Tone.VIOLET, now);
    }

    /** Hides the message. */
    void clear() {
        line.setText("");
        shownAt = null;
    }

    /** Settles the flash toward the message color. */
    void animate(Instant now) {
        if (shownAt != null) {
            var color = theme.mix(PmTheme.Tone.BRIGHT, tone,
                    PmTheme.easeOut(PmTheme.progress(shownAt, now, SETTLE)));
            if (!color.equals(line.getForegroundColor())) {
                line.setForegroundColor(color); // repaint only when the color moved
            }
        }
    }

    private void show(String text, PmTheme.Tone messageTone, Instant now) {
        tone = messageTone;
        shownAt = now;
        line.setText(text);
        animate(now);
    }
}
