package pm.tui;

import com.googlecode.lanterna.SGR;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.AbstractComponent;
import com.googlecode.lanterna.gui2.ComponentRenderer;
import com.googlecode.lanterna.gui2.TextGUIGraphics;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * The pm wordmark on the unlock card: a violet-to-cyan gradient with a soft highlight that sweeps
 * across it every few seconds. The sweep position is a pure function of the time passed to
 * {@link #animate}, quantised to frames so it repaints only when the picture changes.
 */
final class Banner extends AbstractComponent<Banner> {
    static final List<String> LOGO = List.of(
            " ╭───╮   █▀▀▀█ █▀▄▀▄▀█",
            "╭┴───┴╮  █▄▄▄█ █  █  █",
            "│  ●  │  █     █  █  █",
            "╰─────╯  ▀     ▀  ▀  ▀");

    /** One sweep plus a pause. */
    private static final Duration CYCLE = Duration.ofMillis(3600);
    /** Time the highlight takes to cross the logo. */
    private static final Duration SWEEP = Duration.ofMillis(1400);
    private static final long FRAME_MILLIS = 40;
    private static final double BAND = 4.0;
    private static final double GLOW_STRENGTH = 0.75;

    private final PmTheme theme;
    private final int width = LOGO.stream().mapToInt(String::length).max().orElse(0);
    private Instant start;
    private long frame = -1;
    private boolean sweeping;
    /** Column at the centre of the highlight while {@link #sweeping}. */
    private double sweepColumn;

    Banner(PmTheme theme) {
        this.theme = theme;
    }

    /** Advances the shimmer to {@code now}; the first call starts the cycle. */
    void animate(Instant now) {
        if (start == null) {
            start = now;
        }
        long elapsed = Duration.between(start, now).toMillis() % CYCLE.toMillis();
        long nextFrame = elapsed / FRAME_MILLIS;
        if (nextFrame == frame) {
            return;
        }
        frame = nextFrame;
        double t = PmTheme.easeOut((double) elapsed / SWEEP.toMillis());
        sweeping = elapsed < SWEEP.toMillis();
        sweepColumn = -BAND + t * (width + BAND * 2);
        invalidate();
    }

    @Override
    protected ComponentRenderer<Banner> createDefaultRenderer() {
        return new ComponentRenderer<>() {
            @Override
            public TerminalSize getPreferredSize(Banner banner) {
                return new TerminalSize(banner.width, LOGO.size());
            }

            @Override
            public void drawComponent(TextGUIGraphics graphics, Banner banner) {
                graphics.setBackgroundColor(theme.color(PmTheme.Tone.CARD));
                graphics.fill(' ');
                graphics.enableModifiers(SGR.BOLD);
                for (int row = 0; row < LOGO.size(); row++) {
                    String line = LOGO.get(row);
                    for (int col = 0; col < line.length(); col++) {
                        int base = PmTheme.blend(PmTheme.Tone.VIOLET.rgb, PmTheme.Tone.CYAN.rgb,
                                (double) col / Math.max(1, banner.width - 1));
                        int lit = PmTheme.blend(base, PmTheme.Tone.BRIGHT.rgb, banner.glow(col) * GLOW_STRENGTH);
                        graphics.setForegroundColor(theme.rgb(lit));
                        graphics.setCharacter(col, row, line.charAt(col));
                    }
                }
            }
        };
    }

    /** Highlight strength at {@code col}: 1 at the sweep centre, fading to 0 at {@link #BAND}. */
    private double glow(int col) {
        if (!sweeping) {
            return 0;
        }
        return PmTheme.clamp(1 - Math.abs(col - sweepColumn) / BAND);
    }
}
