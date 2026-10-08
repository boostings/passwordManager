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
 * The pm wordmark on the unlock card: a violet, blue and cyan gradient that flows continuously
 * across it, with a slanted shine that sweeps over it every few seconds. Both are pure functions of
 * the time passed to {@link #animate}, quantised to frames so it repaints only when the picture
 * changes.
 */
final class Banner extends AbstractComponent<Banner> {
    static final List<String> LOGO = List.of(
            " ╭───╮   █▀▀▀█ █▀▄▀▄▀█",
            "╭┴───┴╮  █▄▄▄█ █  █  █",
            "│  ●  │  █     █  █  █",
            "╰─────╯  ▀     ▀  ▀  ▀");

    /** Gradient stops, walked as a loop so the flow never jumps. */
    private static final int[] STOPS = {PmTheme.Tone.VIOLET.rgb, PmTheme.Tone.BLUE.rgb, PmTheme.Tone.CYAN.rgb};
    /** Time for the gradient to flow through one full loop of {@link #STOPS}. */
    private static final Duration FLOW = Duration.ofSeconds(6);
    /** Share of the loop visible across the logo at once. */
    private static final double SPAN = 0.6;
    /** One sweep plus a pause. */
    private static final Duration CYCLE = Duration.ofMillis(3600);
    /** Time the highlight takes to cross the logo. */
    private static final Duration SWEEP = Duration.ofMillis(1400);
    private static final long FRAME_MILLIS = 40;
    private static final double BAND = 4.0;
    /** Columns the shine leans per row, so it reads as a glint rather than a wipe. */
    private static final double SLANT = 1.5;
    private static final double GLOW_STRENGTH = 0.85;

    private final PmTheme theme;
    private final int width = LOGO.stream().mapToInt(String::length).max().orElse(0);
    private Instant start;
    private long frame = -1;
    private boolean sweeping;
    /** Column at the centre of the highlight on the top row while {@link #sweeping}. */
    private double sweepColumn;
    /** Gradient offset along the {@link #STOPS} loop, in [0, 1). */
    private double phase;

    Banner(PmTheme theme) {
        this.theme = theme;
    }

    /** Advances the shimmer to {@code now}; the first call starts the cycle. */
    void animate(Instant now) {
        if (start == null) {
            start = now;
        }
        long total = Duration.between(start, now).toMillis();
        long nextFrame = total / FRAME_MILLIS;
        if (nextFrame == frame) {
            return;
        }
        frame = nextFrame;
        long quantised = nextFrame * FRAME_MILLIS;
        long elapsed = quantised % CYCLE.toMillis();
        double t = PmTheme.easeOut((double) elapsed / SWEEP.toMillis());
        sweeping = elapsed < SWEEP.toMillis();
        double reach = BAND + SLANT * (LOGO.size() - 1);
        sweepColumn = -BAND + t * (width + reach + BAND);
        phase = (double) (quantised % FLOW.toMillis()) / FLOW.toMillis();
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
                        int base = banner.gradient(col);
                        int lit = PmTheme.blend(base, PmTheme.Tone.BRIGHT.rgb, banner.glow(col, row) * GLOW_STRENGTH);
                        graphics.setForegroundColor(theme.rgb(lit));
                        graphics.setCharacter(col, row, line.charAt(col));
                    }
                }
            }
        };
    }

    /** Gradient color at {@code col}; colors drift rightward, with the shine. */
    private int gradient(int col) {
        double along = SPAN * col / Math.max(1, width - 1) - phase;
        double scaled = (along - Math.floor(along)) * STOPS.length;
        int stop = Math.min((int) scaled, STOPS.length - 1);
        return PmTheme.blend(STOPS[stop], STOPS[(stop + 1) % STOPS.length], scaled - stop);
    }

    /**
     * Highlight strength at a cell: 1 at the slanted sweep centre, fading to 0 at {@link #BAND},
     * eased so the core of the glint stays bright.
     */
    private double glow(int col, int row) {
        if (!sweeping) {
            return 0;
        }
        double linear = PmTheme.clamp(1 - Math.abs(col + row * SLANT - sweepColumn) / BAND);
        return linear * linear * (3 - 2 * linear);
    }
}
