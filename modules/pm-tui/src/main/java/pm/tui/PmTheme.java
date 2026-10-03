package pm.tui;

import com.googlecode.lanterna.SGR;
import com.googlecode.lanterna.TerminalPosition;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TerminalTextUtils;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.graphics.SimpleTheme;
import com.googlecode.lanterna.graphics.Theme;
import com.googlecode.lanterna.gui2.AbstractBorder;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.DefaultWindowDecorationRenderer;
import com.googlecode.lanterna.gui2.GUIBackdrop;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.TextGUIGraphics;
import com.googlecode.lanterna.gui2.table.Table;
import java.time.Duration;
import java.time.Instant;
import pm.domain.env.Env;

/**
 * The pm look: a dark palette with a violet-to-cyan accent, rounded card frames, pill buttons
 * and no window shadows. The app draws with the nearest of the 256 indexed colors, which every
 * terminal pm targets renders (macOS Terminal included), unless the terminal announces 24-bit
 * color through {@code COLORTERM}, read with the validating pm-domain accessor (ENV02-J). Also holds the small motion helpers the animated parts share; all
 * of them are pure functions of an {@link Instant}, so tests drive them with a manual clock.
 */
final class PmTheme {
    /** One palette entry as 0xRRGGBB. */
    enum Tone {
        BACKDROP(0x13141c), SURFACE(0x1a1b26), CARD(0x1f2335), RAISED(0x292e42), FIELD(0x16161e),
        SELECTION(0x2e3c64), BORDER(0x3b4261), DIM(0x565f89), MUTED(0x7a83ad), TEXT(0xc0caf5),
        BRIGHT(0xe6e9ff), VIOLET(0xbb9af7), BLUE(0x7aa2f7), CYAN(0x7dcfff), GREEN(0x9ece6a),
        AMBER(0xe0af68), RED(0xf7768e);

        final int rgb;

        Tone(int rgb) {
            this.rgb = rgb;
        }
    }

    private static final String TRUECOLOR = "truecolor";
    private static final String BITS24 = "24bit";
    private static final int BYTE = 0xff;
    private static final int RED_SHIFT = 16;
    private static final int GREEN_SHIFT = 8;

    private final boolean trueColor;

    PmTheme(boolean trueColor) {
        this.trueColor = trueColor;
    }

    /** The theme the app runs with: 256 indexed colors. */
    static PmTheme standard() {
        return new PmTheme(false);
    }

    /**
     * The theme for the terminal described by {@code env}: 24-bit when {@code COLORTERM} is
     * {@code truecolor} or {@code 24bit}, otherwise 256 indexed colors.
     */
    static PmTheme forEnvironment(Env env) {
        boolean full = env.get(Env.Var.COLORTERM).map(v -> TRUECOLOR.equals(v) || BITS24.equals(v)).orElse(false);
        return new PmTheme(full);
    }

    /** Whether colors are emitted as 24-bit RGB. */
    boolean isTrueColor() {
        return trueColor;
    }

    /** The terminal color for {@code tone}. */
    TextColor color(Tone tone) {
        return rgb(tone.rgb);
    }

    /** {@code from} blended toward {@code to} by {@code t} in [0, 1]. */
    TextColor mix(Tone from, Tone to, double t) {
        return rgb(blend(from.rgb, to.rgb, t));
    }

    /** {@code a} blended toward {@code b} by {@code t}, clamped to [0, 1], per channel. */
    static int blend(int a, int b, double t) {
        double k = clamp(t);
        int out = 0;
        for (int shift : new int[] {RED_SHIFT, GREEN_SHIFT, 0}) {
            int ca = (a >> shift) & BYTE;
            int cb = (b >> shift) & BYTE;
            out |= (int) Math.round(ca + (cb - ca) * k) << shift;
        }
        return out;
    }

    /** Linear progress of {@code duration} since {@code start}, clamped to [0, 1]. */
    static double progress(Instant start, Instant now, Duration duration) {
        return clamp((double) Duration.between(start, now).toMillis() / duration.toMillis());
    }

    /** Ease-out cubic: fast start, gentle landing. */
    static double easeOut(double t) {
        double inv = 1 - clamp(t);
        return 1 - inv * inv * inv;
    }

    static double clamp(double t) {
        return Math.max(0, Math.min(1, t));
    }

    /** The terminal color for a raw 0xRRGGBB value. */
    TextColor rgb(int rgb) {
        int r = (rgb >> RED_SHIFT) & BYTE;
        int g = (rgb >> GREEN_SHIFT) & BYTE;
        int b = rgb & BYTE;
        return trueColor ? new TextColor.RGB(r, g, b) : TextColor.Indexed.fromRGB(r, g, b);
    }

    /** Theme for floating cards (unlock, detail, add login) over the dark backdrop. */
    Theme cards() {
        return build(Tone.CARD);
    }

    /** Theme for the full-screen dashboard. */
    Theme screen() {
        return build(Tone.SURFACE);
    }

    private Theme build(Tone surface) {
        TextColor text = color(Tone.TEXT);
        TextColor base = color(surface);
        SimpleTheme theme = new SimpleTheme(text, base);
        theme.getDefaultDefinition()
                .setActive(color(Tone.BRIGHT), color(Tone.SELECTION), SGR.BOLD)
                .setSelected(color(Tone.BRIGHT), color(Tone.SELECTION))
                .setInsensitive(color(Tone.DIM), base);
        theme.addOverride(GUIBackdrop.class, text, color(Tone.BACKDROP));
        theme.addOverride(AbstractBorder.class, color(Tone.BORDER), base);
        theme.addOverride(Label.class, text, base);
        theme.addOverride(TextBox.class, color(Tone.BRIGHT), color(Tone.FIELD))
                .setActive(color(Tone.BRIGHT), color(Tone.RAISED))
                .setSelected(color(Tone.BRIGHT), color(Tone.RAISED));
        theme.addOverride(Button.class, color(Tone.MUTED), color(Tone.RAISED))
                .setActive(color(Tone.BACKDROP), color(Tone.VIOLET), SGR.BOLD)
                .setSelected(color(Tone.BACKDROP), color(Tone.VIOLET), SGR.BOLD)
                .setPreLight(color(Tone.TEXT), color(Tone.RAISED));
        theme.addOverride(Table.class, text, base)
                .setActive(color(Tone.BRIGHT), color(Tone.SELECTION), SGR.BOLD)
                .setSelected(color(Tone.TEXT), color(Tone.RAISED))
                .setCustom("HEADER", color(Tone.DIM), base, SGR.BOLD);
        theme.addOverride(DefaultWindowDecorationRenderer.class, color(Tone.BORDER), base)
                .setActive(color(Tone.VIOLET), base, SGR.BOLD)
                .setInsensitive(color(Tone.MUTED), base)
                .setPreLight(color(Tone.VIOLET), base)
                .setCharacter("TOP_LEFT_CORNER", '╭')
                .setCharacter("TOP_RIGHT_CORNER", '╮')
                .setCharacter("BOTTOM_LEFT_CORNER", '╰')
                .setCharacter("BOTTOM_RIGHT_CORNER", '╯')
                .setCharacter("TITLE_SEPARATOR_LEFT", ' ')
                .setCharacter("TITLE_SEPARATOR_RIGHT", ' ')
                .setBooleanProperty("CENTER_TITLE", true);
        theme.setWindowPostRenderer(null); // flat: no drop shadows
        return theme;
    }

    /** Draws buttons as {@code  label } pills: violet when focused, raised gray otherwise. */
    static final class PillButtonRenderer implements Button.ButtonRenderer {
        private static final int PADDING = 2;

        @Override
        public TerminalPosition getCursorLocation(Button button) {
            return null; // no hardware cursor on a button
        }

        @Override
        public TerminalSize getPreferredSize(Button button) {
            return new TerminalSize(TerminalTextUtils.getColumnWidth(button.getLabel()) + PADDING * 2, 1);
        }

        @Override
        public void drawComponent(TextGUIGraphics graphics, Button button) {
            var definition = button.getThemeDefinition();
            graphics.applyThemeStyle(button.isFocused() ? definition.getActive() : definition.getNormal());
            graphics.fill(' ');
            graphics.putString(PADDING, 0, button.getLabel());
        }
    }

    /** A button styled as a pill. */
    static Button pill(String label, Runnable action) {
        Button button = new Button(label, action);
        button.setRenderer(new PillButtonRenderer());
        return button;
    }
}
