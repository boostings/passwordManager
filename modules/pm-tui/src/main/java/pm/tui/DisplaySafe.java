package pm.tui;

import com.googlecode.lanterna.gui2.InputFilter;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;

/**
 * Terminal-safe rendering of record text (SR-501: no record content may drive the terminal).
 * Record fields are user data and may hold C0/C1 controls (ESC, U+009B CSI, U+009D OSC, U+0085),
 * Unicode format characters (bidi overrides such as U+202E, zero-width characters) or line and
 * paragraph separators. Written raw, C1 controls reach the terminal byte stream as escape
 * sequences, and C0 controls make Lanterna's {@code TextCharacter} throw. Every dynamic string the
 * TUI renders therefore passes through {@link #text(String)} first.
 */
final class DisplaySafe {
    /** Shown in place of every unsafe code point. */
    static final char REPLACEMENT = '�';

    private DisplaySafe() {
    }

    /**
     * Returns {@code s} with every unsafe code point replaced by {@link #REPLACEMENT} (SR-501).
     * Unsafe means an ISO control, a {@link Character#FORMAT} character, a line or paragraph
     * separator, or an unpaired surrogate.
     */
    static String text(String s) {
        StringBuilder out = new StringBuilder(s.length());
        s.codePoints().forEach(cp -> {
            if (isUnsafe(cp)) {
                out.append(REPLACEMENT);
            } else {
                out.appendCodePoint(cp);
            }
        });
        return out.toString();
    }

    /** Whether {@code s} contains no unsafe code point (SR-501). */
    static boolean isSafe(String s) {
        return s.codePoints().noneMatch(DisplaySafe::isUnsafe);
    }

    /** Whether {@code cp} must never be written to the terminal (SR-501). */
    static boolean isUnsafe(int cp) {
        if (Character.isISOControl(cp)) {
            return true;
        }
        int type = Character.getType(cp);
        return type == Character.FORMAT
                || type == Character.LINE_SEPARATOR
                || type == Character.PARAGRAPH_SEPARATOR
                || type == Character.SURROGATE;
    }

    /**
     * Input filter for visible text boxes (SR-501): drops a typed unsafe character and runs
     * {@code onRejected}; every other key passes through.
     */
    static InputFilter rejectUnsafe(Runnable onRejected) {
        return (interactable, key) -> {
            if (!isUnsafeKey(key)) {
                return true;
            }
            onRejected.run();
            return false;
        };
    }

    /**
     * Whether {@code key} is a typed unsafe character (SR-501). Only {@link KeyType#Character}
     * strokes count: Lanterna gives Tab, Enter and Backspace strokes a control character too.
     */
    static boolean isUnsafeKey(KeyStroke key) {
        return key.getKeyType() == KeyType.Character && isUnsafe(key.getCharacter());
    }
}
