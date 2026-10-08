package pm.tui;

import com.googlecode.lanterna.gui2.InputFilter;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import pm.crypto.SecretBytes;

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
    /** U+2800, which terminals draw as an empty cell. */
    private static final int BRAILLE_BLANK = 0x2800;

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

    /**
     * Whether a revealed password may hold {@code cp} (m77-004, the set {@code pm show --reveal}
     * uses): not unsafe, and not drawn as nothing or as a blank, so a password read off the screen
     * is the stored one. Refused: every space but U+0020, the braille blank, and the
     * default-ignorable code points of Unicode outside the format category, such as the Hangul
     * fillers, U+034F and the variation selectors.
     */
    static boolean revealable(int cp) {
        return !(isUnsafe(cp) || (Character.isSpaceChar(cp) && cp != ' ') || cp == BRAILLE_BLANK
                || cp == 0x034F || cp == 0x115F || cp == 0x1160 || cp == 0x17B4 || cp == 0x17B5
                || (cp >= 0x180B && cp <= 0x180F) || cp == 0x3164 || (cp >= 0xFE00 && cp <= 0xFE0F)
                || cp == 0xFFA0 || (cp >= 0xFFF0 && cp <= 0xFFF8) || (cp >= 0x1BCA0 && cp <= 0x1BCA3)
                || (cp >= 0x1D173 && cp <= 0x1D17A) || (cp >= 0xE0000 && cp <= 0xE0FFF));
    }

    /**
     * {@code stored} as characters the caller zeroes, if it is well-formed UTF-8 and every code
     * point is {@link #revealable(int)}; otherwise empty, and nothing decoded is left behind.
     */
    static Optional<char[]> revealable(SecretBytes stored) {
        return stored.apply(DisplaySafe::decode).filter(DisplaySafe::allRevealableElseZeroed);
    }

    private static boolean allRevealableElseZeroed(char[] chars) {
        if (CharBuffer.wrap(chars).codePoints().allMatch(DisplaySafe::revealable)) {
            return true;
        }
        Arrays.fill(chars, '\0');
        return false;
    }

    /** Strict UTF-8 decoding into a new array; empty for malformed input, with the work buffer zeroed. */
    private static Optional<char[]> decode(byte[] utf8) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        // UTF-8 never decodes to more UTF-16 units than it has bytes.
        char[] work = new char[utf8.length];
        CharBuffer decoded = CharBuffer.wrap(work);
        try {
            CoderResult result = decoder.decode(ByteBuffer.wrap(utf8), decoded, true);
            if (result.isUnderflow()) {
                result = decoder.flush(decoded);
            }
            return result.isUnderflow() ? Optional.of(Arrays.copyOf(work, decoded.position())) : Optional.empty();
        } finally {
            Arrays.fill(work, '\0');
        }
    }
}
