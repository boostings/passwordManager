package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.TextBox;
import pm.crypto.SecretBoundary;

/**
 * Masked secret entry over a Lanterna {@link TextBox} (ADR 0008, MSC03-J). The box shows only
 * {@code '*'}; its value is drained into a {@code char[]} and the box is cleared at once.
 */
final class MaskedInput {
    /** Mask shown for every typed secret character. */
    static final char MASK = '*';

    private MaskedInput() {
    }

    /** A single-line masked text box. */
    static TextBox newBox(int columns) {
        TextBox box = new TextBox(new TerminalSize(columns, 1));
        box.setMask(MASK);
        return box;
    }

    /**
     * Copies the box content into a fresh {@code char[]} owned by the caller and clears the box.
     * The caller hands the array to {@code SecretChars.takeOwnership}, which zero-fills it.
     */
    @SecretBoundary(reason = "Lanterna 3.1.3 TextBox stores its content only as immutable String "
            + "lines and exposes no char[] accessor. It builds a new String on every keystroke, so "
            + "each typed prefix of the secret is a separate String that stays on the heap until "
            + "GC and cannot be zeroed. This method copies the final String to char[] and clears "
            + "the box; pm code then holds no secret String reference, but the prefix copies "
            + "remain (measured: HeapTui prefix-copy count is non-zero; see ADR 0008, R-003)")
    static char[] drain(TextBox box) {
        char[] out = box.getText().toCharArray();
        box.setText("");
        return out;
    }
}
