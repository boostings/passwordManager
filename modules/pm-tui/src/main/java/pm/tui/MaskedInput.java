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
    @SecretBoundary(reason = "Lanterna 3.1.3 TextBox stores its content only as String lines and "
            + "exposes no char[] accessor; the String is copied to char[] and the box is cleared "
            + "in this one method, so no secret String is held by pm code beyond this call")
    static char[] drain(TextBox box) {
        char[] out = box.getText().toCharArray();
        box.setText("");
        return out;
    }
}
