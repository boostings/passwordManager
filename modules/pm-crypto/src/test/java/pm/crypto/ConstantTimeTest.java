package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;

/** SR-016: {@link ConstantTime#equals} agrees with content equality and rejects null. */
class ConstantTimeTest {
    private static final HexFormat HEX = HexFormat.of();

    @Test
    void equalContentIsEqual() {
        assertTrue(ConstantTime.equals(new byte[] {1, 2, 3}, new byte[] {1, 2, 3}));
        assertTrue(ConstantTime.equals(new byte[0], new byte[0]));
    }

    @Test
    void differingContentOrLengthIsNotEqual() {
        assertFalse(ConstantTime.equals(new byte[] {1, 2, 3}, new byte[] {1, 2, 4}));
        assertFalse(ConstantTime.equals(new byte[] {0, 2, 3}, new byte[] {1, 2, 3}));
        assertFalse(ConstantTime.equals(new byte[] {1, 2, 3}, new byte[] {1, 2}));
        assertFalse(ConstantTime.equals(new byte[0], new byte[] {0}));
    }

    @Test
    void nullIsRejected() {
        assertThrows(NullPointerException.class, () -> ConstantTime.equals(null, new byte[0]));
        assertThrows(NullPointerException.class, () -> ConstantTime.equals(new byte[0], null));
        assertThrows(NullPointerException.class, () -> ConstantTime.equals(null, null));
    }

    @Property(tries = 200)
    void agreesWithContentEquality(@ForAll @Size(max = 8) byte[] a, @ForAll @Size(max = 8) byte[] b) {
        // Test oracle: equal hex renderings mean equal length and content.
        assertEquals(HEX.formatHex(a).equals(HEX.formatHex(b)), ConstantTime.equals(a, b));
        assertTrue(ConstantTime.equals(a, a.clone()));
    }
}
