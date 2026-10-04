package pm.sharing.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Sequence numbers (SR-202) and the byte-string value type. */
@Tag("T-LAN-03")
class SequenceAndOctetsTest {
    @Test
    void sendingNumbersStartAtZeroAndCount() {
        Sequence out = new Sequence();
        assertEquals(0, out.next());
        assertEquals(1, out.next());
    }

    @Test
    void receivingRefusesGapsAndRepeats() throws WireException {
        Sequence in = new Sequence();
        in.accept(0);
        in.accept(1);
        assertEquals(WireException.Code.BAD_SEQUENCE, assertThrows(WireException.class, () -> in.accept(1)).code());
        assertEquals(WireException.Code.BAD_SEQUENCE, assertThrows(WireException.class, () -> in.accept(3)).code());
        in.accept(2);
    }

    @Test
    void octetsAreCopiedComparedByContentAndNeverPrinted() {
        byte[] src = {7, 8, 9};
        Octets o = Octets.copyOf(src);
        src[0] = 0;
        assertArrayEquals(new byte[] {7, 8, 9}, o.toByteArray());
        assertEquals(Octets.copyOf(new byte[] {7, 8, 9}), o);
        assertNotEquals(Octets.copyOf(new byte[] {7, 8, 8}), o);
        assertFalse(o.equals("not octets"));
        assertEquals(3, o.hashCode());
        assertEquals("Octets[3 bytes]", o.toString());
        o.wipe();
        assertArrayEquals(new byte[3], o.toByteArray());
    }

    @Test
    void checksBoundBothEnds() {
        Octets three = Octets.copyOf(new byte[3]);
        assertThrows(IllegalArgumentException.class, () -> Checks.length(three, 4, 8));
        assertThrows(IllegalArgumentException.class, () -> Checks.length(three, 1, 2));
        assertThrows(IllegalArgumentException.class, () -> Checks.range(5, 6, 9));
        assertThrows(IllegalArgumentException.class, () -> Checks.range(10, 6, 9));
        assertTrue(Checks.label("ok", 2).equals("ok"));
    }
}
