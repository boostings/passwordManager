package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.MessageDigest;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CsprngTest {
    private static final int MIN = 1;
    private static final int MAX = 1024;
    private static final int DRAW = 32;

    @Test
    void rejectsOutOfRangeLengths() {
        for (int n : new int[] {Integer.MIN_VALUE, -1, 0, MAX + 1, Integer.MAX_VALUE}) {
            IllegalArgumentException e =
                    assertThrows(IllegalArgumentException.class, () -> assertNotNull(Csprng.bytes(n)));
            assertEquals("BAD_LENGTH", e.getMessage());
            assertThrows(IllegalArgumentException.class, () -> Csprng.secretBytes(n).close());
        }
    }

    @Test
    void acceptsBoundaryLengths() {
        assertEquals(MIN, Csprng.bytes(MIN).length);
        assertEquals(MAX, Csprng.bytes(MAX).length);
    }

    @Test
    void independentDrawsDiffer() {
        byte[] a = Csprng.bytes(DRAW);
        byte[] b = Csprng.bytes(DRAW);
        assertFalse(MessageDigest.isEqual(a, b));
    }

    @Test
    void uuidIsRandomVersion4() {
        UUID u = Csprng.uuid();
        assertEquals(4, u.version());
        assertEquals(2, u.variant());
        assertNotEquals(u, Csprng.uuid());
    }

    @Test
    void secretBytesHasRequestedLength() {
        try (SecretBytes a = Csprng.secretBytes(DRAW);
                SecretBytes b = Csprng.secretBytes(MIN)) {
            assertEquals(DRAW, a.length());
            assertEquals(MIN, b.length());
        }
    }
}
