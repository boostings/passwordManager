package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** ADR 0007 bounds: each limit just inside and just outside. */
class Argon2ParamsTest {
    private static final int MIN_M = 65_536;
    private static final int MAX_M = 1_048_576;
    private static final int MIN_T = 3;
    private static final int MAX_T = 10;
    private static final int MIN_P = 1;
    private static final int MAX_P = 16;

    @Test
    void floorIsAdr0007Floor() {
        assertEquals(new Argon2Params(MIN_M, MIN_T, MIN_P), Argon2Params.FLOOR);
    }

    @Test
    void memoryBounds() {
        assertEquals(MIN_M, new Argon2Params(MIN_M, MIN_T, MIN_P).memoryKiB());
        assertEquals(MAX_M, new Argon2Params(MAX_M, MIN_T, MIN_P).memoryKiB());
        assertThrows(IllegalArgumentException.class, () -> new Argon2Params(MIN_M - 1, MIN_T, MIN_P));
        assertThrows(IllegalArgumentException.class, () -> new Argon2Params(MAX_M + 1, MIN_T, MIN_P));
    }

    @Test
    void iterationBounds() {
        assertEquals(MIN_T, new Argon2Params(MIN_M, MIN_T, MIN_P).iterations());
        assertEquals(MAX_T, new Argon2Params(MIN_M, MAX_T, MIN_P).iterations());
        assertThrows(IllegalArgumentException.class, () -> new Argon2Params(MIN_M, MIN_T - 1, MIN_P));
        assertThrows(IllegalArgumentException.class, () -> new Argon2Params(MIN_M, MAX_T + 1, MIN_P));
    }

    @Test
    void parallelismBounds() {
        assertEquals(MIN_P, new Argon2Params(MIN_M, MIN_T, MIN_P).parallelism());
        assertEquals(MAX_P, new Argon2Params(MIN_M, MIN_T, MAX_P).parallelism());
        assertThrows(IllegalArgumentException.class, () -> new Argon2Params(MIN_M, MIN_T, MIN_P - 1));
        assertThrows(IllegalArgumentException.class, () -> new Argon2Params(MIN_M, MIN_T, MAX_P + 1));
    }

    @Test
    void errorMessageIsACodeNotTheValues() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new Argon2Params(MIN_M, MIN_T, 0));
        assertEquals("ARGON2_PARAMS_OUT_OF_RANGE", e.getMessage());
    }
}
