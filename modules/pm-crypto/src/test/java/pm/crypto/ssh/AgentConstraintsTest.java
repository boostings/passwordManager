package pm.crypto.ssh;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Add-identity constraints (draft-miller-ssh-agent §3.2.6): validation and wire encoding. */
class AgentConstraintsTest {

    private static byte[] encode(AgentConstraints c) {
        try (WireWriter w = new WireWriter()) {
            c.write(w);
            return w.toBytes();
        }
    }

    @Test
    void encodesLifetimeThenConfirm() {
        assertArrayEquals(new byte[0], encode(AgentConstraints.NONE));
        assertTrue(AgentConstraints.NONE.isNone());
        AgentConstraints both = new AgentConstraints(Duration.ofMinutes(5), true);
        assertFalse(both.isNone());
        assertArrayEquals(new byte[] {1, 0, 0, 1, 44, 2}, encode(both));
        AgentConstraints confirmOnly = new AgentConstraints(Duration.ZERO, true);
        assertFalse(confirmOnly.isNone());
        assertArrayEquals(new byte[] {2}, encode(confirmOnly));
        AgentConstraints max = new AgentConstraints(Duration.ofSeconds(AgentConstraints.MAX_LIFETIME_SECONDS), false);
        assertFalse(max.isNone());
        assertArrayEquals(new byte[] {1, 0x7f, -1, -1, -1}, encode(max));
    }

    @Test
    void refusesLifetimesTheWireCannotCarry() {
        assertEquals("BAD_LIFETIME", assertThrows(IllegalArgumentException.class,
                () -> new AgentConstraints(Duration.ofSeconds(-1), false)).getMessage());
        assertThrows(IllegalArgumentException.class, () -> new AgentConstraints(Duration.ofMillis(1500), false));
        assertThrows(IllegalArgumentException.class,
                () -> new AgentConstraints(Duration.ofSeconds(AgentConstraints.MAX_LIFETIME_SECONDS + 1), false));
        // 2^31 s fits the uint32 field but makes OpenSSH ssh-agent 10.3 exit (ADR 0013).
        assertEquals("BAD_LIFETIME", assertThrows(IllegalArgumentException.class,
                () -> new AgentConstraints(Duration.ofSeconds(1L << 31), false)).getMessage());
        assertThrows(IllegalArgumentException.class, () -> new AgentConstraints(Duration.ofSeconds(0xFFFF_FFFFL), false));
        assertThrows(NullPointerException.class, () -> new AgentConstraints(null, false));
    }
}
