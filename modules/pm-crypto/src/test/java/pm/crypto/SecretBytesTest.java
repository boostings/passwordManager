package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicReference;
import net.jqwik.api.Assume;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import org.junit.jupiter.api.Test;

class SecretBytesTest {
    private static final byte[] SAMPLE = {0x41, 0x42, 0x43, 0x7F, (byte) 0xFF};
    private static final byte[] OTHER = {0x10, 0x20, 0x30};

    /** Closes inside the try-with-resources body without tripping the javac [try] lint. */
    private static void closeEarly(SecretBytes s) {
        s.close();
    }

    @Test
    void lengthAfterCloseThrows() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            closeEarly(sb);
            IllegalStateException e = assertThrows(IllegalStateException.class, sb::length);
            assertEquals("SECRET_CLOSED", e.getMessage());
        }
    }

    @Test
    void withBytesAfterCloseThrows() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            closeEarly(sb);
            assertThrows(IllegalStateException.class, () -> sb.withBytes(b -> assertNotNull(b)));
        }
    }

    @Test
    void applyAfterCloseThrows() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            closeEarly(sb);
            assertThrows(IllegalStateException.class, () -> assertNotNull(sb.apply(b -> b.length)));
        }
    }

    @Test
    void equalsAfterCloseThrows() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE);
                SecretBytes open = SecretBytes.copyOf(SAMPLE)) {
            closeEarly(sb);
            assertThrows(IllegalStateException.class, () -> assertTrue(sb.equals(open)));
            assertThrows(IllegalStateException.class, () -> assertTrue(open.equals(sb)));
            assertThrows(IllegalStateException.class, () -> assertTrue(sb.equals(sameReference(sb))));
        }
    }

    @Test
    void closeIsIdempotentAndIsClosedReportsState() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            assertFalse(sb.isClosed());
            closeEarly(sb);
            assertTrue(sb.isClosed());
            closeEarly(sb);
            assertTrue(sb.isClosed());
        }
    }

    @Test
    void closeZeroFillsInternalBuffer() {
        AtomicReference<byte[]> captured = new AtomicReference<>();
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            sb.withBytes(captured::set);
            assertArrayEquals(SAMPLE, captured.get());
            closeEarly(sb);
            assertArrayEquals(new byte[SAMPLE.length], captured.get());
        }
    }

    @Test
    void toStringIsRedacted() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            String text = sb.toString();
            assertEquals("SecretBytes[redacted]", text);
            for (byte b : SAMPLE) {
                assertFalse(text.contains(Byte.toString(b)));
                assertFalse(text.contains(Integer.toString(b & 0xFF)));
                assertFalse(text.contains(String.format("%02x", b)));
            }
        }
    }

    @Test
    void hashCodeIsConstantAcrossContents() {
        try (SecretBytes a = SecretBytes.copyOf(SAMPLE);
                SecretBytes b = SecretBytes.copyOf(OTHER);
                SecretBytes empty = SecretBytes.copyOf(new byte[0])) {
            assertEquals(a.hashCode(), b.hashCode());
            assertEquals(a.hashCode(), empty.hashCode());
        }
    }

    @Test
    void cloneThrows() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            assertThrows(CloneNotSupportedException.class, () -> assertNotNull(sb.clone()));
        }
    }

    @Test
    void takeOwnershipZeroesSource() {
        byte[] src = SAMPLE.clone();
        try (SecretBytes sb = SecretBytes.takeOwnership(src)) {
            assertArrayEquals(new byte[SAMPLE.length], src);
            sb.withBytes(b -> assertArrayEquals(SAMPLE, b));
        }
    }

    @Test
    void copyOfLeavesSourceAndIsDefensive() {
        byte[] src = SAMPLE.clone();
        try (SecretBytes sb = SecretBytes.copyOf(src)) {
            assertArrayEquals(SAMPLE, src);
            src[0] = 0;
            sb.withBytes(b -> assertArrayEquals(SAMPLE, b));
        }
    }

    @Test
    void lengthApplyAndWithBytesSeeContent() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            assertEquals(SAMPLE.length, sb.length());
            sb.withBytes(b -> assertArrayEquals(SAMPLE, b));
            assertEquals(Integer.valueOf(SAMPLE[0]), sb.apply(b -> Integer.valueOf(b[0])));
        }
    }

    @Test
    void nullArgumentsRejected() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            assertThrows(NullPointerException.class, () -> sb.withBytes(null));
            assertThrows(NullPointerException.class, () -> assertNotNull(sb.apply(null)));
        }
        assertThrows(NullPointerException.class, () -> SecretBytes.copyOf(null).close());
        assertThrows(NullPointerException.class, () -> SecretBytes.takeOwnership(null).close());
    }

    @Test
    void sameInstanceIsEqualWhileOpen() {
        try (SecretBytes sb = SecretBytes.copyOf(SAMPLE)) {
            assertTrue(sb.equals(sameReference(sb)));
        }
    }

    @Property
    void copiesOfSameBytesAreEqual(@ForAll byte[] x) {
        try (SecretBytes a = SecretBytes.copyOf(x);
                SecretBytes b = SecretBytes.copyOf(x)) {
            assertTrue(a.equals(b));
            assertEquals(a.hashCode(), b.hashCode());
        }
    }

    @Property
    void copiesOfDifferentBytesAreNotEqual(@ForAll byte[] x, @ForAll byte[] y) {
        Assume.that(!MessageDigest.isEqual(x, y));
        try (SecretBytes a = SecretBytes.copyOf(x);
                SecretBytes b = SecretBytes.copyOf(y)) {
            assertFalse(a.equals(b));
        }
    }

    @Property
    void neverEqualToNonSecretBytes(@ForAll byte[] x) {
        Object plainArray = x.clone();
        Object text = "SecretBytes[redacted]";
        try (SecretBytes a = SecretBytes.copyOf(x)) {
            assertFalse(a.equals(plainArray));
            assertFalse(a.equals(text));
        }
    }

    /** Returns its argument as Object so self-equality can be tested without an Error Prone SelfEquals hit. */
    private static Object sameReference(SecretBytes sb) {
        return sb;
    }
}
