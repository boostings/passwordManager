package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class SecretCharsTest {
    private static final int GRINNING_FACE = 0x1F600;

    private static void assertUtf8RoundTrip(String text) {
        byte[] expected = text.getBytes(StandardCharsets.UTF_8);
        char[] src = text.toCharArray();
        try (SecretChars sc = SecretChars.takeOwnership(src);
                SecretBytes utf8 = sc.toUtf8()) {
            assertEquals(text.length(), sc.length());
            assertEquals(expected.length, utf8.length());
            utf8.withBytes(b -> assertArrayEquals(expected, b));
            sc.withChars(c -> assertArrayEquals(text.toCharArray(), c));
        }
    }

    /** Closes inside the try-with-resources body without tripping the javac [try] lint. */
    private static void closeEarly(SecretChars s) {
        s.close();
    }

    @Test
    void asciiRoundTrip() {
        assertUtf8RoundTrip("correct horse battery staple");
    }

    @Test
    void latin1RoundTrip() {
        assertUtf8RoundTrip("pässwörd");
        byte[] expected = {'p', (byte) 0xC3, (byte) 0xA4, 's', 's', 'w', (byte) 0xC3, (byte) 0xB6, 'r', 'd'};
        try (SecretChars sc = SecretChars.takeOwnership("pässwörd".toCharArray());
                SecretBytes utf8 = sc.toUtf8()) {
            utf8.withBytes(b -> assertArrayEquals(expected, b));
        }
    }

    @Test
    void emojiSurrogatePairRoundTrip() {
        String text = "a" + new String(Character.toChars(GRINNING_FACE)) + "b";
        assertEquals(4, text.length());
        assertUtf8RoundTrip(text);
        byte[] expected = {'a', (byte) 0xF0, (byte) 0x9F, (byte) 0x98, (byte) 0x80, 'b'};
        try (SecretChars sc = SecretChars.takeOwnership(text.toCharArray());
                SecretBytes utf8 = sc.toUtf8()) {
            utf8.withBytes(b -> assertArrayEquals(expected, b));
        }
    }

    @Test
    void emptyArrayWorks() {
        try (SecretChars sc = SecretChars.takeOwnership(new char[0]);
                SecretBytes utf8 = sc.toUtf8()) {
            assertEquals(0, sc.length());
            assertEquals(0, utf8.length());
        }
    }

    @Test
    void takeOwnershipZeroesSource() {
        char[] src = "hunter2".toCharArray();
        try (SecretChars sc = SecretChars.takeOwnership(src)) {
            assertArrayEquals(new char[src.length], src);
            sc.withChars(c -> assertArrayEquals("hunter2".toCharArray(), c));
        }
    }

    @Test
    void unpairedHighSurrogateRejected() {
        try (SecretChars sc = SecretChars.takeOwnership(new char[] {'a', '\uD800'})) {
            IllegalArgumentException e =
                    assertThrows(IllegalArgumentException.class, () -> sc.toUtf8().close());
            assertEquals("MALFORMED_CHARS", e.getMessage());
            assertInstanceOf(CharacterCodingException.class, e.getCause());
        }
    }

    @Test
    void unpairedLowSurrogateRejected() {
        try (SecretChars sc = SecretChars.takeOwnership(new char[] {'\uDC00', 'a'})) {
            IllegalArgumentException e =
                    assertThrows(IllegalArgumentException.class, () -> sc.toUtf8().close());
            assertEquals("MALFORMED_CHARS", e.getMessage());
        }
    }

    @Test
    void useAfterCloseThrows() {
        try (SecretChars sc = SecretChars.takeOwnership("abc".toCharArray())) {
            closeEarly(sc);
            assertThrows(IllegalStateException.class, sc::length);
            assertThrows(IllegalStateException.class, () -> sc.toUtf8().close());
            assertThrows(IllegalStateException.class, () -> sc.withChars(c -> assertNotNull(c)));
        }
    }

    @Test
    void closeIsIdempotentAndZeroFills() {
        AtomicReference<char[]> captured = new AtomicReference<>();
        try (SecretChars sc = SecretChars.takeOwnership("abc".toCharArray())) {
            sc.withChars(captured::set);
            assertFalse(sc.isClosed());
            closeEarly(sc);
            assertTrue(sc.isClosed());
            closeEarly(sc);
            assertTrue(sc.isClosed());
            assertArrayEquals(new char[3], captured.get());
        }
    }

    @Test
    void toStringIsRedacted() {
        try (SecretChars sc = SecretChars.takeOwnership("abc".toCharArray())) {
            String text = sc.toString();
            assertEquals("SecretChars[redacted]", text);
            assertFalse(text.contains("abc"));
        }
    }

    @Test
    void cloneThrows() {
        try (SecretChars sc = SecretChars.takeOwnership("abc".toCharArray())) {
            assertThrows(CloneNotSupportedException.class, () -> assertNotNull(sc.clone()));
        }
    }

    @Test
    void nullArgumentsRejected() {
        assertThrows(NullPointerException.class, () -> SecretChars.takeOwnership(null).close());
        try (SecretChars sc = SecretChars.takeOwnership("abc".toCharArray())) {
            assertThrows(NullPointerException.class, () -> sc.withChars(null));
        }
    }
}
