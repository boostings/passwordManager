package pm.crypto;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * {@code char[]} twin of {@link SecretBytes} for passphrase entry (ADR 0008). Never converted to
 * {@code String} (STR03-J, MSC03-J). Not thread-safe.
 */
@Sensitive
public final class SecretChars implements AutoCloseable {
    private static final int MAX_UTF8_BYTES_PER_CHAR = 3;

    private final char[] buf;
    private boolean closed;

    private SecretChars(char[] owned) {
        this.buf = owned;
    }

    /** Returns a secret holding a copy of {@code src}, then zero-fills {@code src}. */
    public static SecretChars takeOwnership(char[] src) {
        Objects.requireNonNull(src, "src");
        SecretChars secret = new SecretChars(Arrays.copyOf(src, src.length));
        Arrays.fill(src, '\0');
        return secret;
    }

    /** Number of UTF-16 code units. */
    public int length() {
        ensureOpen();
        return buf.length;
    }

    /**
     * Encodes as UTF-8 with an explicit charset (FIO11-J), zeroing intermediate buffers.
     *
     * @throws IllegalArgumentException if the chars are not well-formed UTF-16 (unpaired surrogate)
     */
    public SecretBytes toUtf8() {
        ensureOpen();
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer encoded = ByteBuffer.allocate(Math.multiplyExact(buf.length, MAX_UTF8_BYTES_PER_CHAR));
        try {
            CoderResult result = encoder.encode(CharBuffer.wrap(buf), encoded, true);
            // UTF-8 is stateless and the buffer is sized for the worst case, so flush always
            // underflows. Its result still flows into the single check below rather than a
            // second, never-taken branch; malformed input skips the flush and fails here.
            if (result.isUnderflow()) {
                result = encoder.flush(encoded);
            }
            if (!result.isUnderflow()) {
                result.throwException();
            }
            encoded.flip();
            byte[] out = new byte[encoded.remaining()];
            encoded.get(out);
            return SecretBytes.takeOwnership(out);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("MALFORMED_CHARS", e);
        } finally {
            Arrays.fill(encoded.array(), (byte) 0);
        }
    }

    /** Gives {@code use} scoped access to the internal buffer. {@code use} must not retain it. */
    public void withChars(Consumer<char[]> use) {
        Objects.requireNonNull(use, "use");
        ensureOpen();
        use.accept(buf);
    }

    /** Whether {@link #close()} has run. */
    public boolean isClosed() {
        return closed;
    }

    /** Zero-fills the buffer and marks the secret closed. Idempotent. */
    @Override
    public void close() {
        Arrays.fill(buf, '\0');
        closed = true;
    }

    @Override
    public String toString() {
        return "SecretChars[redacted]";
    }

    /** Always throws: secrets are never cloned (OBJ07-J). */
    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("SECRET_CLOSED");
        }
    }
}
