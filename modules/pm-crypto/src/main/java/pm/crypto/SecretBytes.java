package pm.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Owned, zeroizable secret buffer (ADR 0008, SR-505).
 *
 * <p>Not {@code Serializable}, not {@code Cloneable} (OBJ07-J, SER03-J). No accessor returns the
 * internal array (OBJ05-J); callers get scoped access through {@link #withBytes} or {@link #apply}
 * and must not retain the array. Every method throws {@link IllegalStateException} after
 * {@link #close()} (OBJ14-J). Not thread-safe: confine an instance to one thread.
 */
@Sensitive
public final class SecretBytes implements AutoCloseable {
    private static final int CONSTANT_HASH = 0x5EC2E7;

    private final byte[] buf;
    private boolean closed;

    private SecretBytes(byte[] owned) {
        this.buf = owned;
    }

    /** Returns a secret holding a defensive copy of {@code src}; the caller keeps ownership of {@code src}. */
    public static SecretBytes copyOf(byte[] src) {
        Objects.requireNonNull(src, "src");
        return new SecretBytes(Arrays.copyOf(src, src.length));
    }

    /** Returns a secret holding a copy of {@code src}, then zero-fills {@code src}. */
    public static SecretBytes takeOwnership(byte[] src) {
        SecretBytes secret = copyOf(src);
        Arrays.fill(src, (byte) 0);
        return secret;
    }

    /** Number of secret bytes. */
    public int length() {
        ensureOpen();
        return buf.length;
    }

    /** Gives {@code use} scoped access to the internal buffer. {@code use} must not retain it. */
    public void withBytes(Consumer<byte[]> use) {
        Objects.requireNonNull(use, "use");
        ensureOpen();
        use.accept(buf);
    }

    /** Applies {@code fn} to the internal buffer. {@code fn} must not retain or return it. */
    public <R> R apply(Function<byte[], R> fn) {
        Objects.requireNonNull(fn, "fn");
        ensureOpen();
        return fn.apply(buf);
    }

    /**
     * Applies a JCA operation to the internal buffer. Any {@link GeneralSecurityException} becomes
     * {@link CryptoException.Code#INTERNAL} with no cause and no provider text (SR-501, ERR01-J).
     * {@code fn} must not retain or return the buffer.
     */
    <R> R applyCrypto(CryptoFunction<byte[], R> fn) throws CryptoException {
        Objects.requireNonNull(fn, "fn");
        ensureOpen();
        try {
            return fn.apply(buf);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoException.Code.INTERNAL);
        }
    }

    /** Whether {@link #close()} has run. */
    public boolean isClosed() {
        return closed;
    }

    /** Zero-fills the buffer and marks the secret closed. Idempotent. */
    @Override
    public void close() {
        Arrays.fill(buf, (byte) 0);
        closed = true;
    }

    /** Constant-time content comparison (SR-016). */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            ensureOpen();
            return true;
        }
        if (!(o instanceof SecretBytes other)) {
            return false;
        }
        ensureOpen();
        other.ensureOpen();
        return MessageDigest.isEqual(buf, other.buf);
    }

    /** Constant: secrets must not be usable as hash keys or leak through hashing. */
    @Override
    public int hashCode() {
        return CONSTANT_HASH;
    }

    @Override
    public String toString() {
        return "SecretBytes[redacted]";
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
