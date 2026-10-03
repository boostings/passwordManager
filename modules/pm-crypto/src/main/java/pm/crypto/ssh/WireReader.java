package pm.crypto.ssh;

import java.util.Arrays;

/**
 * Bounds-checked reader for SSH wire types (RFC 4251 §5): {@code byte}, {@code uint32} and
 * {@code string}. Every length is read as an unsigned 32-bit value and checked against both an
 * explicit maximum and the bytes actually left before anything is copied, so a hostile length can
 * neither overflow nor allocate (MSC05-J, NUM00-J). Every failure throws the code given at
 * construction. Reads a range of an array it does not own and never modifies it.
 */
final class WireReader {
    private static final int BYTE_MASK = 0xff;
    private static final int U32_BYTES = 4;

    private final byte[] buf;
    private final int end;
    private final SshException.Code onError;
    private int pos;

    private WireReader(byte[] buf, int from, int to, SshException.Code onError) {
        this.buf = buf;
        this.pos = from;
        this.end = to;
        this.onError = onError;
    }

    /** A reader over {@code buf[from, to)}; the array is shared, not copied, and never modified. */
    static WireReader over(byte[] buf, int from, int to, SshException.Code onError) {
        return new WireReader(buf, from, to, onError);
    }

    /** A reader over all of {@code buf}. */
    static WireReader over(byte[] buf, SshException.Code onError) {
        return new WireReader(buf, 0, buf.length, onError);
    }

    /** One unsigned byte. */
    int u8() throws SshException {
        need(1);
        return buf[pos++] & BYTE_MASK;
    }

    /** One {@code uint32}, as a non-negative {@code long}. */
    long u32() throws SshException {
        need(U32_BYTES);
        long v = 0;
        for (int i = 0; i < U32_BYTES; i++) {
            v = (v << Byte.SIZE) | (buf[pos++] & BYTE_MASK);
        }
        return v;
    }

    /**
     * Reads a {@code string}'s length, checks it against {@code max} and the bytes left, and skips
     * the contents. Returns the offset of the contents in the underlying array.
     */
    int skipString(int max) throws SshException {
        long n = u32();
        if (n > max) {
            throw new SshException(onError);
        }
        need((int) n);
        int start = pos;
        pos += (int) n;
        return start;
    }

    /** A {@code string} of at most {@code max} bytes, as a new array. */
    byte[] string(int max) throws SshException {
        int start = skipString(max);
        return Arrays.copyOfRange(buf, start, pos);
    }

    /** A {@code string} that must be exactly {@code length} bytes; returns its offset. */
    int fixedString(int length) throws SshException {
        int start = skipString(length);
        if (pos - start != length) {
            throw new SshException(onError);
        }
        return start;
    }

    /** Current offset in the underlying array. */
    int position() {
        return pos;
    }

    /** Bytes left. */
    int remaining() {
        return end - pos;
    }

    /** Throws unless every byte was consumed. */
    void expectEnd() throws SshException {
        if (pos != end) {
            throw new SshException(onError);
        }
    }

    private void need(int n) throws SshException {
        if (n > end - pos) {
            throw new SshException(onError);
        }
    }
}
