package pm.crypto.ssh;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import pm.crypto.SecretBytes;

/**
 * Growable buffer for SSH wire types that may hold key material: every buffer it outgrows is
 * zero-filled before it is dropped, and {@link #close()} zero-fills the current one (ADR 0008).
 * Callers bound what they write, so no size check is needed here.
 */
final class WireWriter implements AutoCloseable {
    private static final int INITIAL = 256;
    private static final int BYTE_MASK = 0xff;
    private static final int U32_BYTES = 4;

    private byte[] buf = new byte[INITIAL];
    private int len;

    void u8(int v) {
        ensure(1);
        buf[len++] = (byte) v;
    }

    void u32(long v) {
        ensure(U32_BYTES);
        for (int shift = (U32_BYTES - 1) * Byte.SIZE; shift >= 0; shift -= Byte.SIZE) {
            buf[len++] = (byte) ((v >>> shift) & BYTE_MASK);
        }
    }

    void raw(byte[] src, int off, int n) {
        ensure(n);
        System.arraycopy(src, off, buf, len, n);
        len += n;
    }

    void raw(byte[] src) {
        raw(src, 0, src.length);
    }

    void string(byte[] src) {
        u32(src.length);
        raw(src);
    }

    void string(String ascii) {
        string(ascii.getBytes(StandardCharsets.US_ASCII));
    }

    int length() {
        return len;
    }

    /** A copy of the contents; the caller zero-fills it if it holds key material. */
    byte[] toBytes() {
        return Arrays.copyOf(buf, len);
    }

    /** Appends the contents to {@code other} without an intermediate copy. */
    void writeTo(WireWriter other) {
        other.raw(buf, 0, len);
    }

    /** The contents as a new secret. */
    SecretBytes toSecret() {
        return SecretBytes.takeOwnership(Arrays.copyOf(buf, len));
    }

    /** Writes a {@code uint32} length and then the contents to a blocking channel; see {@link #writeDirect}. */
    void writeFramed(WritableByteChannel ch) throws IOException {
        ByteBuffer direct = ByteBuffer.allocateDirect(U32_BYTES + len);
        try {
            direct.putInt(len).put(buf, 0, len).flip();
            drain(ch, direct);
        } finally {
            wipe(direct);
        }
    }

    /**
     * Writes {@code src} to a blocking channel through a direct buffer that pm owns and zero-fills
     * afterwards. Writing a heap buffer would make the JDK copy it into a per-thread cached direct
     * buffer ({@code sun.nio.ch.Util}) that is reused but never cleared, leaving key bytes behind
     * (ADR 0013).
     */
    static void writeDirect(WritableByteChannel ch, byte[] src) throws IOException {
        ByteBuffer direct = ByteBuffer.allocateDirect(src.length);
        try {
            direct.put(src).flip();
            drain(ch, direct);
        } finally {
            wipe(direct);
        }
    }

    private static void drain(WritableByteChannel ch, ByteBuffer b) throws IOException {
        while (b.hasRemaining()) {
            ch.write(b);
        }
    }

    /** Zero-fills the whole capacity, whatever the position. */
    private static void wipe(ByteBuffer b) {
        b.clear();
        b.put(new byte[b.capacity()]);
    }

    @Override
    public void close() {
        Arrays.fill(buf, (byte) 0);
        len = 0;
    }

    private void ensure(int extra) {
        if (len + extra > buf.length) {
            byte[] grown = Arrays.copyOf(buf, Math.max(buf.length * 2, len + extra));
            Arrays.fill(buf, (byte) 0);
            buf = grown;
        }
    }
}
