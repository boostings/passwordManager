package pm.fuzz;

import java.util.Arrays;

/**
 * Reads a fuzz input front to back as a script of small choices, for the protocol harnesses. Past
 * the end every read returns zero, so any input is a complete script and a seed can be written
 * by hand, one byte per choice.
 */
public final class Script {
    private static final int BYTE_MASK = 0xFF;

    private final byte[] data;
    private int pos;

    /** A script over a copy of {@code data}. */
    public Script(byte[] data) {
        this.data = data.clone();
    }

    /** Whether every byte has been read. */
    public boolean done() {
        return pos >= data.length;
    }

    /** The next byte as 0..255. */
    public int u8() {
        if (done()) {
            return 0;
        }
        return data[pos++] & BYTE_MASK;
    }

    /** A choice among {@code n} options. */
    public int pick(int n) {
        return u8() % n;
    }

    /** A yes/no choice. */
    public boolean bit() {
        return (u8() & 1) == 1;
    }

    /** {@code n} bytes, zero-padded past the end. */
    public byte[] bytes(int n) {
        byte[] out = new byte[n];
        int take = Math.min(n, data.length - Math.min(pos, data.length));
        System.arraycopy(data, Math.min(pos, data.length), out, 0, take);
        pos += take;
        return out;
    }

    /** {@code n} copies of the next byte; a cheap way to choose a key, nonce or id. */
    public byte[] filled(int n) {
        byte[] out = new byte[n];
        Arrays.fill(out, (byte) u8());
        return out;
    }
}
