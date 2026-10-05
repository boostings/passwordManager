package pm.fuzz;

import java.util.Arrays;

/**
 * Lets a fuzzer reach size limits that lie beyond libFuzzer's 4096-byte input cap. An input that
 * starts with {@code '+'} is read as {@code '+' u16 offset, u24 count, u8 fill, rest}: the result is
 * {@code rest} with a run of {@code count} {@code fill} bytes (at most {@code cap}) inserted at
 * {@code offset} (clamped to {@code rest}). So the fuzzer picks a length header and the size of the
 * body it covers independently, and a 4 KiB input can describe a 64 KiB key file or a 256 KiB agent
 * frame. Any other input is returned unchanged.
 */
public final class Stretch {
    /** The byte that marks a stretched input. */
    public static final byte MARK = '+';
    private static final int HEADER = 7;

    private Stretch() {
    }

    /** The input with its run inserted, or the input itself when it is not stretched. */
    public static byte[] apply(byte[] in, int cap) {
        if (in.length < HEADER || in[0] != MARK) {
            return in;
        }
        int offset = (in[1] & 0xff) << 8 | (in[2] & 0xff);
        int count = Math.min(cap, (in[3] & 0xff) << 16 | (in[4] & 0xff) << 8 | (in[5] & 0xff));
        byte fill = in[6];
        int restLength = in.length - HEADER;
        int at = Math.min(offset, restLength);
        byte[] out = new byte[restLength + count];
        System.arraycopy(in, HEADER, out, 0, at);
        Arrays.fill(out, at, at + count, fill);
        System.arraycopy(in, HEADER + at, out, at + count, restLength - at);
        return out;
    }

    /** A stretched input: {@code count} {@code fill} bytes inserted into {@code rest} at {@code offset}. */
    public static byte[] encode(int offset, int count, byte fill, byte[] rest) {
        byte[] out = new byte[HEADER + rest.length];
        out[0] = MARK;
        out[1] = (byte) (offset >>> 8);
        out[2] = (byte) offset;
        out[3] = (byte) (count >>> 16);
        out[4] = (byte) (count >>> 8);
        out[5] = (byte) count;
        out[6] = fill;
        System.arraycopy(rest, 0, out, HEADER, rest.length);
        return out;
    }
}
