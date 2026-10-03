package pm.sharing.wire;

import java.util.Arrays;
import java.util.Objects;
import pm.crypto.ConstantTime;

/**
 * An immutable byte string in a message: ids, nonces, MACs and share payloads. It never hands out
 * its array, compares in constant time, and prints only its length, so a payload cannot reach a log.
 */
public final class Octets {
    private final byte[] bytes;

    private Octets(byte[] owned) {
        this.bytes = owned;
    }

    /** A copy of {@code src}; the caller keeps {@code src}. */
    public static Octets copyOf(byte[] src) {
        return new Octets(Objects.requireNonNull(src, "src").clone());
    }

    /** A copy of the bytes. */
    public byte[] toByteArray() {
        return bytes.clone();
    }

    /** The number of bytes. */
    public int length() {
        return bytes.length;
    }

    /** Zero-fills the bytes, for payloads once applied (ADR 0008). */
    public void wipe() {
        Arrays.fill(bytes, (byte) 0);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Octets other && ConstantTime.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return bytes.length;
    }

    @Override
    public String toString() {
        return "Octets[" + bytes.length + " bytes]";
    }
}
