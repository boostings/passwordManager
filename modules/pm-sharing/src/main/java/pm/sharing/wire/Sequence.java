package pm.sharing.wire;

/**
 * One direction's sequence numbers (SR-202): numbers start at 0 and go up by exactly 1. Use one
 * instance to number what is sent and another to check what is received. Not thread-safe.
 */
public final class Sequence {
    private long expected;

    /** A sequence whose first number is 0. */
    public Sequence() {
        // numbering starts at 0
    }

    /** The number for the next message sent. */
    public long next() {
        return expected++;
    }

    /**
     * Accepts the received number {@code seq}.
     *
     * @throws WireException {@code BAD_SEQUENCE} for a gap or a repeat
     */
    public void accept(long seq) throws WireException {
        if (seq != expected) {
            throw new WireException(WireException.Code.BAD_SEQUENCE);
        }
        expected++;
    }
}
