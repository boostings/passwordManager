package pm.vault.cbor;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane D replaces this file.
 *
 * <p>Strict decoder for the deterministic subset (ADR 0006 amendment). Rejects indefinite
 * length, tags, floats, negative ints, non-shortest ints, duplicate or unsorted map keys,
 * invalid UTF-8, trailing bytes, and any exceeded limit.
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class CborReader {

    private CborReader() {
    }

    /** Decodes {@code in} under {@code lim}. */
    public static CborValue decode(byte[] in, CborLimits lim) throws CborException {
        throw new UnsupportedOperationException("M1 stub");
    }
}
