package pm.vault.cbor;

/**
 * Resource bounds for one encode or decode (ADR 0006 Amendment 1, SR-021, MSC05-J).
 *
 * <p>{@link CborReader} checks every bound before it allocates. {@link CborWriter#encode(CborValue,
 * CborLimits)} applies the same bounds with the same counting rules, so anything it writes can be
 * read back under the same limits.
 *
 * @param maxDepth the deepest allowed container nesting. The top-level array or map is level 1; a
 *     container at level {@code maxDepth + 1} is rejected. Scalars do not add a level.
 * @param maxItems the largest allowed number of data items in the whole encoding, counted as a
 *     running total: every integer, string, boolean, array and map, and every map key and map
 *     value, counts as one
 * @param maxStringBytes the longest allowed byte string or UTF-8 encoded text string, in bytes
 * @param maxTotalBytes the longest allowed encoding, in bytes
 */
public record CborLimits(int maxDepth, int maxItems, int maxStringBytes, int maxTotalBytes) {

    /** Bounds for the unauthenticated vault header (ADR 0003, {@code vault-header.cddl}). */
    public static final CborLimits HEADER = new CborLimits(16, 1_024, 4_096, 64 * 1024);

    /** Bounds for the authenticated record payload ({@code records.cddl}). */
    public static final CborLimits PAYLOAD = new CborLimits(16, 1_000_000, 1 << 20, 256 * 1024 * 1024);

    /**
     * Validates the bounds (MET00-J).
     *
     * @throws IllegalArgumentException if a bound is not positive ({@code maxStringBytes} may be 0)
     */
    public CborLimits {
        if (maxDepth <= 0 || maxItems <= 0 || maxStringBytes < 0 || maxTotalBytes <= 0) {
            throw new IllegalArgumentException("limits must be positive");
        }
    }
}
