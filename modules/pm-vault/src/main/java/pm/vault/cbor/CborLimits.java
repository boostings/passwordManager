package pm.vault.cbor;

/**
 * Decoder resource limits (MSC05-J, ADR 0006 amendment).
 *
 * @param maxDepth       deepest nesting accepted
 * @param maxItems       most items across the whole document
 * @param maxStringBytes longest byte or text string
 * @param maxTotalBytes  largest input
 */
public record CborLimits(int maxDepth, int maxItems, int maxStringBytes, int maxTotalBytes) {
    /** Limits for the vault file header. */
    public static final CborLimits HEADER = new CborLimits(16, 1_024, 4_096, 64 * 1024);
    /** Limits for the decrypted record payload. */
    public static final CborLimits PAYLOAD = new CborLimits(16, 1_000_000, 1 << 20, 256 * 1024 * 1024);
}
