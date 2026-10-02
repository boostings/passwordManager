package pm.vault.cbor;

public record CborLimits(int maxDepth, int maxItems, int maxStringBytes, int maxTotalBytes) {
    public static final CborLimits HEADER = new CborLimits(16, 1_024, 4_096, 64 * 1024);
    public static final CborLimits PAYLOAD = new CborLimits(16, 1_000_000, 1 << 20, 256 * 1024 * 1024);
}
