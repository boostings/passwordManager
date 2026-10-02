package pm.vault.record;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>Case-insensitive ({@code Locale.ROOT}) search over non-secret fields only: title, username,
 * urls, tags, ssid, hosts. Never matches on secrets (SR-503).
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class RecordSearch {

    private RecordSearch() {
    }

    /** Whether {@code r} matches {@code query}. */
    public static boolean matches(VaultRecord r, String query) {
        throw new UnsupportedOperationException("M1 stub");
    }
}
