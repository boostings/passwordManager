package pm.vault.record;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Text search over the non-secret fields of a record (sprint plan section 2 D).
 *
 * <p>The searched fields are exactly: the title of every record, plus user name, URLs and tags of
 * a login, the SSID of a Wi-Fi network and the hosts of an SSH key. Secret fields (passwords,
 * private keys, variable values) are never read, so a query can never confirm part of a secret
 * (SR-505, data-classification.md). Matching is a case-insensitive substring test that lower-cases
 * both sides with {@link Locale#ROOT} (STR02-J).
 */
public final class RecordSearch {
    private RecordSearch() {
    }

    /**
     * Returns whether {@code record} matches {@code query}.
     *
     * @param record the record to test
     * @param query the search text; the empty string matches every record
     * @return true if a searched field contains {@code query}, ignoring case
     * @throws NullPointerException if an argument is null
     */
    public static boolean matches(VaultRecord record, String query) {
        Objects.requireNonNull(record, "record");
        Objects.requireNonNull(query, "query");
        String needle = query.toLowerCase(Locale.ROOT);
        if (needle.isEmpty() || contains(record.title(), needle)) {
            return true;
        }
        // Class.cast, not a pattern variable: the record is the caller's, and a local of an
        // AutoCloseable type would have to be closed here.
        if (record instanceof LoginRecord) {
            return matchesLogin(LoginRecord.class.cast(record), needle);
        }
        if (record instanceof WifiRecord) {
            return contains(WifiRecord.class.cast(record).ssid(), needle);
        }
        if (record instanceof SshKeyRecord) {
            return containsAny(SshKeyRecord.class.cast(record).hosts(), needle);
        }
        return false;
    }

    private static boolean matchesLogin(LoginRecord login, String needle) {
        return contains(login.username(), needle)
                || containsAny(login.urls(), needle)
                || containsAny(login.tags(), needle);
    }

    private static boolean contains(String candidate, String needle) {
        return candidate.toLowerCase(Locale.ROOT).contains(needle);
    }

    private static boolean containsAny(List<String> candidates, String needle) {
        return candidates.stream().anyMatch(candidate -> contains(candidate, needle));
    }
}
