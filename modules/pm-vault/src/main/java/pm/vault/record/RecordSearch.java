package pm.vault.record;

import java.util.List;
import java.util.Locale;

/**
 * Case-insensitive ({@code Locale.ROOT}) substring search over the §2 non-secret fields only:
 * title, username, urls, tags, ssid and hosts. Never reads a secret field (ADR 0006, SR-503).
 * An empty or null query matches every record.
 */
public final class RecordSearch {
    private RecordSearch() {}

    /**
     * Whether {@code record} matches {@code query}.
     *
     * @param record the record; not closed
     * @param query  search text, may be null or empty
     * @return true if any searchable field contains the query, ignoring case
     */
    public static boolean matches(VaultRecord record, String query) {
        String value = query == null ? "" : query.toLowerCase(Locale.ROOT);
        if (value.isEmpty() || contains(record.title(), value)) {
            return true;
        }
        // Class.cast rather than pattern bindings: PMD CloseResource reports every
        // AutoCloseable binding, and these records are owned by the caller.
        if (record instanceof LoginRecord) {
            return loginMatches(LoginRecord.class.cast(record), value);
        }
        if (record instanceof WifiRecord) {
            return contains(WifiRecord.class.cast(record).ssid(), value);
        }
        if (record instanceof SshKeyRecord) {
            return containsAny(SshKeyRecord.class.cast(record).hosts(), value);
        }
        return false;
    }

    private static boolean loginMatches(LoginRecord login, String query) {
        return contains(login.username(), query)
            || containsAny(login.urls(), query)
            || containsAny(login.tags(), query);
    }

    private static boolean contains(String candidate, String query) {
        return candidate.toLowerCase(Locale.ROOT).contains(query);
    }

    private static boolean containsAny(List<String> values, String query) {
        return values.stream().anyMatch(value -> contains(value, query));
    }
}
