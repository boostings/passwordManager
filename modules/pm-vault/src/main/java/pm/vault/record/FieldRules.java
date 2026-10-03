package pm.vault.record;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import pm.crypto.SecretBytes;
import pm.vault.cbor.CborValue;

/**
 * Validation shared by the compact constructors of the four record types (MET00-J, OBJ06-J). The
 * bounds are the ones in {@code docs/schemas/records.cddl}. They are tight enough that any valid
 * record encodes within {@code CborLimits.PAYLOAD}, so the vault can never write a record it cannot
 * read back (SR-021).
 *
 * <p>Every rejection is an {@link IllegalArgumentException} (or {@link NullPointerException} for a
 * null) whose message names the field only, never its content (SR-501, ERR01-J). Text lengths are
 * counted in UTF-16 code units.
 */
final class FieldRules {
    /** Longest title. */
    static final int MAX_TITLE_CHARS = 256;
    /** Longest free-text field: notes, an SSH key comment, a project configuration value. */
    static final int MAX_NOTES_CHARS = 64 * 1024;
    /** Largest number of URLs, tags or hosts on one record. */
    static final int MAX_LIST_ITEMS = 64;
    /** Longest short text: user name, SSID, tag, host, key type, fingerprint, variable or configuration name. */
    static final int MAX_SHORT_TEXT_CHARS = 1_024;
    /** Longest URL or git remote. */
    static final int MAX_URL_CHARS = 8_192;
    /** Longest SSH public key line. */
    static final int MAX_PUBLIC_KEY_CHARS = 16_384;
    /** Longest filesystem path (the Windows extended-length maximum). */
    static final int MAX_PATH_CHARS = 32_768;
    /** Largest secret: a password, a private key or one variable value, in bytes. */
    static final int MAX_SECRET_BYTES = 64 * 1024;
    /** Largest number of variables, and of configuration entries, in one project. */
    static final int MAX_MAP_ENTRIES = 1_024;
    /** Latest accepted instant, 9999-12-31T23:59:59Z, in epoch seconds. */
    static final long MAX_EPOCH_SECOND = 253_402_300_799L;

    private FieldRules() {
    }

    /**
     * Returns {@code value} after checking that it is non-null, well-formed UTF-16 and at most
     * {@code maxChars} long.
     */
    static String text(String value, int maxChars, String field) {
        checkText(value, maxChars, field);
        return value;
    }

    private static void checkText(String value, int maxChars, String field) {
        Objects.requireNonNull(value, field);
        if (value.length() > maxChars) {
            throw new IllegalArgumentException(field + " is too long");
        }
        if (!CborValue.Text.isWellFormed(value)) {
            throw new IllegalArgumentException(field + " is not well-formed text");
        }
    }

    /**
     * Returns an unmodifiable copy of {@code values} after checking the element count and every
     * element as {@link #text} does.
     */
    static List<String> texts(List<String> values, int maxChars, String field) {
        List<String> copy = List.copyOf(Objects.requireNonNull(values, field));
        if (copy.size() > MAX_LIST_ITEMS) {
            throw new IllegalArgumentException(field + " has too many entries");
        }
        for (String value : copy) {
            checkText(value, maxChars, field);
        }
        return copy;
    }

    /**
     * Returns {@code value} truncated to whole seconds, which is the precision the payload stores,
     * so a record equals itself after a save and reload.
     *
     * @throws IllegalArgumentException if the instant is before 1970-01-01T00:00:00Z or after
     *     9999-12-31T23:59:59Z; the payload stores unsigned epoch seconds
     */
    static Instant instant(Instant value, String field) {
        Instant seconds = Objects.requireNonNull(value, field).truncatedTo(ChronoUnit.SECONDS);
        if (seconds.getEpochSecond() < 0 || seconds.getEpochSecond() > MAX_EPOCH_SECOND) {
            throw new IllegalArgumentException(field + " is out of range");
        }
        return seconds;
    }

    /**
     * Checks that {@code value} is non-null and, while it is open, at most
     * {@link #MAX_SECRET_BYTES} long. A closed secret has no readable length and is accepted, so
     * constructing a record never throws for a secret its owner already closed.
     */
    static void secret(SecretBytes value, String field) {
        if (oversized(Objects.requireNonNull(value, field))) {
            throw new IllegalArgumentException(field + " is too large");
        }
    }

    /**
     * Returns an unmodifiable copy of a project's variables after checking the entry count, every
     * name as short text and every value as {@link #secret} does. The secrets are shared with the
     * caller's map, not copied.
     */
    static Map<String, SecretBytes> secrets(Map<String, SecretBytes> values, String field) {
        Map<String, SecretBytes> copy = Map.copyOf(Objects.requireNonNull(values, field));
        if (copy.size() > MAX_MAP_ENTRIES) {
            throw new IllegalArgumentException(field + " has too many entries");
        }
        for (String name : copy.keySet()) {
            checkText(name, MAX_SHORT_TEXT_CHARS, field);
        }
        if (copy.values().stream().anyMatch(FieldRules::oversized)) {
            throw new IllegalArgumentException(field + " is too large");
        }
        return copy;
    }

    /**
     * Returns an unmodifiable copy of a project's configuration after checking the entry count,
     * every name as short text and every value as free text.
     */
    static Map<String, String> settings(Map<String, String> values, String field) {
        Map<String, String> copy = Map.copyOf(Objects.requireNonNull(values, field));
        if (copy.size() > MAX_MAP_ENTRIES) {
            throw new IllegalArgumentException(field + " has too many entries");
        }
        for (Map.Entry<String, String> entry : copy.entrySet()) {
            checkText(entry.getKey(), MAX_SHORT_TEXT_CHARS, field);
            checkText(entry.getValue(), MAX_NOTES_CHARS, field);
        }
        return copy;
    }

    private static boolean oversized(SecretBytes value) {
        return !value.isClosed() && value.length() > MAX_SECRET_BYTES;
    }
}
