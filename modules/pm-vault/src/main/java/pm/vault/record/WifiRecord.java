package pm.vault.record;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import pm.crypto.SecretBytes;

/**
 * A Wi-Fi network (plan.md section 4, ADR 0006, {@code wifi-record} in
 * {@code docs/schemas/records.cddl}).
 *
 * @param id record identity
 * @param title display title, at most 256 characters
 * @param ssid network name, at most 1,024 characters
 * @param security exactly one of {@code WPA2}, {@code WPA3}, {@code WEP}, {@code OPEN}
 * @param password the secret, at most 64 KiB and empty for an open network; owned by this record
 *     and zero-filled by {@link #close()} (ADR 0008)
 * @param hidden whether the network hides its SSID
 * @param notes free text, at most 65,536 characters
 * @param created creation time, truncated to whole seconds
 * @param updated last change, truncated to whole seconds
 */
public record WifiRecord(
        UUID id,
        String title,
        String ssid,
        String security,
        SecretBytes password,
        boolean hidden,
        String notes,
        Instant created,
        Instant updated
) implements VaultRecord {
    private static final Set<String> SECURITY_TYPES = Set.of("WPA2", "WPA3", "WEP", "OPEN");

    /**
     * Validates every field (MET00-J).
     *
     * @throws NullPointerException if a component is null
     * @throws IllegalArgumentException if a field exceeds its bound, a text holds an unpaired
     *     surrogate, {@code security} is not one of the four allowed values, or an instant is
     *     before 1970 or after 9999
     */
    public WifiRecord {
        Objects.requireNonNull(id, "id");
        title = FieldRules.text(title, FieldRules.MAX_TITLE_CHARS, "title");
        ssid = FieldRules.text(ssid, FieldRules.MAX_SHORT_TEXT_CHARS, "ssid");
        Objects.requireNonNull(security, "security");
        if (!SECURITY_TYPES.contains(security)) {
            throw new IllegalArgumentException("security is not a supported type");
        }
        FieldRules.secret(password, "password");
        notes = FieldRules.text(notes, FieldRules.MAX_NOTES_CHARS, "notes");
        created = FieldRules.instant(created, "created");
        updated = FieldRules.instant(updated, "updated");
    }

    @Override
    public void close() {
        password.close();
    }
}
