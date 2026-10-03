package pm.vault.record;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretBytes;

/**
 * A website or application login (plan.md section 4, ADR 0006, {@code login-record} in
 * {@code docs/schemas/records.cddl}).
 *
 * @param id record identity
 * @param title display title, at most 256 characters
 * @param username account name, at most 1,024 characters
 * @param password the secret, at most 64 KiB; owned by this record and zero-filled by
 *     {@link #close()} (ADR 0008)
 * @param urls at most 64 URLs of at most 8,192 characters each
 * @param notes free text, at most 65,536 characters
 * @param tags at most 64 tags of at most 1,024 characters each
 * @param created creation time, truncated to whole seconds
 * @param updated last change, truncated to whole seconds
 * @param lastUsed last use, truncated to whole seconds
 */
public record LoginRecord(
        UUID id,
        String title,
        String username,
        SecretBytes password,
        List<String> urls,
        String notes,
        List<String> tags,
        Instant created,
        Instant updated,
        Instant lastUsed
) implements VaultRecord {
    /**
     * Validates every field and takes unmodifiable copies of the lists (MET00-J, OBJ06-J).
     *
     * @throws NullPointerException if a component or a list element is null
     * @throws IllegalArgumentException if a field exceeds its bound, a text holds an unpaired
     *     surrogate, or an instant is before 1970 or after 9999
     */
    public LoginRecord {
        Objects.requireNonNull(id, "id");
        title = FieldRules.text(title, FieldRules.MAX_TITLE_CHARS, "title");
        username = FieldRules.text(username, FieldRules.MAX_SHORT_TEXT_CHARS, "username");
        FieldRules.secret(password, "password");
        urls = List.copyOf(FieldRules.texts(urls, FieldRules.MAX_URL_CHARS, "urls"));
        notes = FieldRules.text(notes, FieldRules.MAX_NOTES_CHARS, "notes");
        tags = List.copyOf(FieldRules.texts(tags, FieldRules.MAX_SHORT_TEXT_CHARS, "tags"));
        created = FieldRules.instant(created, "created");
        updated = FieldRules.instant(updated, "updated");
        lastUsed = FieldRules.instant(lastUsed, "lastUsed");
    }

    @Override
    public void close() {
        password.close();
    }
}
