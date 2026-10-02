package pm.vault.record;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import pm.crypto.SecretBytes;

/**
 * Website or application login (ADR 0006). The password is a {@link SecretBytes} (ADR 0008);
 * lists are defensively copied (OBJ06-J) and bounded (MSC05-J).
 *
 * @param id       stable record id
 * @param title    display title, at most 256 chars
 * @param username account name
 * @param password secret password, closed by {@link #close()}
 * @param urls     at most 64 urls
 * @param notes    free text, at most 64 KiB
 * @param tags     at most 64 tags
 * @param created  creation time
 * @param updated  last modification time
 * @param lastUsed last use time
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
    /** Null checks, length bounds and defensive copies (ADR 0006, OBJ06-J). */
    public LoginRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(urls, "urls");
        Objects.requireNonNull(notes, "notes");
        Objects.requireNonNull(tags, "tags");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        Objects.requireNonNull(lastUsed, "lastUsed");
        RecordLimits.checkTitle(title);
        RecordLimits.checkNotes(notes);
        urls = List.copyOf(urls);
        tags = List.copyOf(tags);
        RecordLimits.checkListSize(urls.size());
        RecordLimits.checkListSize(tags.size());
    }

    /** Closes the password (ADR 0008). */
    @Override
    public void close() {
        password.close();
    }
}
