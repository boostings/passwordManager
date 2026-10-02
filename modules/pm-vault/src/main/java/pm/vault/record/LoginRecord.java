package pm.vault.record;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretBytes;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>Website or application login (ADR 0006). Collections are defensively copied (OBJ06-J).
 */
public record LoginRecord(UUID id, String title, String username, SecretBytes password,
        List<String> urls, String notes, List<String> tags, Instant created, Instant updated,
        Instant lastUsed) implements VaultRecord {

    /** Null checks and defensive copies. */
    public LoginRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(notes, "notes");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        Objects.requireNonNull(lastUsed, "lastUsed");
        urls = List.copyOf(urls);
        tags = List.copyOf(tags);
        // Lane D: length bounds
    }

    /** Closes the password. */
    @Override
    public void close() {
        password.close();
    }
}
