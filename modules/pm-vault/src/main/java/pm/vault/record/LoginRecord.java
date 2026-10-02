package pm.vault.record;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import pm.crypto.SecretBytes;

record LoginRecord(
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
        if (title.length() > 256) {
            throw new IllegalArgumentException("title too long");
        }
        if (notes.length() > 64 * 1024) {
            throw new IllegalArgumentException("notes too long");
        }
        urls = List.copyOf(urls);
        tags = List.copyOf(tags);
        if (urls.size() > 64 || tags.size() > 64) {
            throw new IllegalArgumentException("too many urls/tags");
        }
    }

    @Override
    public void close() {
        password.close();
    }
}
