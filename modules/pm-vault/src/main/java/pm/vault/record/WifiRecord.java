package pm.vault.record;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import pm.crypto.SecretBytes;

record WifiRecord(
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
    public WifiRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(ssid, "ssid");
        Objects.requireNonNull(security, "security");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(notes, "notes");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        if (title.length() > 256) {
            throw new IllegalArgumentException("title too long");
        }
        if (notes.length() > 64 * 1024) {
            throw new IllegalArgumentException("notes too long");
        }
    }

    @Override
    public void close() {
        password.close();
    }
}
