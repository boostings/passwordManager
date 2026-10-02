package pm.vault.record;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretBytes;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>Wi-Fi network credential (ADR 0006). {@code security} is one of WPA2, WPA3, WEP, OPEN.
 */
public record WifiRecord(UUID id, String title, String ssid, String security,
        SecretBytes password, boolean hidden, String notes, Instant created, Instant updated)
        implements VaultRecord {

    /** Null checks. */
    public WifiRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(ssid, "ssid");
        Objects.requireNonNull(security, "security");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(notes, "notes");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        // Lane D: length bounds
    }

    /** Closes the password. */
    @Override
    public void close() {
        password.close();
    }
}
