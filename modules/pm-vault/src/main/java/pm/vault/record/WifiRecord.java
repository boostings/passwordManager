package pm.vault.record;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import pm.crypto.SecretBytes;

/**
 * Wi-Fi network credential (ADR 0006). The password is a {@link SecretBytes} (ADR 0008).
 *
 * @param id       stable record id
 * @param title    display title, at most 256 chars
 * @param ssid     network name
 * @param security one of WPA2, WPA3, WEP, OPEN
 * @param password secret network key, closed by {@link #close()}
 * @param hidden   whether the network is hidden
 * @param notes    free text, at most 64 KiB
 * @param created  creation time
 * @param updated  last modification time
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
    /** Null checks and length bounds (ADR 0006, MSC05-J). */
    public WifiRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(ssid, "ssid");
        Objects.requireNonNull(security, "security");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(notes, "notes");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        RecordLimits.checkTitle(title);
        RecordLimits.checkNotes(notes);
    }

    /** Closes the password (ADR 0008). */
    @Override
    public void close() {
        password.close();
    }
}
