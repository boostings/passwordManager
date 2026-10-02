package pm.vault.record;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretBytes;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>SSH key pair (ADR 0006). Collections are defensively copied (OBJ06-J).
 */
public record SshKeyRecord(UUID id, String title, String keyType, SecretBytes privateKey,
        String publicKey, String fingerprint, String comment, List<String> hosts, Instant created,
        Instant updated) implements VaultRecord {

    /** Null checks and defensive copies. */
    public SshKeyRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(keyType, "keyType");
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(fingerprint, "fingerprint");
        Objects.requireNonNull(comment, "comment");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        hosts = List.copyOf(hosts);
        // Lane D: length bounds
    }

    /** Closes the private key. */
    @Override
    public void close() {
        privateKey.close();
    }
}
