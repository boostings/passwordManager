package pm.vault.record;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import pm.crypto.SecretBytes;

/**
 * SSH key pair (ADR 0006). The private key is a {@link SecretBytes} (ADR 0008); hosts are
 * defensively copied (OBJ06-J) and bounded (MSC05-J).
 *
 * @param id          stable record id
 * @param title       display title, at most 256 chars
 * @param keyType     key algorithm, for example ssh-ed25519
 * @param privateKey  secret private key, closed by {@link #close()}
 * @param publicKey   public key in OpenSSH format
 * @param fingerprint public key fingerprint
 * @param comment     key comment, at most 64 KiB
 * @param hosts       at most 64 host patterns
 * @param created     creation time
 * @param updated     last modification time
 */
public record SshKeyRecord(
        UUID id,
        String title,
        String keyType,
        SecretBytes privateKey,
        String publicKey,
        String fingerprint,
        String comment,
        List<String> hosts,
        Instant created,
        Instant updated
) implements VaultRecord {
    /** Null checks, length bounds and defensive copies (ADR 0006, OBJ06-J). */
    public SshKeyRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(keyType, "keyType");
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(fingerprint, "fingerprint");
        Objects.requireNonNull(comment, "comment");
        Objects.requireNonNull(hosts, "hosts");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        RecordLimits.checkTitle(title);
        RecordLimits.checkNotes(comment);
        hosts = List.copyOf(hosts);
        RecordLimits.checkListSize(hosts.size());
    }

    /** Closes the private key (ADR 0008). */
    @Override
    public void close() {
        privateKey.close();
    }
}
