package pm.vault.record;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import pm.crypto.SecretBytes;

record SshKeyRecord(
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
        if (title.length() > 256) {
            throw new IllegalArgumentException("title too long");
        }
        if (comment.length() > 64 * 1024) {
            throw new IllegalArgumentException("comment too long");
        }
        hosts = List.copyOf(hosts);
        if (hosts.size() > 64) {
            throw new IllegalArgumentException("too many hosts");
        }
    }

    @Override
    public void close() {
        privateKey.close();
    }
}
