package pm.vault.record;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretBytes;

/**
 * An SSH key pair (plan.md section 4, ADR 0006, {@code ssh-key-record} in
 * {@code docs/schemas/records.cddl}).
 *
 * @param id record identity
 * @param title display title, at most 256 characters
 * @param keyType algorithm name such as {@code ed25519}, at most 1,024 characters
 * @param privateKey the secret, at most 64 KiB; owned by this record and zero-filled by
 *     {@link #close()} (ADR 0008)
 * @param publicKey public key line, at most 16,384 characters
 * @param fingerprint key fingerprint, at most 1,024 characters
 * @param comment free text, at most 65,536 characters
 * @param hosts at most 64 host names of at most 1,024 characters each
 * @param created creation time, truncated to whole seconds
 * @param updated last change, truncated to whole seconds
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
    /**
     * Validates every field and takes an unmodifiable copy of the host list (MET00-J, OBJ06-J).
     *
     * @throws NullPointerException if a component or a host is null
     * @throws IllegalArgumentException if a field exceeds its bound, a text holds an unpaired
     *     surrogate, or an instant is before 1970 or after 9999
     */
    public SshKeyRecord {
        Objects.requireNonNull(id, "id");
        title = FieldRules.text(title, FieldRules.MAX_TITLE_CHARS, "title");
        keyType = FieldRules.text(keyType, FieldRules.MAX_SHORT_TEXT_CHARS, "keyType");
        FieldRules.secret(privateKey, "privateKey");
        publicKey = FieldRules.text(publicKey, FieldRules.MAX_PUBLIC_KEY_CHARS, "publicKey");
        fingerprint = FieldRules.text(fingerprint, FieldRules.MAX_SHORT_TEXT_CHARS, "fingerprint");
        comment = FieldRules.text(comment, FieldRules.MAX_NOTES_CHARS, "comment");
        hosts = List.copyOf(FieldRules.texts(hosts, FieldRules.MAX_SHORT_TEXT_CHARS, "hosts"));
        created = FieldRules.instant(created, "created");
        updated = FieldRules.instant(updated, "updated");
    }

    @Override
    public void close() {
        privateKey.close();
    }
}
