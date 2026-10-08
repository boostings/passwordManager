package pm.vault.record;

import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretBytes;

/**
 * This install's LAN identity (lan-share.md §1): the Ed25519 private key (Secret class), its
 * self-signed certificate and the name it announces. A vault holds at most one; the record is
 * internal ({@link DeviceRecord}) and never listed or shared.
 *
 * @param id record identity
 * @param title the device name sent in HELLO: 1 to 32 characters, no control or format characters
 * @param privateKey the PKCS#8 Ed25519 private key, at most 64 KiB; owned by this record and
 *     zero-filled by {@link #close()} (ADR 0008)
 * @param certificate the self-signed X.509 certificate as standard base64 of its DER, 1 to 16,384
 *     characters; the payload stores the DER bytes
 * @param created when the identity was generated, whole seconds
 * @param updated last change, whole seconds
 */
public record DeviceIdentityRecord(
        UUID id,
        String title,
        SecretBytes privateKey,
        String certificate,
        Instant created,
        Instant updated
) implements DeviceRecord {
    /**
     * Validates every field.
     *
     * @throws NullPointerException if a component is null
     * @throws IllegalArgumentException if the name is not a valid device name, the certificate is
     *     empty, too long or not base64, the key is too long, or an instant is out of range
     */
    public DeviceIdentityRecord {
        Objects.requireNonNull(id, "id");
        title = DeviceRecord.checkName(title);
        FieldRules.secret(privateKey, "privateKey");
        certificate = FieldRules.text(certificate, FieldRules.MAX_PUBLIC_KEY_CHARS, "certificate");
        if (Base64.getDecoder().decode(certificate).length == 0) { // empty text decodes to nothing
            throw new IllegalArgumentException("certificate is empty");
        }
        created = FieldRules.instant(created, "created");
        updated = FieldRules.instant(updated, "updated");
    }

    /** A record holding {@code certificateDer}, base64-encoded. */
    public static DeviceIdentityRecord of(UUID id, String name, SecretBytes privateKey, byte[] certificateDer,
            Instant created) {
        return new DeviceIdentityRecord(id, name, privateKey, Base64.getEncoder().encodeToString(certificateDer),
                created, created);
    }

    /** The certificate's DER encoding, a new array. */
    public byte[] certificateDer() {
        return Base64.getDecoder().decode(certificate);
    }

    @Override
    public void close() {
        privateKey.close();
    }
}
