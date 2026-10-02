package pm.vault.envelope;

import java.util.Objects;

/**
 * A structurally valid vault file, not yet authenticated. Nothing in here may be trusted
 * until AES-GCM has verified the tag over {@link #aad()} (SR-020). Arrays are copied on the
 * way in and out (OBJ05-J, OBJ06-J).
 *
 * <p>Contract note: a final class rather than the record in §2, because Error Prone's
 * {@code ArrayRecordComponent} rejects array record components under {@code -Werror}.
 * Equality is identity: two parses of a file are never compared.
 */
public final class ParsedEnvelope {
    private final EnvelopeHeader parsedHeader;
    private final byte[] aadBytes;
    private final byte[] saltBytes;
    private final byte[] sealed;

    /**
     * Creates a parsed envelope; every array is copied.
     *
     * @param header     decoded header
     * @param aad        exact file bytes {@code [0, 14 + headerLen + 32)}
     * @param dataSalt   32-byte per-save HKDF salt
     * @param ciphertext AES-256-GCM ciphertext with its 16-byte tag
     */
    public ParsedEnvelope(EnvelopeHeader header, byte[] aad, byte[] dataSalt, byte[] ciphertext) {
        this.parsedHeader = Objects.requireNonNull(header, "header");
        this.aadBytes = Objects.requireNonNull(aad, "aad").clone();
        this.saltBytes = Objects.requireNonNull(dataSalt, "dataSalt").clone();
        this.sealed = Objects.requireNonNull(ciphertext, "ciphertext").clone();
    }

    /** Returns the decoded, unauthenticated header. */
    public EnvelopeHeader header() {
        return parsedHeader;
    }

    /** Returns a copy of the AAD. */
    public byte[] aad() {
        return aadBytes.clone();
    }

    /** Returns a copy of the data salt. */
    public byte[] dataSalt() {
        return saltBytes.clone();
    }

    /** Returns a copy of the ciphertext. */
    public byte[] ciphertext() {
        return sealed.clone();
    }

    @Override
    public String toString() {
        return "ParsedEnvelope[header=" + parsedHeader + ", ciphertextLength=" + sealed.length + "]";
    }
}
