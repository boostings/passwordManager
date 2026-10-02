package pm.vault.record;

import java.util.List;
import pm.crypto.SecretBytes;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane D replaces this file.
 *
 * <p>Encodes and decodes the record payload {@code {"schema_version":1,"records":[...]}}
 * (ADR 0006). Decoding is all-or-nothing.
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class RecordCodec {
    /** Payload schema version. */
    public static final int SCHEMA_VERSION = 1;

    private RecordCodec() {
    }

    /** Encodes {@code records} as the plaintext payload; the caller closes the result. */
    public static SecretBytes encodePayload(List<VaultRecord> records) {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Decodes an authenticated payload, all or nothing. */
    public static List<VaultRecord> decodePayload(SecretBytes plaintext) throws RecordException {
        throw new UnsupportedOperationException("M1 stub");
    }
}
