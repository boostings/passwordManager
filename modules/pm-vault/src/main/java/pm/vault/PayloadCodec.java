package pm.vault;

import java.util.List;
import pm.crypto.SecretBytes;
import pm.vault.record.RecordCodec;
import pm.vault.record.RecordException;
import pm.vault.record.VaultRecord;

/**
 * Seam over {@link RecordCodec} so tests can count payload decodes and prove that no
 * record is parsed before the GCM tag verifies (SR-020, TamperTest). Production code always
 * uses {@link #RECORDS}.
 */
interface PayloadCodec {

    /** Encodes the record list as the plaintext payload; the caller closes the result. */
    SecretBytes encode(List<VaultRecord> records);

    /** Decodes an authenticated payload, all or nothing; the caller keeps ownership of {@code plaintext}. */
    List<VaultRecord> decode(SecretBytes plaintext) throws RecordException;

    /** The production codec (ADR 0006). */
    PayloadCodec RECORDS = new PayloadCodec() {
        @Override
        public SecretBytes encode(List<VaultRecord> records) {
            return RecordCodec.encodePayload(records);
        }

        @Override
        public List<VaultRecord> decode(SecretBytes plaintext) throws RecordException {
            return RecordCodec.decodePayload(plaintext);
        }
    };
}
