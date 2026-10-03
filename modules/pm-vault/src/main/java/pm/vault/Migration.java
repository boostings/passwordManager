package pm.vault;

import pm.crypto.SecretBytes;
import pm.vault.record.RecordException;

/**
 * One format step, {@code fromVersion() -> fromVersion() + 1} (ADR 0015).
 *
 * <p>A migration is a pure function over the authenticated plaintext payload: no I/O, no clock,
 * no randomness, no state. It runs only after the source file's GCM tag has verified (SR-020),
 * and its output is decoded by the current record codec before anything is written, so a
 * migration that produces an invalid payload cannot reach the disk.
 */
interface Migration {

    /** Returns the format version this step reads. */
    int fromVersion();

    /**
     * Transforms a version {@link #fromVersion()} payload into a version {@code fromVersion() + 1}
     * payload.
     *
     * @param payload authenticated plaintext; not closed, the caller keeps ownership
     * @return the next version's payload; the caller closes it
     * @throws RecordException if the payload does not have the shape this version requires
     */
    SecretBytes apply(SecretBytes payload) throws RecordException;
}
