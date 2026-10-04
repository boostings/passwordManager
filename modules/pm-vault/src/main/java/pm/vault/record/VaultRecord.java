package pm.vault.record;

import java.time.Instant;
import java.util.UUID;

/**
 * A typed vault entry (plan.md section 4, ADR 0006, schema in {@code docs/schemas/records.cddl}).
 *
 * <p>A record owns the {@link pm.crypto.SecretBytes} it holds: {@link #close()} zero-fills every
 * one of them (ADR 0008, SR-505) and may be called more than once. All other fields are immutable.
 * Timestamps are whole seconds from 1970-01-01T00:00:00Z on, because that is what the payload
 * stores; the constructors truncate finer instants and refuse earlier ones.
 */
public sealed interface VaultRecord extends AutoCloseable permits LoginRecord, WifiRecord, SshKeyRecord, ProjectRecord,
        DeviceRecord {
    /** Returns the record's identity, unique within a vault. */
    UUID id();

    /** Returns the display title. */
    String title();

    /** Returns when the record was created, in whole seconds. */
    Instant created();

    /** Returns when the record was last changed, in whole seconds. */
    Instant updated();

    /** Zero-fills every secret this record holds. Idempotent. */
    @Override
    void close();
}
