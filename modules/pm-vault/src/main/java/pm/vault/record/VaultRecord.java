package pm.vault.record;

import java.time.Instant;
import java.util.UUID;

/**
 * One vault entry (ADR 0006 record schema). Secret fields are {@code SecretBytes} (ADR 0008);
 * {@link #close()} closes them.
 */
public sealed interface VaultRecord extends AutoCloseable
        permits LoginRecord, WifiRecord, SshKeyRecord, ProjectRecord {

    /**
     * Stable record id.
     *
     * @return the id
     */
    UUID id();

    /**
     * Display title.
     *
     * @return the title
     */
    String title();

    /**
     * Creation time.
     *
     * @return the creation instant
     */
    Instant created();

    /**
     * Last modification time.
     *
     * @return the update instant
     */
    Instant updated();

    /** Closes every contained {@code SecretBytes}. */
    @Override
    void close();
}
