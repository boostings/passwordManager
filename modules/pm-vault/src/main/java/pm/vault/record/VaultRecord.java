package pm.vault.record;

import java.time.Instant;
import java.util.UUID;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>One vault entry (ADR 0006 record schema). Secret fields are {@code SecretBytes} (ADR 0008);
 * {@link #close()} closes them.
 */
public sealed interface VaultRecord extends AutoCloseable
        permits LoginRecord, WifiRecord, SshKeyRecord, ProjectRecord {

    /** Stable record id. */
    UUID id();

    /** Display title. */
    String title();

    /** Creation time. */
    Instant created();

    /** Last modification time. */
    Instant updated();

    /** Closes every contained {@code SecretBytes}. */
    @Override
    void close();
}
