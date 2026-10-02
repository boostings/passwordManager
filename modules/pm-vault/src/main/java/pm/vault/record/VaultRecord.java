package pm.vault.record;

import java.time.Instant;
import java.util.UUID;

public sealed interface VaultRecord extends AutoCloseable permits LoginRecord, WifiRecord, SshKeyRecord, ProjectRecord {
    UUID id();
    String title();
    Instant created();
    Instant updated();

    @Override
    void close();
}
