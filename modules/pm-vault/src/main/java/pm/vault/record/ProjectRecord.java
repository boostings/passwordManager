package pm.vault.record;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretBytes;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>Per-project secrets and configuration (ADR 0006). Maps are defensively copied (OBJ06-J).
 */
public record ProjectRecord(UUID id, String title, String canonicalPath, String gitRemote,
        Map<String, SecretBytes> variables, Map<String, String> config, Instant created,
        Instant updated) implements VaultRecord {

    /** Null checks and defensive copies. */
    public ProjectRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(canonicalPath, "canonicalPath");
        Objects.requireNonNull(gitRemote, "gitRemote");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        variables = Map.copyOf(variables);
        config = Map.copyOf(config);
        // Lane D: length bounds
    }

    /** Closes every secret variable. */
    @Override
    public void close() {
        variables.values().forEach(SecretBytes::close);
    }
}
