package pm.vault.record;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import pm.crypto.SecretBytes;

/**
 * Per-project secrets and configuration (ADR 0006). Variable values are {@link SecretBytes}
 * (ADR 0008); maps are defensively copied (OBJ06-J).
 *
 * @param id            stable record id
 * @param title         display title, at most 256 chars
 * @param canonicalPath canonical project directory
 * @param gitRemote     git remote url, may be empty
 * @param variables     secret variables, closed by {@link #close()}
 * @param config        non-secret configuration
 * @param created       creation time
 * @param updated       last modification time
 */
public record ProjectRecord(
        UUID id,
        String title,
        String canonicalPath,
        String gitRemote,
        Map<String, SecretBytes> variables,
        Map<String, String> config,
        Instant created,
        Instant updated
) implements VaultRecord {
    /** Null checks, length bounds and defensive copies (ADR 0006, OBJ06-J). */
    public ProjectRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(canonicalPath, "canonicalPath");
        Objects.requireNonNull(gitRemote, "gitRemote");
        Objects.requireNonNull(variables, "variables");
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        RecordLimits.checkTitle(title);
        variables = Map.copyOf(variables);
        config = Map.copyOf(config);
    }

    /** Closes every secret variable (ADR 0008). */
    @Override
    public void close() {
        for (SecretBytes value : variables.values()) {
            value.close();
        }
    }
}
