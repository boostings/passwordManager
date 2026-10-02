package pm.vault.record;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import pm.crypto.SecretBytes;

record ProjectRecord(
        UUID id,
        String title,
        String canonicalPath,
        String gitRemote,
        Map<String, SecretBytes> variables,
        Map<String, String> config,
        Instant created,
        Instant updated
) implements VaultRecord {
    public ProjectRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(canonicalPath, "canonicalPath");
        Objects.requireNonNull(gitRemote, "gitRemote");
        Objects.requireNonNull(variables, "variables");
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(created, "created");
        Objects.requireNonNull(updated, "updated");
        if (title.length() > 256) {
            throw new IllegalArgumentException("title too long");
        }
        variables = Map.copyOf(variables);
        config = Map.copyOf(config);
    }

    @Override
    public void close() {
        for (SecretBytes value : variables.values()) {
            value.close();
        }
    }
}
