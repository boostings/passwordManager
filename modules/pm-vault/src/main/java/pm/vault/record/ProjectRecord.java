package pm.vault.record;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretBytes;

/**
 * A software project with its environment variables (plan.md section 4, ADR 0006,
 * {@code project-record} in {@code docs/schemas/records.cddl}).
 *
 * @param id record identity
 * @param title project name, at most 256 characters
 * @param canonicalPath canonical filesystem path, at most 32,768 characters
 * @param gitRemote git remote URL, at most 8,192 characters
 * @param variables at most 1,024 variables; each name is at most 1,024 characters and each value
 *     is a secret of at most 64 KiB, owned by this record and zero-filled by {@link #close()}
 *     (ADR 0008)
 * @param config at most 1,024 non-secret settings; each name is at most 1,024 characters and each
 *     value at most 65,536 characters
 * @param created creation time, truncated to whole seconds
 * @param updated last change, truncated to whole seconds
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
    /**
     * Validates every field and takes unmodifiable copies of the maps (MET00-J, OBJ06-J). The
     * copied variable map shares its {@link SecretBytes} values with the caller's map.
     *
     * @throws NullPointerException if a component, a map key or a map value is null
     * @throws IllegalArgumentException if a field exceeds its bound, a text holds an unpaired
     *     surrogate, or an instant is before 1970 or after 9999
     */
    public ProjectRecord {
        Objects.requireNonNull(id, "id");
        title = FieldRules.text(title, FieldRules.MAX_TITLE_CHARS, "title");
        canonicalPath = FieldRules.text(canonicalPath, FieldRules.MAX_PATH_CHARS, "canonicalPath");
        gitRemote = FieldRules.text(gitRemote, FieldRules.MAX_URL_CHARS, "gitRemote");
        variables = FieldRules.secrets(variables, "variables");
        config = FieldRules.settings(config, "config");
        created = FieldRules.instant(created, "created");
        updated = FieldRules.instant(updated, "updated");
    }

    @Override
    public void close() {
        variables.values().forEach(SecretBytes::close);
    }
}
