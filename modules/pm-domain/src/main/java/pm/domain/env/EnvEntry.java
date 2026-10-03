package pm.domain.env;

import java.util.Objects;
import pm.crypto.SecretBytes;

/**
 * One environment variable: a non-secret name and a secret value it owns (ADR 0008).
 *
 * @param name variable name, matching {@link DotEnv#isValidName}
 * @param value UTF-8 value; closed by {@link #close()}
 */
public record EnvEntry(String name, SecretBytes value) implements AutoCloseable {
    /**
     * @throws IllegalArgumentException {@code BAD_NAME} if {@code name} is not a valid variable name
     */
    public EnvEntry {
        Objects.requireNonNull(value, "value");
        if (!DotEnv.isValidName(Objects.requireNonNull(name, "name"))) {
            throw new IllegalArgumentException("BAD_NAME");
        }
    }

    @Override
    public void close() {
        value.close();
    }
}
