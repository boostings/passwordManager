package pm.crypto;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks one of the few reviewed methods allowed to hold a secret in a {@code String}
 * (Semgrep {@code cert.MSC03-J.secret-in-string} allowlist, ADR 0008).
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
public @interface SecretBoundary {
    /** Why a String is unavoidable here. */
    String reason();
}
