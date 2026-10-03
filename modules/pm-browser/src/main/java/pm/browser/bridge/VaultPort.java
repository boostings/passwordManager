package pm.browser.bridge;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.approval.Grant;
import pm.browser.host.HostException;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

/**
 * What the bridge needs from the vault, so {@code pm-browser} does not depend on the module that
 * holds the open vault (M5.4 implements it in the TUI process). The two methods that touch a
 * password take the broker's {@link Grant}, which only the broker can create, and must
 * {@link Grant#consume() consume} it; the bridge refuses to answer if they did not.
 */
public interface VaultPort {

    /**
     * A login's metadata: never its password.
     *
     * @param id record id
     * @param title record title
     * @param username account name, possibly empty
     * @param urls the URLs registered on the record, as stored
     */
    record Login(UUID id, String title, String username, List<String> urls) {
        public Login {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(title, "title");
            Objects.requireNonNull(username, "username");
            urls = List.copyOf(urls);
        }
    }

    /** Metadata of every login in the open vault. */
    List<Login> logins();

    /**
     * The password of login {@code entry}, released under {@code grant}, which this call consumes.
     *
     * @throws HostException {@code NOT_FOUND} if the login is gone
     */
    SecretBytes password(Grant grant, UUID entry) throws HostException;

    /**
     * Stores a new login for {@code origin} under {@code grant}, which this call consumes. Does
     * not take ownership of {@code password}.
     *
     * @return the new record id
     */
    UUID save(Grant grant, Origin origin, String username, SecretChars password) throws HostException;
}
