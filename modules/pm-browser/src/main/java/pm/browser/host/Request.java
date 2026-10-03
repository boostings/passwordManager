package pm.browser.host;

import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretChars;

/**
 * One validated request from the extension (ADR 0014 §3). Every request carries the extension's
 * correlation {@link #id()}, echoed in the reply. Origins are checked for shape here and
 * canonicalised by the bridge.
 */
public sealed interface Request extends AutoCloseable
        permits Request.Hello, Request.Lookup, Request.Fill, Request.Save, Request.Generate {

    /** The extension's correlation id: 1–64 of {@code [A-Za-z0-9_-]}. */
    String id();

    /** Releases any secret the request holds. */
    @Override
    default void close() {
        // most requests hold no secret
    }

    /**
     * Version negotiation.
     *
     * @param id correlation id
     */
    record Hello(String id) implements Request {
        /** The only protocol version. */
        public static final int VERSION = 1;

        public Hello {
            Objects.requireNonNull(id, "id");
        }
    }

    /**
     * Logins registered for exactly {@code origin}: ids, titles and usernames, never passwords.
     *
     * @param id correlation id
     * @param origin the page origin as the extension saw it
     */
    record Lookup(String id, String origin) implements Request {
        public Lookup {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(origin, "origin");
        }
    }

    /**
     * Release one login's username and password to fill into {@code origin}.
     *
     * @param id correlation id
     * @param origin the page origin
     * @param entry the login record id
     */
    record Fill(String id, String origin, UUID entry) implements Request {
        public Fill {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(origin, "origin");
            Objects.requireNonNull(entry, "entry");
        }
    }

    /**
     * Store a new login for {@code origin}. Owns {@code password}; {@link #close()} zeroes it.
     *
     * @param id correlation id
     * @param origin the page origin
     * @param username account name, possibly empty
     * @param password the password
     */
    record Save(String id, String origin, String username, SecretChars password) implements Request {
        public Save {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(origin, "origin");
            Objects.requireNonNull(username, "username");
            Objects.requireNonNull(password, "password");
        }

        @Override
        public void close() {
            password.close();
        }
    }

    /**
     * Generate a new password for {@code origin} and store it as a new login before it is
     * released, so a filled password can never exist only in the page (ADR 0014 §6).
     *
     * @param id correlation id
     * @param origin the page origin
     * @param username account name stored with the new login, possibly empty
     * @param policy what the password must look like
     */
    record Generate(String id, String origin, String username, Policy policy) implements Request {
        public Generate {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(origin, "origin");
            Objects.requireNonNull(username, "username");
            Objects.requireNonNull(policy, "policy");
        }
    }

    /**
     * A password policy: length and the character classes that must each appear at least once.
     *
     * @param length characters, {@link #MIN_LENGTH} to {@link #MAX_LENGTH}
     * @param lower include a–z
     * @param upper include A–Z
     * @param digits include 0–9
     * @param symbols include ASCII punctuation
     */
    record Policy(int length, boolean lower, boolean upper, boolean digits, boolean symbols) {
        /** Shortest password generated. */
        public static final int MIN_LENGTH = 8;
        /** Longest password generated. */
        public static final int MAX_LENGTH = 128;

        /**
         * Validates the policy.
         *
         * @throws IllegalArgumentException {@code BAD_POLICY} if out of range or no class is chosen
         */
        public Policy {
            if (length < MIN_LENGTH || length > MAX_LENGTH || !(lower || upper || digits || symbols)) {
                throw new IllegalArgumentException("BAD_POLICY");
            }
        }
    }
}
