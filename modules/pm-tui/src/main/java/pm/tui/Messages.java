package pm.tui;

import java.time.Duration;
import java.util.Locale;
import pm.vault.VaultException;

/**
 * Fixed TUI message catalogue (SR-501, ERR01-J): every user-visible error is one of these
 * constants. No exception message, path, or record content is ever shown.
 */
final class Messages {
    /** What the UI shows in place of any secret field (SR-503; reveal/copy are M4). */
    static final String SECRET_MASK = "••••••••";

    static final String EMPTY_CREDENTIAL = "Enter a passphrase or recovery key.";
    static final String TITLE_REQUIRED = "A title is required.";
    static final String INVALID_INPUT = "The entry could not be saved: a field is invalid.";
    static final String UNSAFE_CHARACTER = "Control and formatting characters are not allowed.";
    static final String UNLOCKING = "Unlocking…";
    static final String SAVED = "Login saved";
    static final String EMPTY_VAULT = "Your vault is empty";
    static final String EMPTY_VAULT_HINT = "Press Ctrl+N to add your first login.";
    static final String NO_MATCHES = "No matches";
    static final String NO_MATCHES_HINT = "Try a shorter search, or press Esc to clear it.";

    // M4.4: tools menu, generator, health view, ssh-agent actions.
    static final String BAD_POLICY = "Length is 4 to 1024; a passphrase has 3 to 64 words.";
    static final String GENERATED_HINT = "Shown here only; it is not saved. Close or lock to clear it.";
    static final String HEALTH_CLEAN = "No weak, reused or old passwords.";
    static final String BREACH_HINT = "Breach check: run 'pm health --breach' in a terminal;"
            + " it sends a 5-character hash prefix per password, so it never runs on its own.";
    static final String SELECT_SSH_KEY = "Select an SSH key in the list first.";
    static final String SSH_WORKING = "Talking to ssh-agent...";

    // M5.4: why the browser extension is not served (dashboard header, ADR 0014 §8).
    static final String BROWSER_NOT_DEFAULT = "browser off: not the default vault";
    static final String BROWSER_NO_APPROVALS = "browser off: approvals unavailable";

    /** The status-line note for a relay that did not start. */
    static String browserOff(BrowserRelay.Unavailable reason) {
        if (reason == BrowserRelay.Unavailable.IN_USE) {
            return "browser off: another pm window serves it";
        } else if (reason == BrowserRelay.Unavailable.PATH_TOO_LONG) {
            return "browser off: socket path too long";
        }
        return "browser off: socket folder unsafe";
    }

    /** Entropy line under a generated secret. */
    static String entropy(double bits) {
        return String.format(Locale.ROOT, "%.1f bits of entropy", bits);
    }

    /** The message for an ssh-agent action's outcome (SR-501: fixed text only). */
    static String of(SshActions.Outcome outcome) {
        return switch (outcome) {
            case ADDED -> "Added to ssh-agent.";
            case REMOVED -> "Removed from ssh-agent.";
            case NOT_IN_AGENT -> "ssh-agent does not hold this key.";
            case NO_AGENT -> "No ssh-agent found. Start one and set SSH_AUTH_SOCK.";
            case UNSAFE_SOCKET -> "The ssh-agent socket failed its safety checks; nothing was sent.";
            case AGENT_FAILED -> "ssh-agent refused the request or sent an invalid reply.";
            case AGENT_TIMEOUT -> "ssh-agent did not answer in time; nothing more was sent.";
            case BAD_KEY -> "This item is not a usable unencrypted Ed25519 or ECDSA P-256 key.";
            case AUDIT_FAILED -> "The audit log could not be written, so the key was not sent.";
            case UNAVAILABLE -> "SSH agent actions are not available here.";
        };
    }

    private static final long SECONDS_PER_MINUTE = 60;

    private Messages() {
    }

    /** The catalogue message for {@code code}. */
    static String of(VaultException.Code code) {
        return switch (code) {
            case WRONG_CREDENTIAL -> "Wrong passphrase or recovery key.";
            case CORRUPT -> "The vault file is damaged and was not opened.";
            case UNSUPPORTED_VERSION -> "This vault needs a newer version of the app.";
            case ALREADY_EXISTS -> "A vault already exists at this location.";
            case LOCKED -> "The vault is locked or in use by another process.";
            case STORAGE -> "The vault file could not be read or written.";
            case INSUFFICIENT_MEMORY -> "This vault needs more memory than the app was given. Restart with a larger -Xmx.";
        };
    }

    /** Header count: {@code "3 items"}, or {@code "1 of 3"} while a search filters the list. */
    static String items(int shown, int total) {
        if (shown != total) {
            return String.format(Locale.ROOT, "%d of %d", shown, total);
        }
        return total == 1 ? "1 item" : String.format(Locale.ROOT, "%d items", total);
    }

    /** Status bar text, {@code "Locked in m:ss"} (SR-504). Negative input shows {@code 0:00}. */
    static String lockedIn(Duration remaining) {
        long total = Math.max(0, remaining.toSeconds());
        return String.format(Locale.ROOT, "Locked in %d:%02d",
                total / SECONDS_PER_MINUTE, total % SECONDS_PER_MINUTE);
    }
}
