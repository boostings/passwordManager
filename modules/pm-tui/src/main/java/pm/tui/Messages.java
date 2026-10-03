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
