package pm.tui;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import pm.crypto.ConstantTime;
import pm.crypto.SecretBytes;

/**
 * Clears a copied password off the clipboard (SR-503, AC-63): after {@link #clearAfter()} (30 s by
 * default), on lock and on quit. It clears only while the clipboard still holds its copy (compared
 * in constant time against a {@link SecretBytes} copy it zeroes once done), so text the user
 * copied afterwards stays.
 * When the clipboard cannot be read back it clears anyway. GUI-thread confined, like
 * {@link TuiController}. A process that is killed cannot clear anything; that is a documented
 * limit, as are clipboard managers that keep their own history.
 */
final class ClipboardGuard {
    /** SR-503's default. */
    static final Duration DEFAULT_CLEAR_AFTER = Duration.ofSeconds(30);

    /** What {@link #copy} did. */
    enum Copied {
        /** On the clipboard; cleared at {@link #clearAfter()}. */
        COPIED,
        /** This platform has no clipboard pm can use. */
        UNAVAILABLE,
        /** The clipboard tool failed or did not answer in time. */
        FAILED
    }

    private final Clipboard clipboard;
    private final Duration clearDelay;
    private SecretBytes copied;
    private Instant clearAt;

    ClipboardGuard(Clipboard clipboard, Duration clearAfter) {
        this.clipboard = Objects.requireNonNull(clipboard, "clipboard");
        if (clearAfter.isNegative() || clearAfter.isZero()) {
            throw new IllegalArgumentException("clearAfter must be positive");
        }
        this.clearDelay = clearAfter;
    }

    /** How long a copy stays on the clipboard. */
    Duration clearAfter() {
        return clearDelay;
    }

    /** Places {@code secret} on the clipboard at {@code now} and schedules its clearing. */
    Copied copy(SecretBytes secret, Instant now) {
        if (!clipboard.available()) {
            return Copied.UNAVAILABLE;
        }
        if (!secret.apply(clipboard::copy)) {
            return Copied.FAILED;
        }
        forget();
        copied = secret.apply(SecretBytes::copyOf);
        clearAt = now.plus(clearDelay);
        return Copied.COPIED;
    }

    /** Whether a copy is waiting to be cleared. */
    boolean pending() {
        return copied != null;
    }

    /** Clears the copy once its time is up; called on every UI tick. */
    void tick(Instant now) {
        if (clearAt != null && !now.isBefore(clearAt)) {
            clearNow();
        }
    }

    /**
     * Clears the copy now if the clipboard still holds it (lock and quit). Idempotent.
     *
     * @return false only when the clipboard held the copy, or could not be read, and clearing it
     *     failed; the copy is forgotten either way, since a stuck tool is not retried
     */
    boolean clearNow() {
        if (copied == null) {
            return true;
        }
        Optional<byte[]> current = clipboard.read();
        boolean ours = current.map(this::isOurs).orElse(true); // cannot tell: clear
        boolean cleared = !ours || clipboard.clear();
        forget();
        return cleared;
    }

    private boolean isOurs(byte[] text) {
        try {
            return copied.apply(mine -> ConstantTime.equals(mine, text));
        } finally {
            Arrays.fill(text, (byte) 0);
        }
    }

    private void forget() {
        if (copied != null) {
            copied.close();
        }
        copied = null;
        clearAt = null;
    }
}
