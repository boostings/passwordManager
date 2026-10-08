package pm.approval;

import java.util.Objects;

/** The audit log could not be opened or verified. Carries a code and an entry number only. */
public final class AuditException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why. */
    public enum Code {
        /** An entry was edited, reordered or removed: the chain breaks after {@link #entry()}. */
        TAMPERED,
        /** Entries at the end are missing or the last line is cut: intact up to {@link #entry()}. */
        TRUNCATED,
        /** The log is a symbolic link, or is readable by other users. */
        UNSAFE_FILE,
        /** The log is larger than {@link AuditLog#MAX_FILE_BYTES}. */
        TOO_LARGE,
        /** Another pm process held the log for longer than {@link AuditLog#LOCK_WAIT}; nothing was written. */
        BUSY,
        /** Reading or writing failed. */
        IO
    }

    private final Code reason;
    private final long lastGood;

    AuditException(Code code, long entry, Throwable cause) {
        super(Objects.requireNonNull(code, "code").name() + " after entry " + entry);
        this.reason = code;
        this.lastGood = entry;
        if (cause != null) {
            // Keep the type only: messages of I/O errors carry paths.
            addSuppressed(new Exception(cause.getClass().getName()));
            for (Throwable also : cause.getSuppressed()) {
                addSuppressed(new Exception(also.getClass().getName())); // such as a rollback that failed too
            }
        }
    }

    /** Why. */
    public Code code() {
        return reason;
    }

    /** The last entry known to be intact; 0 if none. */
    public long entry() {
        return lastGood;
    }

    /** The message the user sees (approval-model §7). */
    public String userMessage() {
        return switch (reason) {
            case TAMPERED, TRUNCATED -> "audit log tampered or truncated after entry " + lastGood;
            case UNSAFE_FILE -> "audit log is a link or is readable by other users";
            case TOO_LARGE -> "audit log is too large; archive it";
            case BUSY -> "the audit log is in use by another pm process; try again";
            case IO -> "audit log could not be read or written";
        };
    }
}
