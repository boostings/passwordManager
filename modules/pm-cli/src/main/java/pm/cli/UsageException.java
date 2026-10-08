package pm.cli;

import java.util.Objects;
import pm.approval.AuditException;

/**
 * Invalid invocation or input; carries only a catalogue entry, never user input (SR-501, ERR01-J).
 * An audit log failure also carries the number of the last intact entry, which the user needs to
 * archive the log (approval-model §7).
 */
final class UsageException extends Exception {
    private static final long serialVersionUID = 1L;

    private final Messages catalogueEntry;
    private final long entry;

    UsageException(Messages entry) {
        this(entry, -1);
    }

    private UsageException(Messages catalogueEntry, long entry) {
        super(catalogueEntry.name());
        this.catalogueEntry = Objects.requireNonNull(catalogueEntry, "entry");
        this.entry = entry;
    }

    /**
     * The audit log refused an entry, so the operation was not done: a tampered or cut log names
     * its last intact entry, a busy one asks to try again, and only a plain I/O failure keeps the
     * generic text.
     */
    static UsageException audit(AuditException e) {
        return switch (e.code()) {
            case TAMPERED, TRUNCATED -> new UsageException(Messages.AUDIT_BROKEN, e.entry());
            case BUSY -> new UsageException(Messages.AUDIT_BUSY);
            case UNSAFE_FILE -> new UsageException(Messages.AUDIT_UNSAFE);
            case TOO_LARGE -> new UsageException(Messages.AUDIT_TOO_LARGE);
            case IO -> new UsageException(Messages.AUDIT_UNAVAILABLE);
        };
    }

    /** The catalogue message to show. */
    Messages reason() {
        return catalogueEntry;
    }

    /** The text to print: the catalogue entry, or for a broken audit log its last intact entry and what to do. */
    String text() {
        return entry < 0 ? catalogueEntry.text() : brokenLog(entry);
    }

    /** What the CLI prints for an audit log that is tampered or truncated after entry {@code n}. */
    static String brokenLog(long n) {
        return Messages.AUDIT_BROKEN.text() + n + Messages.AUDIT_BROKEN_ARCHIVE.text();
    }
}
