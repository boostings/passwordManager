package pm.cli;

import java.util.Objects;

/**
 * Invalid invocation or input; carries only a catalogue entry, never user input (SR-501, ERR01-J).
 */
final class UsageException extends Exception {
    private static final long serialVersionUID = 1L;

    private final Messages catalogueEntry;

    UsageException(Messages entry) {
        super(entry.name());
        this.catalogueEntry = Objects.requireNonNull(entry, "entry");
    }

    /** The catalogue message to show. */
    Messages reason() {
        return catalogueEntry;
    }
}
