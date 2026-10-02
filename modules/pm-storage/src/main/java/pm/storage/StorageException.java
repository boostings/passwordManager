package pm.storage;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane B replaces this file.
 *
 * <p>Checked storage failure carrying only an error code; the message is the code name and never a
 * path (SR-501, ERR01-J).
 */
public final class StorageException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Fixed error catalogue. */
    public enum Code {
        /** The vault file does not exist. */
        NOT_FOUND,
        /** The file exceeds {@link VaultFileStore#MAX_FILE_BYTES}. */
        TOO_LARGE,
        /** The vault path is a symbolic link. */
        SYMLINK_REFUSED,
        /** Another process holds the vault lock. */
        LOCKED_BY_OTHER,
        /** Permissions are not owner-only. */
        PERMISSIONS,
        /** Any other I/O failure. */
        IO
    }

    private final Code errorCode;

    /** Creates an exception whose message is {@code code.name()}. */
    public StorageException(Code code, Throwable cause) {
        super(code.name(), cause);
        this.errorCode = code;
    }

    /** The error code. */
    public Code code() {
        return errorCode;
    }
}
