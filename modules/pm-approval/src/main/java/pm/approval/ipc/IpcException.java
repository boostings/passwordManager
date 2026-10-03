package pm.approval.ipc;

import java.util.Objects;

/** An IPC failure. Carries a code only; never a path or frame content. */
public final class IpcException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why. */
    public enum Code {
        /** The run directory or token file is a link, not owned by this user, or open to others. */
        UNSAFE_PATH,
        /** No broker is listening, or the vault is locked (no token file). */
        NO_BROKER,
        /** A frame is larger than allowed. */
        TOO_LARGE,
        /** A frame could not be decoded. */
        MALFORMED,
        /** Reading or writing failed. */
        IO
    }

    private final Code reason;

    IpcException(Code code, Throwable cause) {
        super(Objects.requireNonNull(code, "code").name());
        this.reason = code;
        if (cause != null) {
            addSuppressed(new Exception(cause.getClass().getName())); // type only: messages carry paths
        }
    }

    /** Why. */
    public Code code() {
        return reason;
    }
}
