package pm.crypto.ssh;

/**
 * Checked SSH key or agent failure carrying only an error code; the message is the code name, with
 * no key material, path or agent text (SR-501, ERR01-J).
 */
public final class SshException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Fixed error catalogue. */
    public enum Code {
        /** The key file is not a well-formed unencrypted {@code openssh-key-v1} key. */
        MALFORMED_KEY,
        /** The key file is passphrase-protected; decrypt it with {@code ssh-keygen -p} first (ADR 0013). */
        ENCRYPTED_KEY,
        /** The key algorithm is not Ed25519 or ECDSA P-256. */
        UNSUPPORTED_KEY,
        /** No agent socket exists at the path, or nothing listens on it. */
        NO_AGENT,
        /** The socket is a link, not a socket, not owned by this user, or in a group/world-writable directory. */
        UNSAFE_SOCKET,
        /** The agent answered {@code SSH_AGENT_FAILURE}. */
        AGENT_REFUSED,
        /** The agent's reply was oversized, truncated, of an unexpected type or malformed. */
        BAD_REPLY,
        /** The export target already exists (or is a link). */
        TARGET_EXISTS,
        /** The export target's file system cannot create an owner-only (0600) file. */
        UNSAFE_TARGET,
        /** An I/O error on the agent socket or the export file. */
        IO
    }

    private final Code errorCode;

    /** Creates an exception whose message is {@code code.name()}. */
    public SshException(Code code) {
        super(code.name());
        this.errorCode = code;
    }

    /** The error code. */
    public Code code() {
        return errorCode;
    }
}
