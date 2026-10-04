package pm.vault;

import java.util.Objects;

/**
 * Failure of {@link Vault#signWithPasskey} (ADR 0016 addendum, SR-087, SR-088). The message is the
 * code name only, never record content or key material (SR-501, ERR01-J).
 */
public final class PasskeyException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why no signature was released. */
    public enum Code {
        /** The vault is locked. */
        LOCKED,
        /**
         * Called from inside an {@link AssertionPort} on the same thread while another signature
         * is in progress; refused so that signing order stays counter order. Nothing changed.
         */
        REENTRANT,
        /** The client data hash is not 32 bytes; nothing changed. */
        BAD_INPUT,
        /** No passkey record has the requested id. */
        NOT_FOUND,
        /**
         * The counter is at 2^32 - 1, the largest value authenticator data can carry. The
         * credential cannot sign again and nothing was saved; the user registers a new passkey.
         */
        COUNTER_EXHAUSTED,
        /**
         * Saving the advanced counter failed; the cause is the {@link VaultException}, or the
         * unchecked failure of the payload codec or store. Nothing was signed. The advanced value stays in memory (it is burnt, never reused), so the
         * counter never goes backwards even if the failed write did reach disk.
         */
        SAVE_FAILED,
        /** The stored key is not a valid storage form; the advanced counter is already saved. */
        BAD_KEY,
        /**
         * The {@link AssertionPort} threw (the cause), returned null, or returned authenticator data
         * that is not 37 bytes to 16 KiB or not bound to the record (RP ID hash, UP set, AT clear,
         * ED matching trailing bytes, counter equal to the persisted value); the advanced counter
         * is already saved and burnt, and nothing was signed.
         */
        SIGN_FAILED
    }

    private final Code failure;

    /**
     * Creates an exception for {@code code}.
     *
     * @param code failure class, never null
     * @param cause underlying exception, or null
     */
    public PasskeyException(Code code, Throwable cause) {
        super(Objects.requireNonNull(code, "code").name(), cause);
        this.failure = code;
    }

    /** Returns the failure class. */
    public Code code() {
        return failure;
    }
}
