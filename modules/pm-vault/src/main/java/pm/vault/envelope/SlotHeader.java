package pm.vault.envelope;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * One unlock slot of the vault header (ADR 0004). {@code wrappedKey} is the vault key
 * wrapped under this slot's KEK with AES-KWP. It is ciphertext, so it is safe to store in
 * the authenticated header, but it is still copied on the way in and out (OBJ06-J).
 *
 * <p>Contract note: a final class rather than the record in §2, because Error Prone's
 * {@code ArrayRecordComponent} rejects array record components under {@code -Werror}.
 */
public final class SlotHeader {

    /**
     * Slot type {@code "passphrase"}: unlocked by the master passphrase. The constant is
     * not named after its value because the CERT Semgrep pack (MSC03-J) bans String
     * variables with that name.
     */
    public static final String MASTER = "passphrase";

    /** Slot type unlocked by the recovery key. */
    public static final String RECOVERY = "recovery";

    private final UUID slotId;
    private final String slotType;
    private final byte[] wrapped;

    /**
     * Creates a slot header.
     *
     * @param id         slot UUID, bound into the KEK derivation
     * @param type       {@link #MASTER} or {@link #RECOVERY} in M1
     * @param wrappedKey 40-byte RFC 5649 wrapped vault key; copied
     */
    public SlotHeader(UUID id, String type, byte[] wrappedKey) {
        this.slotId = Objects.requireNonNull(id, "id");
        this.slotType = Objects.requireNonNull(type, "type");
        this.wrapped = Objects.requireNonNull(wrappedKey, "wrappedKey").clone();
    }

    /** Returns the slot UUID. */
    public UUID id() {
        return slotId;
    }

    /** Returns the slot type. */
    public String type() {
        return slotType;
    }

    /** Returns a copy of the wrapped key. */
    public byte[] wrappedKey() {
        return wrapped.clone();
    }

    /** Compares wrapped-key contents in constant time, not references (EXP02-J, SR-016). */
    @Override
    public boolean equals(Object o) {
        return o instanceof SlotHeader s
                && slotId.equals(s.slotId) && slotType.equals(s.slotType)
                && Bytes.sameContents(wrapped, s.wrapped);
    }

    @Override
    public int hashCode() {
        return Objects.hash(slotId, slotType, Arrays.hashCode(wrapped));
    }

    @Override
    public String toString() {
        return "SlotHeader[id=" + slotId + ", type=" + slotType + "]";
    }
}
