package pm.vault.envelope;

import java.util.List;
import java.util.Objects;

/**
 * The authenticated vault header (ADR 0003). Immutable: the slot list is copied with
 * {@link List#copyOf} (OBJ06-J).
 *
 * @param kdf     passphrase KDF parameters
 * @param slots   unlock slots, at least one
 * @param created creation time, epoch seconds
 * @param saved   last save time, epoch seconds
 * @param saveSeq monotonic save counter, starts at 1 (rollback detection)
 */
public record EnvelopeHeader(KdfHeader kdf, List<SlotHeader> slots,
                             long created, long saved, long saveSeq) {

    /** Rejects nulls and freezes the slot list. */
    public EnvelopeHeader {
        Objects.requireNonNull(kdf, "kdf");
        slots = List.copyOf(Objects.requireNonNull(slots, "slots"));
    }

    /**
     * Returns a copy of this header for the next save.
     *
     * @param savedAt save time, epoch seconds
     * @throws ArithmeticException if the save counter would overflow (NUM00-J)
     */
    public EnvelopeHeader nextSave(long savedAt) {
        return new EnvelopeHeader(kdf, slots, created, savedAt, Math.addExact(saveSeq, 1L));
    }

    /**
     * Returns the first slot of {@code type}, or null if there is none.
     *
     * @param type slot type
     */
    public SlotHeader firstSlot(String type) {
        for (SlotHeader s : slots) {
            if (s.type().equals(type)) {
                return s;
            }
        }
        return null;
    }
}
