package pm.tui;

import java.util.Optional;
import pm.vault.VaultException;
import pm.vault.record.VaultRecord;

/**
 * Puts a new or edited record into the session and saves the vault, so that a failed save leaves
 * the session as it was (ADR 0008). Failures come back as catalogue text only (SR-501).
 */
final class RecordStore {
    private RecordStore() {
    }

    /**
     * Adds {@code added} and saves. If the save fails, the record is taken out again and zeroed.
     *
     * @return the message for a failed save; empty once saved
     * @throws IllegalStateException if the session refuses the put; the record is zeroed first
     */
    static Optional<String> add(Session session, VaultRecord added) {
        put(session, added);
        try {
            session.save();
            return Optional.empty();
        } catch (VaultException e) {
            session.remove(added.id());
            added.close();
            return Optional.of(Messages.of(e.code()));
        }
    }

    /**
     * Replaces {@code old} with {@code edited} (same id) and saves. If the save fails, {@code old}
     * goes back: the session retired it on the put and closes it only on lock, so it is still
     * whole, and {@code edited} is retired in its place.
     *
     * @return the message for a failed save; empty once saved
     * @throws IllegalStateException if the session refuses the put; {@code edited} is zeroed first
     */
    static Optional<String> replace(Session session, VaultRecord old, VaultRecord edited) {
        put(session, edited);
        try {
            session.save();
            return Optional.empty();
        } catch (VaultException e) {
            session.put(old);
            return Optional.of(Messages.of(e.code()));
        }
    }

    private static void put(Session session, VaultRecord r) {
        try {
            session.put(r);
        } catch (RuntimeException e) {
            r.close();
            throw new IllegalStateException("session put failed", e); // fixed text only (SR-501)
        }
    }
}
