package pm.sharing.share;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import pm.sharing.wire.Octets;

/** Share ids this device has applied; an offer that repeats one is refused as a replay (SR-204). */
public final class ReceivedShares {
    private final ReentrantLock guard = new ReentrantLock();
    private final Set<Octets> applied = new HashSet<>();

    /** None applied. */
    public ReceivedShares() {
        // empty
    }

    /** Whether {@code id} was applied before. */
    public boolean contains(Octets id) {
        Objects.requireNonNull(id, "id");
        return locked(() -> applied.contains(id));
    }

    /** Records {@code id} as applied. */
    public void add(Octets id) {
        Objects.requireNonNull(id, "id");
        locked(() -> applied.add(id));
    }

    private <T> T locked(Supplier<T> body) {
        guard.lock();
        try {
            return body.get();
        } finally {
            guard.unlock();
        }
    }
}
