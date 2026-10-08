package pm.tui;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;

/**
 * Who is behind each browser prompt (ADR 0014 §8): the relay registers the peer of a request
 * while its prompt waits, and the approval dialog shows that peer. A request the relay did not
 * register (for example one sent straight to the broker socket) has no peer here, and the dialog
 * says so. Each peer may have at most one prompt waiting at a time. With the peer the relay
 * registers whether the asking extension is still allowlisted, so a prompt whose extension was
 * taken off the allowlist is denied before the dialog shows it.
 */
final class RelayPeers {
    /**
     * One socket peer.
     *
     * @param key the host instance the peer claims ({@link BrowserRelay#HOST_INSTANCE})
     * @param line what the prompt shows: the start of that instance, marked as unverified
     */
    record Peer(String key, String line) {
        Peer {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(line, "line");
        }
    }

    /** A registered prompt: its peer line and whether its extension is still allowlisted. */
    private record Asking(String line, BooleanSupplier allowed) {
    }

    private final Map<UUID, Asking> asking = new ConcurrentHashMap<>();
    private final Set<String> waiting = ConcurrentHashMap.newKeySet();

    /**
     * Registers {@code peer} for the prompt of {@code requestId}, asked for an extension that
     * {@code allowed} says is still allowlisted (read again on every call).
     *
     * @return false, registering nothing, if {@code peer} already has a prompt waiting
     */
    boolean begin(UUID requestId, Peer peer, BooleanSupplier allowed) {
        Objects.requireNonNull(allowed, "allowed");
        if (!waiting.add(peer.key())) {
            return false;
        }
        asking.put(requestId, new Asking(peer.line(), allowed));
        return true;
    }

    /** The prompt of {@code requestId} is answered (or withdrawn): forget it. */
    void end(UUID requestId, Peer peer) {
        asking.remove(requestId);
        waiting.remove(peer.key());
    }

    /** The peer line for the prompt of {@code requestId}, if the relay registered one. */
    Optional<String> line(UUID requestId) {
        return Optional.ofNullable(asking.get(requestId)).map(Asking::line);
    }

    /**
     * False if the relay registered the prompt of {@code requestId} and its extension is no longer
     * allowlisted; true otherwise (a prompt the relay did not register is not the relay's to drop).
     */
    boolean stillAllowed(UUID requestId) {
        Asking a = asking.get(requestId);
        return a == null || a.allowed().getAsBoolean();
    }
}
