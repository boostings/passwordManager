package pm.tui.lan;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import javax.net.ssl.SSLServerSocket;
import pm.crypto.CryptoException;
import pm.sharing.net.Lan;
import pm.sharing.net.PeerLink;
import pm.sharing.pair.Lockout;
import pm.sharing.pair.PairedDevice;
import pm.sharing.pair.Pairer;
import pm.sharing.pair.PairingException;
import pm.sharing.pair.PairingSession;
import pm.sharing.pair.SasPrompt;

/**
 * The pairing ceremony from either end (lan-share.md §5). The responder listens and shows its
 * address; the initiator connects to it. Both sides accept any key during the handshake: the
 * commit-reveal SAS that both users compare is what binds the keys, and nothing is pinned until
 * both confirm. Every failure counts in the {@link Lockout}; while it is locked no ceremony runs.
 */
public final class Pairing {
    /** How long a responder waits for an initiator by default. */
    public static final Duration DEFAULT_WINDOW = Duration.ofMinutes(5);
    /** How often a waiting responder wakes to check the window and the lockout. */
    static final Duration POLL = Duration.ofMillis(200);

    private Pairing() {
    }

    /**
     * Connects to a responder at {@code peer} and runs the ceremony as initiator.
     *
     * @return the device to pin
     * @throws PairingException the ceremony failed, the user rejected the digits, or pairing is
     *     locked out
     * @throws IOException the connection failed
     * @throws CryptoException the TLS context could not be built
     */
    public static PairedDevice initiate(Local self, InetSocketAddress peer, Clock clock, Lockout lockout,
            SasPrompt prompt) throws IOException, CryptoException, PairingException {
        Objects.requireNonNull(prompt, "prompt");
        if (!lockout.allows(clock.instant())) {
            throw new PairingException(PairingException.Code.LOCKED);
        }
        try (PeerLink link = Lan.connect(self.identity(), k -> true, clock, peer)) {
            return ceremony(self, link, PairingSession.Role.INITIATOR, clock, lockout, prompt);
        }
    }

    private static PairedDevice ceremony(Local self, PeerLink link, PairingSession.Role role, Clock clock,
            Lockout lockout, SasPrompt prompt) throws IOException, PairingException {
        try (PairingSession session = PairingSession.of(role, self.identity().publicKey(), link.peerKey(),
                self.name())) {
            return new Pairer(lockout, clock).run(link, session, prompt);
        }
    }

    /** A responder's listening socket: it shows the address, then waits for one good ceremony. */
    public static final class Listener implements AutoCloseable {
        private final SSLServerSocket server;
        private final Local self;
        private final Clock clock;

        private Listener(SSLServerSocket server, Local self, Clock clock) {
            this.server = server;
            this.self = self;
            this.clock = clock;
        }

        /**
         * Listens on an ephemeral port of {@code address}.
         *
         * @throws IOException the port could not be opened
         * @throws CryptoException the TLS context could not be built
         */
        public static Listener open(Local self, Clock clock, InetAddress address) throws IOException, CryptoException {
            Objects.requireNonNull(self, "self");
            Objects.requireNonNull(clock, "clock");
            SSLServerSocket server = Lan.listen(self.identity(), k -> true, clock, address);
            try {
                server.setSoTimeout(Math.toIntExact(POLL.toMillis()));
            } catch (IOException e) {
                server.close();
                throw e;
            }
            return new Listener(server, self, clock);
        }

        /** The port, for the address shown to the initiator. */
        public int port() {
            return server.getLocalPort();
        }

        /** The address listened on. */
        public InetAddress address() {
            return server.getInetAddress();
        }

        /**
         * Accepts initiators one at a time until a ceremony succeeds or {@code deadline} passes. A
         * failed ceremony is reported to {@code failures} and counted in {@code lockout}; while it
         * is locked, a connecting initiator is turned away with {@code LOCKED} and nothing is
         * compared.
         *
         * @return the device to pin, or empty if the window closed first
         */
        public Optional<PairedDevice> await(Lockout lockout, SasPrompt prompt, Instant deadline,
                Consumer<PairingException.Code> failures) {
            Objects.requireNonNull(lockout, "lockout");
            Objects.requireNonNull(prompt, "prompt");
            Objects.requireNonNull(failures, "failures");
            while (clock.instant().isBefore(deadline) && !server.isClosed()) {
                Optional<PairedDevice> paired = acceptOne(lockout, prompt, failures);
                if (paired.isPresent()) {
                    return paired;
                }
            }
            return Optional.empty();
        }

        private Optional<PairedDevice> acceptOne(Lockout lockout, SasPrompt prompt,
                Consumer<PairingException.Code> failures) {
            try (PeerLink link = Lan.accept(server)) {
                return Optional.of(ceremony(self, link, PairingSession.Role.RESPONDER, clock, lockout, prompt));
            } catch (SocketTimeoutException e) {
                return Optional.empty();
            } catch (PairingException e) {
                failures.accept(e.code());
                return Optional.empty();
            } catch (IOException | CryptoException e) {
                if (!server.isClosed()) {
                    failures.accept(PairingException.Code.PEER_ABORTED);
                }
                return Optional.empty();
            }
        }

        /** Stops listening and frees the port. */
        @Override
        public void close() throws IOException {
            server.close();
        }
    }
}
