package pm.sharing.pair;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import pm.sharing.net.PeerLink;
import pm.sharing.wire.Message;
import pm.sharing.wire.WireException;

/**
 * Runs a {@link PairingSession} over a {@link PeerLink} (lan-share.md §5). Every failure is
 * counted in the {@link Lockout}; while it is locked no ceremony starts.
 */
public final class Pairer {
    /** How long the peer may wait for its user to compare the digits. */
    public static final Duration CONFIRM_TIMEOUT = Duration.ofMinutes(2);

    private final Lockout lockout;
    private final Clock clock;

    /** A pairer sharing {@code lockout} with every other ceremony of this listener. */
    public Pairer(Lockout lockout, Clock clock) {
        this.lockout = Objects.requireNonNull(lockout, "lockout");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Runs the ceremony to the end.
     *
     * @return the device to pin
     * @throws PairingException the ceremony failed (counted) or pairing is locked out (not counted)
     * @throws IOException the connection failed (counted)
     */
    public PairedDevice run(PeerLink link, PairingSession session, SasPrompt prompt)
            throws IOException, PairingException {
        Objects.requireNonNull(link, "link");
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(prompt, "prompt");
        if (!lockout.allows(clock.instant())) {
            throw new PairingException(PairingException.Code.LOCKED);
        }
        try (session) {
            PairedDevice paired = ceremony(link, session, prompt);
            lockout.succeeded();
            return paired;
        } catch (PairingException | IOException e) {
            lockout.failed(clock.instant());
            throw e;
        }
    }

    private static PairedDevice ceremony(PeerLink link, PairingSession session, SasPrompt prompt)
            throws IOException, PairingException {
        link.send(session.start());
        while (session.state() != PairingSession.State.DONE) {
            if (session.state() == PairingSession.State.CONFIRM && !session.userConfirmed()) {
                link.readTimeout(CONFIRM_TIMEOUT);
                if (!prompt.sameDigits(session.sas(), session.peerName(), session.peerFingerprint())) {
                    link.send(session.reject());
                    throw new PairingException(PairingException.Code.REJECTED);
                }
                link.send(session.confirm());
            } else {
                link.send(session.receive(next(link)));
            }
        }
        return session.result();
    }

    private static Message next(PeerLink link) throws IOException, PairingException {
        try {
            return link.receive();
        } catch (WireException e) {
            throw new PairingException(PairingException.Code.PROTOCOL);
        }
    }
}
