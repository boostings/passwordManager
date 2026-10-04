package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.ConstantTime;
import pm.crypto.DeviceIdentity;
import pm.sharing.share.ReceiveSession;
import pm.sharing.share.ReceivedShares;
import pm.sharing.share.SendSession;
import pm.sharing.share.Share;
import pm.sharing.share.ShareException;
import pm.sharing.share.Shares;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;

/**
 * Fuzz harness for share windows and the share session state machines (SR-202, SR-204, T-FUZZ-LAN).
 * The input is a script over one sender and two paired receiving devices: open windows, move the
 * clock, revoke a window or a device, start connections, pass messages between the two sessions
 * (in order, dropped, or replayed from an earlier connection), let the receiving user accept,
 * decline or apply, and inject messages of the script's choosing into either side.
 *
 * <p>The oracle, kept outside the code under test:
 * <ul>
 *   <li>the sender releases a window's data only to that window's device, before its expiry,
 *       never after the harness asked to revoke it, and a one-use window at most once;
 *   <li>a receiving device shows an offer only while its window is open and only if it has not
 *       applied that share id before, and never applies a share id twice;
 *   <li>{@code receive} throws only {@link ShareException}, after which the session stays failed.
 * </ul>
 *
 * <p>Without {@code JAZZER_FUZZ=1} the seeds in {@code ShareSessionFuzzTestInputs} are replayed.
 */
@Tag("T-FUZZ-LAN")
@Tag("T-LAN-03")
@Tag("T-LAN-05")
class ShareSessionFuzzTest {
    static final int MAX_STEPS = 64;
    private static final int MAX_WINDOWS = 8;
    private static final byte PAYLOAD_TAG = 7;
    private static final int STEP_KINDS = 14;
    private static final int TO_RECEIVER_KINDS = 6;
    private static final int TO_SENDER_KINDS = 6;
    private static final long MILLIS_PER_TICK = 100;
    private static final byte[] SENDER = key(1);
    private static final List<byte[]> RECEIVERS = List.of(key(2), key(3));

    @FuzzTest
    void fuzz(byte[] in) {
        new Run(new Script(in)).play();
    }

    private static byte[] key(int fill) {
        byte[] k = new byte[DeviceIdentity.PUBLIC_KEY_BYTES];
        Arrays.fill(k, (byte) fill);
        return k;
    }

    /**
     * The harness's own record of one window: what it asked for (target, end, one-use, payload),
     * kept apart from the {@link Share} so the oracle does not read back the code under test.
     */
    private static final class Window {
        final Octets id;
        final byte[] target;
        final Instant expires;
        final boolean oneUse;
        final byte[] payload;
        boolean revokeRequested;
        int released;

        Window(Octets id, byte[] target, Instant expires, boolean oneUse, byte[] payload) {
            this.id = id;
            this.target = target.clone();
            this.expires = expires;
            this.oneUse = oneUse;
            this.payload = payload.clone();
        }
    }

    /** One connection: a sender session, a receiver session and the two directions between them. */
    private static final class Link {
        final int device;
        final SendSession sender;
        final ReceiveSession receiver;
        final Deque<Message> toReceiver = new ArrayDeque<>();
        final Deque<Message> toSender = new ArrayDeque<>();
        long receiverIn;
        long senderIn;

        Link(int device, SendSession sender, ReceiveSession receiver) {
            this.device = device;
            this.sender = sender;
            this.receiver = receiver;
        }
    }

    /** What one script did, for the seed tests. */
    record Outcome(int releases, int applied, int refusals) {}

    /** One scripted run. */
    static final class Run {
        private final Script s;
        private final FuzzClock clock = new FuzzClock();
        private final Shares shares = new Shares();
        private final List<ReceivedShares> received = List.of(new ReceivedShares(), new ReceivedShares());
        private final List<Set<Octets>> appliedIds = List.of(new HashSet<>(), new HashSet<>());
        private final Map<Octets, Window> windows = new HashMap<>();
        private final List<Message> history = new ArrayList<>();
        private Link link;
        private int releases;
        private int applied;
        private int refusals;

        Run(Script s) {
            this.s = s;
        }

        Outcome play() {
            for (int i = 0; i < MAX_STEPS && !s.done(); i++) {
                step();
            }
            return new Outcome(releases, applied, refusals);
        }

        private void step() {
            switch (s.pick(STEP_KINDS)) {
                case 0 -> open();
                case 1 -> clock.advance(s.bit() ? Duration.ofSeconds(s.u8()) : Duration.ofMillis(s.u8() * MILLIS_PER_TICK));
                case 2 -> revokeOne();
                case 3 -> revokeDevice();
                case 4 -> connect();
                case 5 -> toReceiver(link == null ? null : link.toReceiver.poll());
                case 6 -> toSender(link == null ? null : link.toSender.poll());
                case 7 -> userDecides();
                case 8 -> apply();
                case 9 -> toReceiver(link == null ? null : craftedForReceiver());
                case 10 -> toSender(link == null ? null : craftedForSender());
                case 11 -> drop();
                case 12 -> replay();
                default -> clock.advance(Duration.ofMillis(MILLIS_PER_TICK));
            }
        }

        private void open() {
            if (windows.size() == MAX_WINDOWS) {
                return;
            }
            byte[] target = RECEIVERS.get(s.pick(RECEIVERS.size()));
            Duration ttl = Duration.ofSeconds(1L + s.u8());
            boolean oneUse = s.bit();
            byte[] payload = {PAYLOAD_TAG, (byte) windows.size()}; // distinct per window, so a mix-up shows
            Instant opened = clock.instant();
            Share share = shares.open(target, Message.Kind.SECRET, "1 secret", payload, ttl, oneUse, opened);
            // The window ends on a whole second: offers carry expiry as epoch seconds (lan-share.cddl).
            Instant expires = opened.plus(ttl).truncatedTo(ChronoUnit.SECONDS);
            windows.put(share.id(), new Window(share.id(), target, expires, oneUse, payload));
        }

        private void revokeOne() {
            Window w = pickWindow();
            if (w != null) {
                w.revokeRequested = true;
                shares.revoke(w.id);
            }
        }

        private void revokeDevice() {
            byte[] device = RECEIVERS.get(s.pick(RECEIVERS.size()));
            windows.values().stream()
                    .filter(w -> ConstantTime.equals(w.target, device))
                    .forEach(w -> w.revokeRequested = true);
            shares.revokeDevice(device);
        }

        private Window pickWindow() {
            List<Window> all = new ArrayList<>(windows.values());
            all.sort((a, b) -> Arrays.compare(a.id.toByteArray(), b.id.toByteArray()));
            return all.isEmpty() ? null : all.get(s.pick(all.size()));
        }

        private void connect() {
            int device = s.pick(RECEIVERS.size());
            byte[] peer = RECEIVERS.get(device);
            link = new Link(device, new SendSession(SENDER, peer, "sender", shares, clock),
                    new ReceiveSession(peer, SENDER, "receiver", received.get(device), clock));
            fromSender(link.sender.start());
            fromReceiver(link.receiver.start());
        }

        private void toReceiver(Message m) {
            if (m == null || link.receiver.failed()) {
                return;
            }
            Message delivered = s.bit() ? renumber(m, link.receiverIn) : m;
            try {
                fromReceiver(link.receiver.receive(delivered));
                link.receiverIn++;
            } catch (ShareException e) {
                refused(link.receiver.failed(), e);
                fromReceiver(link.receiver.abort(e.code()));
                return;
            }
            if (link.receiver.state() == ReceiveSession.State.OFFERED) {
                Message.ShareOffer offer = link.receiver.offer();
                assertTrue(Instant.ofEpochSecond(offer.expires()).isAfter(clock.instant()), "expired offer shown");
                assertFalse(appliedIds.get(link.device).contains(offer.shareId()), "applied share offered again");
            }
        }

        private void toSender(Message m) {
            if (m == null || link.sender.failed()) {
                return;
            }
            Message delivered = s.bit() ? renumber(m, link.senderIn) : m;
            try {
                fromSender(link.sender.receive(delivered));
                link.senderIn++;
            } catch (ShareException e) {
                refused(link.sender.failed(), e);
                fromSender(link.sender.abort(e.code()));
            }
        }

        private void refused(boolean failed, ShareException e) {
            assertTrue(failed, "refused without failing: " + e.code());
            refusals++;
        }

        private void fromSender(List<Message> out) {
            for (Message m : out) {
                if (m instanceof Message.ShareData d) {
                    released(d);
                }
                history.add(m);
                link.toReceiver.add(m);
            }
        }

        private void fromReceiver(List<Message> out) {
            link.toSender.addAll(out);
        }

        private void released(Message.ShareData d) {
            Window w = windows.get(d.shareId());
            assertNotNull(w, "data for a window that was never opened");
            assertTrue(ConstantTime.equals(w.target, RECEIVERS.get(link.device)),
                    "data released to another device");
            assertFalse(w.revokeRequested, "data released after revocation");
            assertTrue(clock.instant().isBefore(w.expires), "data released after expiry");
            assertTrue(!w.oneUse || w.released == 0, "one-use data released twice");
            assertArrayEquals(w.payload, d.payload().toByteArray(), "payload");
            w.released++;
            releases++;
        }

        private void userDecides() {
            if (link == null || link.receiver.state() != ReceiveSession.State.OFFERED) {
                return;
            }
            fromReceiver(s.bit() ? link.receiver.accept() : link.receiver.decline());
        }

        private void apply() {
            if (link == null || link.receiver.state() != ReceiveSession.State.VALIDATING) {
                return;
            }
            Octets id = link.receiver.offer().shareId();
            boolean ok = s.bit();
            fromReceiver(link.receiver.applied(ok));
            if (ok) {
                assertTrue(appliedIds.get(link.device).add(id), "share applied twice");
                applied++;
            }
        }

        private void drop() {
            if (link != null) {
                (s.bit() ? link.toReceiver : link.toSender).poll();
            }
        }

        private void replay() {
            if (link != null && !history.isEmpty()) {
                toReceiver(history.get(s.pick(history.size())));
            }
        }

        /** A share id the script picks: a window's, one already applied, or a made-up one. */
        private Octets someId() {
            Window w = s.bit() ? pickWindow() : null;
            if (w != null) {
                return w.id;
            }
            List<Octets> done = new ArrayList<>(appliedIds.get(link.device));
            done.sort((a, b) -> Arrays.compare(a.toByteArray(), b.toByteArray()));
            return !done.isEmpty() && s.bit() ? done.get(s.pick(done.size())) : Octets.copyOf(s.filled(Message.SHARE_ID_BYTES));
        }

        private Message craftedForReceiver() {
            long seq = link.receiverIn;
            return switch (s.pick(TO_RECEIVER_KINDS)) {
                case 0 -> new Message.Hello(seq, Octets.copyOf(DeviceIdentity.deviceId(s.bit() ? SENDER : RECEIVERS.get(0))),
                        "sender", List.of("share"));
                case 1 -> new Message.ShareOffer(seq, someId(), Message.Kind.SECRET, "1 secret",
                        Math.max(1, clock.instant().getEpochSecond() + s.u8() - Byte.MAX_VALUE), s.bit());
                case 2 -> new Message.ShareData(seq, someId(), Octets.copyOf(new byte[] {9}));
                case 3 -> new Message.Bye(seq);
                case 4 -> new Message.ErrorReport(seq, s.pick(ShareException.Code.values().length + 1));
                default -> new Message.ShareAck(seq, someId(), s.bit());
            };
        }

        private Message craftedForSender() {
            long seq = link.senderIn;
            return switch (s.pick(TO_SENDER_KINDS)) {
                case 0 -> new Message.Hello(seq, Octets.copyOf(DeviceIdentity.deviceId(RECEIVERS.get(s.pick(RECEIVERS.size())))),
                        "receiver", List.of("share"));
                case 1 -> new Message.ShareAccept(seq, someId());
                case 2 -> new Message.ShareAck(seq, someId(), s.bit());
                case 3 -> new Message.Bye(seq);
                case 4 -> new Message.ErrorReport(seq, s.pick(ShareException.Code.values().length + 1));
                default -> new Message.ShareData(seq, someId(), Octets.copyOf(new byte[] {9}));
            };
        }
    }

    /** {@code m} with sequence number {@code seq}. */
    static Message renumber(Message m, long seq) {
        return switch (m) {
            case Message.Hello h -> new Message.Hello(seq, h.deviceId(), h.name(), h.caps());
            case Message.PairReq r -> new Message.PairReq(seq);
            case Message.PairCommit c -> new Message.PairCommit(seq, c.commit());
            case Message.PairNonce n -> new Message.PairNonce(seq, n.nonce());
            case Message.PairReveal r -> new Message.PairReveal(seq, r.nonce());
            case Message.PairSasOk ok -> new Message.PairSasOk(seq, ok.mac());
            case Message.PairDone d -> new Message.PairDone(seq);
            case Message.ShareOffer o -> new Message.ShareOffer(seq, o.shareId(), o.kind(), o.summary(), o.expires(),
                    o.oneUse());
            case Message.ShareAccept a -> new Message.ShareAccept(seq, a.shareId());
            case Message.ShareData d -> new Message.ShareData(seq, d.shareId(), d.payload());
            case Message.ShareAck a -> new Message.ShareAck(seq, a.shareId(), a.applied());
            case Message.Revoke r -> new Message.Revoke(seq, r.deviceId());
            case Message.ErrorReport e -> new Message.ErrorReport(seq, e.code());
            case Message.Bye b -> new Message.Bye(seq);
        };
    }

    /** What each seed must do: releases, applied shares, refusals. */
    static Map<String, Outcome> seedOutcomes() {
        return Map.of(
                "honest-one-use.bin", new Outcome(1, 1, 0),
                "one-use-second-connection.bin", new Outcome(1, 1, 0),
                "replayed-offer.bin", new Outcome(1, 1, 1),
                "expired-before-accept.bin", new Outcome(0, 0, 1),
                "revoked-before-accept.bin", new Outcome(0, 0, 1));
    }

    /** The seeds do what their names say, so the release and apply oracles are exercised. */
    @Test
    void seedsEndAsLabelled() throws IOException {
        for (Map.Entry<String, Outcome> seed : seedOutcomes().entrySet()) {
            byte[] script = Seeds.read(ShareSessionFuzzTest.class, seed.getKey());
            assertEquals(seed.getValue(), new Run(new Script(script)).play(), seed.getKey());
        }
    }
}
