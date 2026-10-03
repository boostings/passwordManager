package pm.sharing.share;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import pm.sharing.share.ShareException.Code;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;

/** Share windows on the sender: expiry, one use, revocation (SR-204, SR-205). */
class SharesTest {
    static final Instant T0 = Instant.parse("2026-10-03T12:00:00.250Z");
    static final byte[] BOB = filled(2);
    static final byte[] CAROL = filled(4);
    static final byte[] PAYLOAD = {1, 2, 3};

    static byte[] filled(int b) {
        byte[] k = new byte[32];
        Arrays.fill(k, (byte) b);
        return k;
    }

    static Share open(Shares shares, byte[] target, boolean oneUse) {
        return shares.open(target, Message.Kind.PROJECT, "api: 3 variables", PAYLOAD, Shares.DEFAULT_TTL, oneUse, T0);
    }

    private static Code claimFails(Shares shares, Octets id, byte[] peer, Instant now) {
        return assertThrows(ShareException.class, () -> shares.claim(id, peer, now)).code();
    }

    @Test
    void aOneUseShareIsConsumedByTheFirstClaim() throws ShareException {
        Shares shares = new Shares();
        Share s = open(shares, BOB, true);
        assertEquals(T0.plusSeconds(600).minusMillis(250), s.expires());
        assertSame(s, shares.offerFor(BOB, T0).orElseThrow());
        assertSame(s, shares.claim(s.id(), BOB, T0));
        assertEquals(Code.USED, claimFails(shares, s.id(), BOB, T0));
        assertTrue(shares.offerFor(BOB, T0).isEmpty());
        assertFalse(shares.anyOpen(T0));
    }

    @Test
    void aReusableShareServesUntilItExpires() throws ShareException {
        Shares shares = new Shares();
        Share s = open(shares, BOB, false);
        shares.claim(s.id(), BOB, T0);
        shares.claim(s.id(), BOB, T0.plusSeconds(1));
        assertTrue(shares.anyOpen(T0.plusSeconds(1)));
        Instant end = s.expires();
        assertFalse(s.openAt(end));
        assertEquals(Code.EXPIRED, claimFails(shares, s.id(), BOB, end));
        assertFalse(shares.anyOpen(end));
        assertTrue(shares.offerFor(BOB, end).isEmpty());
    }

    @Test
    void anotherDevicesShareOrAnUnknownIdIsUnknown() {
        Shares shares = new Shares();
        Share s = open(shares, BOB, true);
        assertEquals(Code.UNKNOWN, claimFails(shares, s.id(), CAROL, T0));
        assertEquals(Code.UNKNOWN, claimFails(shares, Octets.copyOf(new byte[16]), BOB, T0));
        assertTrue(shares.offerFor(CAROL, T0).isEmpty());
    }

    @Test
    void revokingAShareOrItsDeviceClosesTheWindow() {
        Shares shares = new Shares();
        Share one = open(shares, BOB, true);
        Share two = open(shares, BOB, false);
        Share carols = open(shares, CAROL, true);
        assertTrue(shares.revoke(one.id()));
        assertFalse(shares.revoke(one.id()));
        assertFalse(shares.revoke(Octets.copyOf(new byte[16])));
        assertEquals(Code.REVOKED, claimFails(shares, one.id(), BOB, T0));
        assertEquals(1, shares.revokeDevice(BOB));
        assertEquals(0, shares.revokeDevice(BOB));
        assertEquals(Code.REVOKED, claimFails(shares, two.id(), BOB, T0));
        assertTrue(shares.anyOpen(T0));
        assertSame(carols, shares.offerFor(CAROL, T0).orElseThrow());
    }

    @Test
    void windowsAreBetweenOneSecondAndADay() {
        Shares shares = new Shares();
        for (Duration bad : new Duration[] {Duration.ZERO, Duration.ofMillis(999), Shares.MAX_TTL.plusSeconds(1)}) {
            assertThrows(IllegalArgumentException.class, () -> shares.open(BOB, Message.Kind.SECRET, "x", PAYLOAD,
                    bad, true, T0));
        }
        Share day = shares.open(BOB, Message.Kind.SECRET, "x", PAYLOAD, Shares.MAX_TTL, true, T0);
        assertTrue(day.openAt(T0.plus(Duration.ofHours(23))));
    }

    @Test
    void aShareMustFitTheWire() {
        Octets id = Octets.copyOf(new byte[16]);
        Octets key = Octets.copyOf(BOB);
        Octets data = Octets.copyOf(PAYLOAD);
        assertThrows(IllegalArgumentException.class, () -> new Share(Octets.copyOf(new byte[15]), key,
                Message.Kind.SECRET, "x", data, T0, true));
        assertThrows(IllegalArgumentException.class, () -> new Share(id, Octets.copyOf(new byte[31]),
                Message.Kind.SECRET, "x", data, T0, true));
        assertThrows(IllegalArgumentException.class, () -> new Share(id, key, Message.Kind.SECRET, "x",
                Octets.copyOf(new byte[0]), T0, true));
        assertThrows(IllegalArgumentException.class, () -> new Share(id, key, Message.Kind.SECRET, "bad\u0000",
                data, T0, true));
    }

    @Test
    void errorCodesRoundTripAndUnknownCodesMeanAborted() {
        for (Code c : Code.values()) {
            assertEquals(c.wire() == 0 ? Code.PEER_ABORTED : c, Code.fromWire(c.wire()));
        }
        assertEquals(Code.PEER_ABORTED, Code.fromWire(99));
    }
}
