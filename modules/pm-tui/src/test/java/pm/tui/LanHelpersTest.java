package pm.tui;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.sharing.pair.Lockout;
import pm.sharing.wire.Message;
import pm.tui.lan.Devices;
import pm.tui.lan.LanAddress;
import pm.tui.lan.LanException;
import pm.tui.lan.LanState;
import pm.tui.lan.Local;
import pm.tui.lan.SharePayload;
import pm.vault.VaultException;
import pm.vault.record.DeviceIdentityRecord;
import pm.vault.record.LoginRecord;
import pm.vault.record.DeviceRecord;
import pm.vault.record.TrustedDeviceRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/** The pure helpers behind the LAN screens and commands: addresses, windows, payloads, the trust list. */
@SuppressWarnings("PMD.AvoidUsingHardCodedIP") // CE-036: see docs/security/cert-exceptions.md
@Tag("T-LAN-08")
class LanHelpersTest {
    private static final Clock CLOCK = Clock.fixed(FakeVaultPort.T0, ZoneOffset.UTC);

    @Test
    void addressesAreIpLiteralsWithAPort() throws LanException {
        assertEquals(8443, LanAddress.parse("192.168.1.5:8443").getPort());
        assertTrue(LanAddress.parse("[::1]:9").getAddress().isLoopbackAddress());
        for (String bad : List.of("example.org:80", "1.2.3.4", "1.2.3.4:0", "1.2.3.4:65536", "256.1.1.1:1",
                "::1:9", " 1.2.3.4:5", "")) {
            LanException e = assertThrows(LanException.class, () -> LanAddress.parse(bad), bad);
            assertEquals(LanException.Code.BAD_ADDRESS, e.code());
        }
        assertTrue(LanAddress.bind("127.0.0.1").isLoopbackAddress());
        assertTrue(LanAddress.bind("::1").isLoopbackAddress());
        assertThrows(LanException.class, () -> LanAddress.bind("localhost"));
        assertEquals("127.0.0.1:7", LanAddress.show(InetAddress.getLoopbackAddress(), 7));
        assertEquals("[0:0:0:0:0:0:0:1]:7", LanAddress.show(LanAddress.bind("::1"), 7));
        assertFalse(LanAddress.defaultBind().isAnyLocalAddress(), "never a wildcard");
        for (String wildcard : List.of("0.0.0.0", "::", "0:0:0:0:0:0:0:0")) {
            assertEquals(LanException.Code.BAD_ADDRESS,
                    assertThrows(LanException.class, () -> LanAddress.bind(wildcard), wildcard).code(),
                    "a window never listens on every interface");
        }
        // TEST-NET-1 (RFC 5737) and documentation IPv6 (RFC 3849) belong to no interface here.
        for (String foreign : List.of("192.0.2.1", "2001:db8::1")) {
            assertThrows(LanException.class, () -> LanAddress.bind(foreign), foreign);
        }
        InetAddress own = LanAddress.defaultBind();
        assertEquals(own, LanAddress.bind(own.getHostAddress().replaceFirst("%.*$", "")), "an own address is fine");
    }

    @Test
    void windowsAreBoundedToADay() throws LanException {
        assertEquals(Duration.ofSeconds(90), LanAddress.ttl("90s"));
        assertEquals(Duration.ofMinutes(10), LanAddress.ttl("10m"));
        assertEquals(Duration.ofHours(24), LanAddress.ttl("24h"));
        for (String bad : List.of("25h", "1d", "0m", "-5m", "10", "m", "10M", "1441m")) {
            LanException e = assertThrows(LanException.class, () -> LanAddress.ttl(bad), bad);
            assertEquals(LanException.Code.BAD_TTL, e.code());
        }
    }

    @Test
    @SuppressWarnings("PMD.CloseResource") // CE-035: fake sessions and their records need no closing
    void aPayloadAppliesOnlyIfItMatchesTheAcceptedOfferAndOnlyOnce() throws LanException {
        FakeVaultPort.FakeSession from = new FakeVaultPort.FakeSession();
        FakeVaultPort.FakeSession to = new FakeVaultPort.FakeSession();
        TrustedDeviceRecord sender = TrustedDeviceRecord.of(UUID.randomUUID(), "desk", filled(9), FakeVaultPort.T0);
        to.put(sender);
        String fp = sender.fingerprint();
        String stranger = TrustedDeviceRecord.of(UUID.randomUUID(), "x", filled(5), FakeVaultPort.T0).fingerprint();
        LoginRecord login = first(from, LoginRecord.class);
        assertEquals("login: GitHub", SharePayload.summary(login));
        assertEquals(Message.Kind.SECRET, SharePayload.kindOf(login));
        Message.ShareOffer offer = offer(Message.Kind.SECRET, "login: GitHub", 1);
        try (SharePayload.Prepared prepared = SharePayload.prepare(login)) {
            byte[] bytes = prepared.payload().apply(byte[]::clone);
            assertFalse(SharePayload.apply(to, offer(Message.Kind.PROJECT, "login: GitHub", 1), fp, bytes,
                    FakeVaultPort.T0), "the kind must match the offer");
            assertFalse(SharePayload.apply(to, offer(Message.Kind.SECRET, "login: Bank", 1), fp, bytes,
                    FakeVaultPort.T0), "the title must match the summary the user accepted");
            assertFalse(SharePayload.apply(to, offer, stranger, bytes, FakeVaultPort.T0), "only from a paired device");
            assertEquals(0, to.saveCount(), "nothing was applied");

            to.failSaves(VaultException.Code.STORAGE);
            assertFalse(SharePayload.apply(to, offer, fp, bytes, FakeVaultPort.T0));
            assertEquals(1, logins(to, "GitHub"), "a failed save takes the item back");
            assertFalse(Devices.trusted(to).get(0).hasReceived(hex(offer), FakeVaultPort.T0), "and the guard entry");

            FakeVaultPort.FakeSession fresh = new FakeVaultPort.FakeSession();
            fresh.put(sender);
            assertTrue(SharePayload.apply(fresh, offer, fp, bytes, FakeVaultPort.T0));
            assertEquals(1, fresh.saveCount(), "the item and the replay guard go in one save");
            assertTrue(Devices.trusted(fresh).get(0).hasReceived(hex(offer), FakeVaultPort.T0.plusSeconds(599)));
            assertTrue(Devices.receivedShares(fresh, FakeVaultPort.T0).contains(offer.shareId()),
                    "a later receive, in any process, starts from the vault's guard");
            assertFalse(Devices.receivedShares(fresh, FakeVaultPort.T0.plusSeconds(600)).contains(offer.shareId()),
                    "and forgets it once the window has closed");
            assertFalse(SharePayload.apply(fresh, offer, fp, bytes, FakeVaultPort.T0), "a replay is refused");
            assertEquals(2, logins(fresh, "GitHub"), "a login with a title already here is added beside it");
            Arrays.fill(bytes, (byte) 0);
            LoginRecord copy = fresh.records().stream().filter(LoginRecord.class::isInstance)
                    .map(LoginRecord.class::cast)
                    .filter(r -> !r.id().equals(first(fresh, LoginRecord.class).id())).findFirst().orElseThrow();
            assertNotEquals(login.id(), copy.id());
            assertEquals(login.username(), copy.username());
            assertFalse(SharePayload.apply(fresh, offer(Message.Kind.SECRET, "login: GitHub", 2), fp,
                    new byte[] {1, 2, 3}, FakeVaultPort.T0), "garbage is refused");
        }
    }

    private static Message.ShareOffer offer(Message.Kind kind, String summary, int id) {
        byte[] shareId = new byte[Message.SHARE_ID_BYTES];
        Arrays.fill(shareId, (byte) id);
        return new Message.ShareOffer(1, pm.sharing.wire.Octets.copyOf(shareId), kind, summary,
                FakeVaultPort.T0.plusSeconds(600).getEpochSecond(), true);
    }

    private static String hex(Message.ShareOffer offer) {
        return java.util.HexFormat.of().formatHex(offer.shareId().toByteArray());
    }

    private static long logins(FakeVaultPort.FakeSession s, String title) {
        return s.records().stream().filter(r -> r instanceof LoginRecord && r.title().equals(title)).count();
    }

    private static byte[] filled(int b) {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) b);
        return key;
    }

    @Test
    @SuppressWarnings("PMD.CloseResource") // CE-035: records are the fake session's
    void browserTextIsTheOneSecretAndSummariesAreSafe() throws LanException {
        FakeVaultPort.FakeSession s = new FakeVaultPort.FakeSession();
        try (SecretBytes text = SharePayload.browserText(first(s, WifiRecord.class))) {
            assertArrayEquals(FakeVaultPort.WIFI_SECRET.getBytes(StandardCharsets.UTF_8), text.apply(byte[]::clone));
        }
        LoginRecord odd = new LoginRecord(UUID.randomUUID(), "a\u0007b" + Character.toString(0x202E) + "c", "u",
                SecretBytes.copyOf(new byte[0]), List.of(), "", List.of(), FakeVaultPort.T0, FakeVaultPort.T0,
                FakeVaultPort.T0);
        assertEquals("login: a?b?c", SharePayload.summary(odd));
        LanException empty = assertThrows(LanException.class, () -> SharePayload.browserText(odd));
        assertEquals(LanException.Code.NOT_SHAREABLE, empty.code());
        assertEquals("pm device", Devices.deviceName(" \n "));
        assertEquals("a?b", Devices.deviceName("a\tb"));
        assertEquals(DeviceRecord.MAX_NAME_CHARS, Devices.deviceName("x".repeat(500)).length());
    }

    @Test
    @SuppressWarnings("PMD.CloseResource") // CE-035: records are the fake session's
    void theDeviceIdentityLivesInTheVaultAndIsNeverShared() throws CryptoException, VaultException {
        FakeVaultPort.FakeSession s = new FakeVaultPort.FakeSession();
        String fingerprint;
        try (Local me = Devices.local(s, "laptop", CLOCK)) {
            fingerprint = me.fingerprint();
            assertEquals("laptop", me.name());
        }
        DeviceIdentityRecord stored = Devices.identityRecord(s).orElseThrow();
        assertEquals(fingerprint, Devices.fingerprint(stored).orElseThrow());
        try (Local again = Devices.local(s, "other", CLOCK)) {
            assertEquals(fingerprint, again.fingerprint(), "one identity per vault");
        }
        try (Local renamed = Devices.rename(s, "desk", CLOCK)) {
            assertEquals("desk", renamed.name());
            assertEquals(fingerprint, renamed.fingerprint(), "renaming keeps the key");
        }
        assertTrue(Devices.isInternal(stored));
        LanException e = assertThrows(LanException.class, () -> SharePayload.prepare(stored));
        assertEquals(LanException.Code.NOT_SHAREABLE, e.code());
        assertEquals(1, s.records().stream().filter(DeviceIdentityRecord.class::isInstance).count());
    }

    @Test
    @SuppressWarnings("PMD.CloseResource") // CE-035: fake sessions and their records need no closing
    void theTrustListFindsByNameOrFingerprintAndRemembersWhatWasShared() throws LanException, VaultException {
        FakeVaultPort.FakeSession s = new FakeVaultPort.FakeSession();
        byte[] keyA = new byte[32];
        byte[] keyB = new byte[32];
        Arrays.fill(keyB, (byte) 7);
        TrustedDeviceRecord a = TrustedDeviceRecord.of(UUID.randomUUID(), "phone", keyA, FakeVaultPort.T0);
        TrustedDeviceRecord b = TrustedDeviceRecord.of(UUID.randomUUID(), "phone", keyB, FakeVaultPort.T0);
        s.put(a);
        assertEquals(a.id(), Devices.find(s, "phone").id());
        assertEquals(a.id(), Devices.find(s, a.fingerprint().replace(" ", "").toUpperCase(java.util.Locale.ROOT)).id());
        s.put(b);
        assertEquals(LanException.Code.AMBIGUOUS_DEVICE,
                assertThrows(LanException.class, () -> Devices.find(s, "phone")).code());
        assertEquals(b.id(), Devices.find(s, b.fingerprint()).id());
        assertEquals(LanException.Code.NO_SUCH_DEVICE,
                assertThrows(LanException.class, () -> Devices.find(s, "tablet")).code());
        assertEquals(a.id(), Devices.byKey(s, keyA).orElseThrow().id());
        assertTrue(Devices.pinnedIn(Devices.trusted(s)).test(keyB));
        assertFalse(Devices.pinnedIn(List.of(a)).test(keyB));

        VaultRecord login = first(s, LoginRecord.class);
        assertTrue(Devices.recordShare(s, a, login.id(), FakeVaultPort.T0).isPresent());
        // `a` is now a stale copy: recording through it must keep what was recorded since.
        assertTrue(Devices.recordShare(s, a, UUID.randomUUID(), FakeVaultPort.T0).isPresent());
        TrustedDeviceRecord now = Devices.find(s, a.fingerprint());
        assertEquals(2, now.shared().size(), "the current entry was read again, nothing was lost");
        assertEquals(List.of(login), Devices.sharedWith(s, now), "items deleted since are not listed");
        assertTrue(Devices.remove(s, now));
        assertFalse(Devices.remove(s, now));
        int saves = s.saveCount();
        assertTrue(Devices.recordShare(s, now, login.id(), FakeVaultPort.T0).isEmpty(),
                "a device removed since is not pinned again");
        assertEquals(saves, s.saveCount());
        assertEquals(List.of(b), Devices.trusted(s));
    }

    @Test
    void removedDevicesAreSharedThroughTheVaultFileWhateverTheRunDirectory(@TempDir Path tmp) throws IOException {
        Path vault = Files.writeString(tmp.resolve("vault.pm"), "v");
        Path link = Files.createSymbolicLink(tmp.resolve("other-name.pm"), vault);
        byte[] key = filled(3);
        LanState one = LanState.forVault(vault, Files.createDirectory(tmp.resolve("run-a")));
        // another pm process of the same vault, started with another run directory and through a link
        LanState other = LanState.forVault(link, Files.createDirectory(tmp.resolve("run-b")));
        assertFalse(other.isRemoved(key));
        one.removed(key);
        one.removed(key);
        assertTrue(other.isRemoved(key), "a removal reaches every process of the vault");
        assertFalse(other.stillTrusted().test(key));
        assertTrue(other.stillTrusted().test(filled(4)));
        Path dir = tmp.resolve("vault.pm" + LanState.VAULT_SUFFIX);
        assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"),
                Files.getPosixFilePermissions(dir), "owner-only directory");
        Path marker = dir.resolve(LanState.REMOVED_PREFIX + java.util.HexFormat.of().formatHex(key));
        assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(marker), "owner-only");
        other.pinned(key);
        assertFalse(one.isRemoved(key), "pairing the key again clears it");

        Files.setPosixFilePermissions(dir, mode("rwxr-xr-x"));
        assertThrows(IOException.class, () -> LanState.forVault(vault, tmp.resolve("run-a")),
                "a directory others can read is refused");

        LanState memory = LanState.memory();
        memory.removed(key);
        assertTrue(memory.isRemoved(key));
        java.time.Instant t0 = FakeVaultPort.T0;
        assertSame(memory.lockout(t0), memory.lockout(t0.plusSeconds(5)), "one lockout per process in memory");
    }

    @Test
    void thePairingLockoutIsMergedAcrossProcessesAndFailsClosed(@TempDir Path tmp) throws IOException {
        Path runDir = Files.createDirectory(tmp.resolve("run"));
        LanState one = LanState.forVault(Files.writeString(tmp.resolve("a.pm"), "a"), runDir);
        LanState two = LanState.forVault(Files.writeString(tmp.resolve("b.pm"), "b"), runDir);
        java.time.Instant t0 = FakeVaultPort.T0;
        Lockout early = one.lockout(t0); // a pairing that started before the other one locked
        Lockout locker = two.lockout(t0);
        for (int i = 0; i <= Lockout.FREE_FAILURES; i++) {
            locker.failed(t0);
        }
        assertTrue(two.save(locker, t0));
        early.failed(t0);
        assertTrue(one.save(early, t0), "a weaker state merges, it does not overwrite");
        Lockout next = LanState.forVault(tmp.resolve("a.pm"), runDir).lockout(t0.plusSeconds(1));
        assertFalse(next.allows(t0.plusSeconds(1)), "a new pairing process starts locked");
        assertEquals(Duration.ofSeconds(59), next.remaining(t0.plusSeconds(1)));
        assertEquals(Lockout.FREE_FAILURES + 1, next.failures());

        early.succeeded();
        assertTrue(one.save(early, t0));
        assertEquals(Lockout.FREE_FAILURES + 1, two.lockout(t0).failures(),
                "a success does not clear failures another process recorded");
        Lockout mine = two.lockout(t0);
        mine.succeeded();
        assertTrue(two.save(mine, t0));
        assertEquals(0, one.lockout(t0).failures(), "a success clears a count nobody changed since");

        Path file = runDir.resolve(LanState.LOCKOUT_FILE);
        Files.writeString(file, "1 9 " + t0.plus(Duration.ofDays(30)).getEpochSecond() + "\n");
        assertEquals(Lockout.CAP, two.lockout(t0).remaining(t0), "a lock far ahead is cut to one hour");
        Files.writeString(file, "garbage");
        assertEquals(Lockout.CAP, two.lockout(t0).remaining(t0), "an unreadable state locks for the cap");
        Files.writeString(file, "1 0 0\n");
        assertTrue(two.lockout(t0).allows(t0));
        Files.setPosixFilePermissions(file, mode("rw-rw-rw-"));
        assertEquals(Lockout.CAP, two.lockout(t0).remaining(t0), "a state others could write locks for the cap");
        Files.delete(file);
        assertTrue(two.lockout(t0).allows(t0), "no state, no lock (residual: lan-share.md §8.1)");
    }

    /** A mode a test sets on purpose to check it is refused. */
    private static java.util.Set<java.nio.file.attribute.PosixFilePermission> mode(String mode) {
        return java.nio.file.attribute.PosixFilePermissions.fromString(mode);
    }

    private static <T extends VaultRecord> T first(FakeVaultPort.FakeSession s, Class<T> type) {
        return s.records().stream().filter(type::isInstance).map(type::cast).findFirst().orElseThrow();
    }
}
