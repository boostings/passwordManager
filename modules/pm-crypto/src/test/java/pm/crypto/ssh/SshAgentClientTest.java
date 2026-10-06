package pm.crypto.ssh;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.time.Duration;
import java.util.List;
import java.util.function.UnaryOperator;
import jdk.net.ExtendedSocketOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import pm.crypto.SecretBytes;

/**
 * The ssh-agent client against {@link TestAgent} on a Unix domain socket in an owner-only (0700)
 * temporary directory (ADR 0013, SR-060 to SR-062): add, list and remove round trips, the exact
 * add-identity encoding, constraints, refused and malformed replies, and the socket path checks.
 */
class SshAgentClientTest {
    @TempDir
    Path tmp;

    private Path dir;
    private Path sock;
    private TestAgent agent;

    @BeforeEach
    void ownerOnlyDir() throws IOException {
        dir = Files.createDirectory(tmp.resolve("agent"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        sock = dir.resolve("s");
    }

    @AfterEach
    void stop() throws IOException {
        if (agent != null) {
            agent.close();
            assertEquals(List.of(), agent.errors);
        }
    }

    private SshAgentClient client() throws SshException {
        return SshAgentClient.connect(sock);
    }

    private SshAgentClient scripted(UnaryOperator<byte[]> script) throws IOException, SshException {
        agent = TestAgent.start(sock, script, false);
        return client();
    }

    private SshAgentClient hangingUp(UnaryOperator<byte[]> script) throws IOException, SshException {
        agent = TestAgent.start(sock, script, true);
        return client();
    }

    private static SshKey key(KeyFixtures.File f) throws SshException {
        try (SecretBytes s = f.secret()) {
            return SshKey.parse(s);
        }
    }

    @Test
    void addListRemoveRoundTrip() throws IOException, SshException {
        agent = TestAgent.start(sock);
        KeyFixtures.Ed ed = KeyFixtures.ed25519();
        KeyFixtures.Ec ec = KeyFixtures.p256();
        try (SshAgentClient c = client(); SshKey a = key(KeyFixtures.File.of(ed)); SshKey b = key(KeyFixtures.File.of(ec))) {
            assertEquals(List.of(), c.list());
            c.add(a, AgentConstraints.NONE);
            c.add(b, new AgentConstraints(Duration.ofMinutes(10), true));
            List<AgentIdentity> ids = c.list();
            assertEquals(2, ids.size());
            assertTrue(ids.get(0).matches(a));
            assertFalse(ids.get(0).matches(b));
            assertTrue(ids.get(1).matches(b));
            assertEquals("ssh-ed25519", ids.get(0).type());
            assertEquals("ecdsa-sha2-nistp256", ids.get(1).type());
            assertEquals(KeyFixtures.COMMENT, ids.get(0).comment());
            assertEquals(a.fingerprint(), ids.get(0).fingerprint());
            assertArrayEquals(a.publicKeyBlob(), ids.get(0).publicKeyBlob());
            assertEquals("AgentIdentity[ssh-ed25519 " + a.fingerprint() + "]", ids.get(0).toString());

            // Exactly the draft-miller-ssh-agent encoding: the private-section fields, then the comment.
            assertArrayEquals(KeyFixtures.fields(ed), agent.held.get(0).fields);
            assertArrayEquals(KeyFixtures.fields(ec), agent.held.get(1).fields);
            assertEquals(SshAgentClient.ADD_IDENTITY, agent.requests.get(1)[0]);
            assertEquals(SshAgentClient.ADD_ID_CONSTRAINED, agent.requests.get(2)[0]);
            assertEquals(0, agent.held.get(0).lifetime);
            assertFalse(agent.held.get(0).confirm);
            assertEquals(600, agent.held.get(1).lifetime);
            assertTrue(agent.held.get(1).confirm);

            c.remove(a);
            assertEquals(1, c.list().size());
            assertThrows(SshException.class, () -> c.remove(a));
            c.remove(ids.get(1).publicKeyBlob());
            assertEquals(List.of(), c.list());
        }
    }

    @Test
    void constrainedAddsCarryOnlyTheConstraintsAsked() throws IOException, SshException {
        agent = TestAgent.start(sock);
        try (SshAgentClient c = client(); SshKey a = key(KeyFixtures.File.of(KeyFixtures.ed25519()))) {
            c.add(a, new AgentConstraints(Duration.ofSeconds(AgentConstraints.MAX_LIFETIME_SECONDS), false));
            assertEquals(AgentConstraints.MAX_LIFETIME_SECONDS, agent.held.get(0).lifetime);
            assertFalse(agent.held.get(0).confirm);
            c.add(a, new AgentConstraints(Duration.ZERO, true));
            assertEquals(0, agent.held.get(0).lifetime);
            assertTrue(agent.held.get(0).confirm);
            assertEquals(1, c.list().size());
        }
    }

    @Test
    void removeAllEmptiesTheAgent() throws IOException, SshException {
        agent = TestAgent.start(sock);
        try (SshAgentClient c = client(); SshKey a = key(KeyFixtures.File.of(KeyFixtures.ed25519()));
                SshKey b = key(KeyFixtures.File.of(KeyFixtures.ed25519()))) {
            c.add(a, AgentConstraints.NONE);
            c.add(b, AgentConstraints.NONE);
            assertEquals(2, c.list().size());
            c.removeAll();
            assertEquals(List.of(), c.list());
        }
    }

    @Test
    void refusesToSendAClosedKeyOrABadBlob() throws IOException, SshException {
        agent = TestAgent.start(sock);
        try (SshAgentClient c = client()) {
            try (SshKey a = key(KeyFixtures.File.of(KeyFixtures.ed25519()))) {
                SshKeyTest.shut(a);
                assertThrows(IllegalStateException.class, () -> c.add(a, AgentConstraints.NONE));
            }
            assertThrows(IllegalArgumentException.class, () -> c.remove(new byte[0]));
            assertThrows(IllegalArgumentException.class, () -> c.remove(new byte[SshKey.MAX_BLOB_BYTES + 1]));
            assertEquals(List.of(), c.list());
        }
    }

    @Test
    void agentFailureIsRefused() throws IOException, SshException {
        byte[] failure = TestAgent.frame(new byte[] {SshAgentClient.FAILURE});
        try (SshAgentClient c = scripted(req -> failure); SshKey a = key(KeyFixtures.File.of(KeyFixtures.ed25519()))) {
            assertEquals(SshException.Code.AGENT_REFUSED, assertThrows(SshException.class, c::list).code());
            assertEquals(SshException.Code.AGENT_REFUSED,
                    assertThrows(SshException.class, () -> c.add(a, AgentConstraints.NONE)).code());
            assertEquals(SshException.Code.AGENT_REFUSED, assertThrows(SshException.class, c::removeAll).code());
        }
    }

    private SshException.Code badList(byte[] replyBody) throws IOException, SshException {
        byte[] framed = TestAgent.frame(replyBody);
        try (SshAgentClient c = scripted(req -> framed)) {
            return assertThrows(SshException.class, c::list).code();
        }
    }

    @Test
    void malformedIdentityListsAreRejected() throws IOException, SshException {
        byte[] blob = KeyFixtures.blob(KeyFixtures.ed25519());
        assertEquals(SshException.Code.BAD_REPLY, badList(new byte[] {SshAgentClient.SUCCESS}));
        restart();
        // A failure must be exactly one byte, as for every other request (ADR 0013).
        assertEquals(SshException.Code.BAD_REPLY, badList(new byte[] {SshAgentClient.FAILURE, 0}));
        restart();
        assertEquals(SshException.Code.BAD_REPLY, badList(new KeyFixtures.W().u8(SshAgentClient.IDENTITIES_ANSWER)
                .u32(SshAgentClient.MAX_IDENTITIES + 1L).bytes()));
        restart();
        // Claims two identities, carries one.
        assertEquals(SshException.Code.BAD_REPLY, badList(new KeyFixtures.W().u8(SshAgentClient.IDENTITIES_ANSWER)
                .u32(2).str(blob).str("c").bytes()));
        restart();
        // Trailing bytes after the last identity.
        assertEquals(SshException.Code.BAD_REPLY, badList(new KeyFixtures.W().u8(SshAgentClient.IDENTITIES_ANSWER)
                .u32(1).str(blob).str("c").u8(0).bytes()));
        restart();
        // A blob too short to name its algorithm; a blob over the limit; a comment length past the end.
        assertEquals(SshException.Code.BAD_REPLY, badList(new KeyFixtures.W().u8(SshAgentClient.IDENTITIES_ANSWER)
                .u32(1).str(new byte[] {0, 0}).str("c").bytes()));
        restart();
        assertEquals(SshException.Code.BAD_REPLY, badList(new KeyFixtures.W().u8(SshAgentClient.IDENTITIES_ANSWER)
                .u32(1).str(new byte[SshKey.MAX_BLOB_BYTES + 1]).str("c").bytes()));
        restart();
        assertEquals(SshException.Code.BAD_REPLY, badList(new KeyFixtures.W().u8(SshAgentClient.IDENTITIES_ANSWER)
                .u32(1).str(blob).u32(0xFFFF_FFFFL).bytes()));
    }

    private void restart() throws IOException {
        agent.close();
        Files.delete(sock);
        agent = null;
    }

    @Test
    void agentCommentsAreMadeSafeToPrint() throws IOException, SshException {
        byte[] blob = KeyFixtures.blob(KeyFixtures.ed25519());
        byte[] reply = TestAgent.frame(new KeyFixtures.W().u8(SshAgentClient.IDENTITIES_ANSWER).u32(1).str(blob)
                .str("evil\u001b]0;title\u0007\nnext é \u202egpj.exe\u2069\u200b\u2028").bytes());
        try (SshAgentClient c = scripted(req -> reply)) {
            assertEquals("evil?]0;title??next é ?gpj.exe???", c.list().get(0).comment());
        }
    }

    @Test
    void agentKeyTypesAreMadeSafeToPrint() throws IOException, SshException {
        byte[] blob = new KeyFixtures.W().str("ssh-\u001b[2J\u001b]0;PWNED\u0007").str(new byte[32]).bytes();
        byte[] reply = TestAgent.frame(new KeyFixtures.W().u8(SshAgentClient.IDENTITIES_ANSWER).u32(1).str(blob)
                .str("c").bytes());
        try (SshAgentClient c = scripted(req -> reply)) {
            assertEquals("ssh-?[2J?]0;PWNED?", c.list().get(0).type());
        }
    }

    @Test
    void aStalledAgentTimesOutAndTheConnectionIsClosed() throws IOException, SshException {
        // A listener that never accepts: connect completes from the backlog, nothing ever answers.
        try (ServerSocketChannel silent = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            silent.bind(UnixDomainSocketAddress.of(sock));
            try (SshAgentClient c = SshAgentClient.connect(sock, AgentSocket.currentUser(sock), Duration.ofMillis(200))) {
                long start = System.nanoTime();
                assertEquals(SshException.Code.TIMEOUT, assertThrows(SshException.class, c::list).code());
                assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(5)) < 0);
                assertEquals(SshException.Code.IO, assertThrows(SshException.class, c::removeAll).code(),
                        "closed after the timeout");
            }
        }
    }

    @Test
    void timeoutsMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> SshAgentClient.connect(sock, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> SshAgentClient.connect(sock, Duration.ofSeconds(-1)));
        assertThrows(NullPointerException.class, () -> SshAgentClient.connect(sock, (Duration) null));
        assertEquals(Duration.ofSeconds(10), SshAgentClient.DEFAULT_TIMEOUT);
    }

    private SshException.Code badSimpleReply(byte[] raw) throws IOException, SshException {
        try (SshAgentClient c = hangingUp(req -> raw)) {
            return assertThrows(SshException.class, c::removeAll).code();
        }
    }

    @Test
    void oversizedTruncatedAndUnexpectedRepliesAreRejected() throws IOException, SshException {
        // Zero-length frame, a frame one byte over the limit, a 2^32-1 length.
        assertEquals(SshException.Code.BAD_REPLY, badSimpleReply(new byte[] {0, 0, 0, 0}));
        restart();
        assertEquals(SshException.Code.BAD_REPLY, badSimpleReply(new KeyFixtures.W()
                .u32(SshAgentClient.MAX_MESSAGE + 1L).bytes()));
        restart();
        assertEquals(SshException.Code.BAD_REPLY, badSimpleReply(new byte[] {-1, -1, -1, -1}));
        restart();
        // Success with trailing data; an unknown type; a two-byte failure.
        assertEquals(SshException.Code.BAD_REPLY, badSimpleReply(TestAgent.frame(new byte[] {SshAgentClient.SUCCESS, 0})));
        restart();
        assertEquals(SshException.Code.BAD_REPLY, badSimpleReply(TestAgent.frame(new byte[] {7})));
        restart();
        assertEquals(SshException.Code.BAD_REPLY, badSimpleReply(TestAgent.frame(new byte[] {SshAgentClient.FAILURE, 0})));
        restart();
        // The agent hangs up mid-header and mid-body.
        assertEquals(SshException.Code.BAD_REPLY, badSimpleReply(new byte[] {0, 0}));
        restart();
        assertEquals(SshException.Code.BAD_REPLY, badSimpleReply(new byte[] {0, 0, 0, 9, SshAgentClient.SUCCESS}));
    }

    @Test
    void aBrokenStreamClosesTheConnection() throws IOException, SshException {
        try (SshAgentClient c = scripted(req -> new byte[] {0, 0, 0, 0})) {
            assertEquals(SshException.Code.BAD_REPLY, assertThrows(SshException.class, c::removeAll).code());
            assertEquals(SshException.Code.IO, assertThrows(SshException.class, c::list).code());
        }
    }

    @Test
    void aHangUpBeforeAnyReplyIsBadReply() throws IOException, SshException {
        try (SshAgentClient c = scripted(req -> new byte[0])) {
            assertEquals(SshException.Code.BAD_REPLY, assertThrows(SshException.class, c::list).code());
        }
    }

    // ---- socket path checks (CERT FIO00-J, FIO15-J, FIO16-J; SR-061) ----

    private SshException.Code connectRefused(Path p) {
        return assertThrows(SshException.class, () -> SshAgentClient.connect(p).close()).code();
    }

    @Test
    void noSocketMeansNoAgent() throws IOException {
        assertEquals(SshException.Code.NO_AGENT, connectRefused(sock));
        assertEquals(SshException.Code.NO_AGENT, connectRefused(tmp.resolve("missing").resolve("s")));
        // A stale socket file nobody listens on.
        try (ServerSocketChannel s = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            s.bind(UnixDomainSocketAddress.of(sock));
        }
        assertTrue(Files.exists(sock));
        assertEquals(SshException.Code.NO_AGENT, connectRefused(sock));
    }

    @Test
    void refusesRelativeAndRootPaths() {
        assertEquals(SshException.Code.UNSAFE_SOCKET, connectRefused(Path.of("agent.sock")));
        assertEquals(SshException.Code.UNSAFE_SOCKET, connectRefused(Path.of("/")));
    }

    // FIO00-J: the modes are test parameters so each write bit is covered (as in SymlinkRefusedTest).
    @ParameterizedTest
    @ValueSource(strings = {"rwxrwx---", "rwx----w-", "rwxrwxrwx"})
    void refusesAGroupOrWorldWritableDirectory(String shared) throws IOException {
        agent = TestAgent.start(sock);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString(shared));
        assertEquals(SshException.Code.UNSAFE_SOCKET, connectRefused(sock));
    }

    @ParameterizedTest
    @ValueSource(strings = {"rwxr-x---", "rwxr-xr-x"})
    void acceptsADirectoryOthersCanOnlyRead(String readable) throws IOException, SshException {
        agent = TestAgent.start(sock);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString(readable));
        try (SshAgentClient c = client()) {
            assertEquals(List.of(), c.list());
        }
    }

    @Test
    void refusesALinkARegularFileAndAFileAsDirectory() throws IOException {
        agent = TestAgent.start(sock);
        Path link = dir.resolve("link");
        Files.createSymbolicLink(link, sock);
        assertEquals(SshException.Code.UNSAFE_SOCKET, connectRefused(link));
        Path plain = Files.createFile(dir.resolve("plain"));
        assertEquals(SshException.Code.UNSAFE_SOCKET, connectRefused(plain));
        assertEquals(SshException.Code.UNSAFE_SOCKET, connectRefused(plain.resolve("s")));
    }

    @Test
    void aLinkedDirectoryIsCanonicalisedThenChecked() throws IOException, SshException {
        agent = TestAgent.start(sock);
        Path alias = Files.createSymbolicLink(tmp.resolve("alias"), dir);
        try (SshAgentClient c = SshAgentClient.connect(alias.resolve("s"))) {
            assertEquals(List.of(), c.list());
        }
    }

    private static void shut(SocketChannel ch) throws IOException {
        ch.close();
    }

    @Test
    void checksTheListeningProcessAfterConnecting() throws IOException {
        agent = TestAgent.start(sock);
        UserPrincipal root = sock.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName("root");
        UserPrincipal me = sock.getFileSystem().getUserPrincipalLookupService()
                .lookupPrincipalByName(System.getProperty("user.name"));
        try (SocketChannel ch = SocketChannel.open(UnixDomainSocketAddress.of(sock))) {
            assertDoesNotThrow(() -> AgentSocket.checkPeer(ch, me, sock));
            // The peer runs as this user, not root: a swapped socket served by another user is refused.
            assertEquals(SshException.Code.UNSAFE_SOCKET,
                    assertThrows(SshException.class, () -> AgentSocket.checkPeer(ch, root, sock)).code());
            shut(ch);
            assertEquals(SshException.Code.UNSAFE_SOCKET,
                    assertThrows(SshException.class, () -> AgentSocket.checkPeer(ch, me, sock)).code());
        }
    }

    @Test
    void refusesASocketOwnedBySomeoneElse() throws IOException {
        agent = TestAgent.start(sock);
        UserPrincipal root = user("root");
        assertEquals(SshException.Code.UNSAFE_SOCKET,
                assertThrows(SshException.class, () -> SshAgentClient.connect(sock, root).close()).code());
        // The directory check passes on the name; the socket must belong to this very account.
        UserPrincipal namesake = () -> System.getProperty("user.name");
        assertEquals(SshException.Code.UNSAFE_SOCKET,
                assertThrows(SshException.class, () -> AgentSocket.check(sock, namesake)).code());
    }

    @Test
    void refusesADirectoryOwnedBySomeoneElse() throws IOException {
        agent = TestAgent.start(sock);
        UserPrincipal nobody = user("nobody");
        assertEquals(SshException.Code.UNSAFE_SOCKET,
                assertThrows(SshException.class, () -> AgentSocket.check(sock, nobody)).code());
    }

    @Test
    void theUserAndRootAreTrustedAndNoOneElse() throws IOException {
        UserPrincipal me = user(System.getProperty("user.name"));
        UserPrincipal root = user("root");
        UserPrincipal nobody = user("nobody");
        assertTrue(AgentSocket.trusted(me, me));
        assertTrue(AgentSocket.trusted(root, me));
        assertFalse(AgentSocket.trusted(nobody, me));
        assertFalse(AgentSocket.trusted(me, nobody));
    }

    /** SR-140: a peer running as root is trusted only where root is launchd holding this user's listener. */
    @Test
    void aRootPeerIsTrustedOnlyWhereAllowed() throws IOException {
        UserPrincipal me = user(System.getProperty("user.name"));
        UserPrincipal root = user("root");
        UserPrincipal nobody = user("nobody");
        assertTrue(AgentSocket.peerTrusted(me, me, false));
        assertTrue(AgentSocket.peerTrusted(root, me, true));
        assertFalse(AgentSocket.peerTrusted(root, me, false));
        assertFalse(AgentSocket.peerTrusted(nobody, me, true));
    }

    /**
     * SR-140: launchd's listener is recognised by its place, name, owner and mode, read without
     * following links; anything else is a socket a root peer may not serve.
     */
    @Test
    void launchdsListenerIsRecognisedByPlaceOwnerAndMode() throws IOException {
        UserPrincipal me = user(System.getProperty("user.name"));
        Path run = Files.createDirectory(tmp.resolve("run"));
        Path folder = Files.createDirectory(run.resolve("com.apple.launchd.abc"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path listeners = folder.resolve("Listeners");
        assertTrue(AgentSocket.launchdListener(listeners, me, run));
        // Another socket name, another folder name, a folder one level deeper, no folder at all.
        assertFalse(AgentSocket.launchdListener(folder.resolve("s"), me, run));
        Path agent = Files.createDirectory(run.resolve("agent"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        assertFalse(AgentSocket.launchdListener(agent.resolve("Listeners"), me, run));
        Path deeper = Files.createDirectory(folder.resolve("com.apple.launchd.x"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        assertFalse(AgentSocket.launchdListener(deeper.resolve("Listeners"), me, run));
        assertFalse(AgentSocket.launchdListener(tmp.getRoot(), me, run));
        // Someone else's folder, or one with any other permission bit.
        assertFalse(AgentSocket.launchdListener(listeners, user("nobody"), run));
        Files.setPosixFilePermissions(folder, PosixFilePermissions.fromString("rwxr-x---"));
        assertFalse(AgentSocket.launchdListener(listeners, me, run));
        Files.setPosixFilePermissions(folder, PosixFilePermissions.fromString("rwx------"));
        // A link to the folder, a file in its place, a folder that is gone.
        Path link = Files.createSymbolicLink(run.resolve("com.apple.launchd.link"), folder);
        assertFalse(AgentSocket.launchdListener(link.resolve("Listeners"), me, run));
        Path file = Files.createFile(run.resolve("com.apple.launchd.file"));
        assertFalse(AgentSocket.launchdListener(file.resolve("Listeners"), me, run));
        assertFalse(AgentSocket.launchdListener(run.resolve("com.apple.launchd.gone").resolve("Listeners"), me, run));
    }

    /**
     * SR-140: macOS's own agent socket is held by launchd (pid 1, root), which starts ssh-agent on
     * the first connection. Runs only where this user has such a socket
     * ({@code /private/var/run/com.apple.launchd.*}{@code /Listeners}); it checks the path and the
     * peer and sends nothing.
     */
    @Test
    void theMacOsLaunchdAgentSocketIsAccepted() throws IOException, SshException {
        Path launchd = launchdSocket();
        Assumptions.assumeTrue(launchd != null, "no launchd agent socket");
        UserPrincipal me = AgentSocket.currentUser(launchd);
        Path real = AgentSocket.check(launchd, me);
        try (SocketChannel ch = SocketChannel.open(UnixDomainSocketAddress.of(real))) {
            assertEquals("root", ch.getOption(ExtendedSocketOptions.SO_PEERCRED).user().getName());
            assertTrue(AgentSocket.launchdListener(real, me, AgentSocket.LAUNCHD_RUN));
            assertDoesNotThrow(() -> AgentSocket.checkPeer(ch, me, real));
            // The same root peer behind any other path could be another user's launchd job.
            assertEquals(SshException.Code.UNSAFE_SOCKET,
                    assertThrows(SshException.class, () -> AgentSocket.checkPeer(ch, me, sock)).code());
        }
    }

    /** This user's launchd-held socket, or null; other users' launchd folders are not readable. */
    private static Path launchdSocket() throws IOException {
        Path run = Path.of("/private/var/run");
        if (!Files.isDirectory(run)) {
            return null;
        }
        try (DirectoryStream<Path> dirs = Files.newDirectoryStream(run, "com.apple.launchd.*")) {
            for (Path d : dirs) {
                Path listeners = d.resolve("Listeners");
                if (Files.isReadable(d) && Files.exists(listeners, LinkOption.NOFOLLOW_LINKS)) {
                    return listeners;
                }
            }
        }
        return null;
    }

    private UserPrincipal user(String name) throws IOException {
        return sock.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(name);
    }
}
