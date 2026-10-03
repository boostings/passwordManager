package pm.crypto.ssh;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.UnaryOperator;
import pm.crypto.ConstantTime;

/**
 * A minimal ssh-agent for tests (draft-miller-ssh-agent): listens on a Unix domain socket and
 * serves one connection at a time on one executor thread. By default it keeps identities like a
 * real agent (request-identities, add, add-constrained, remove, remove-all); a {@code script}
 * instead answers every request with raw bytes, so tests can send malformed, oversized and
 * truncated replies. A script that returns an empty array makes the agent hang up without replying.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-020: the test agent must answer while the client blocks
final class TestAgent implements AutoCloseable {
    /** One identity the agent holds. */
    static final class Held {
        final byte[] blob;
        final byte[] fields;
        final String comment;
        final long lifetime;
        final boolean confirm;

        Held(byte[] blob, byte[] fields, String comment, long lifetime, boolean confirm) {
            this.blob = blob.clone();
            this.fields = fields.clone();
            this.comment = comment;
            this.lifetime = lifetime;
            this.confirm = confirm;
        }
    }

    final List<Held> held = new CopyOnWriteArrayList<>();
    final List<byte[]> requests = new CopyOnWriteArrayList<>();
    final List<Throwable> errors = new CopyOnWriteArrayList<>();
    private final ServerSocketChannel server;
    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private final UnaryOperator<byte[]> script;
    private final boolean hangUp;

    private TestAgent(ServerSocketChannel server, UnaryOperator<byte[]> script, boolean hangUp) {
        this.server = server;
        this.script = script;
        this.hangUp = hangUp;
    }

    static TestAgent start(Path socket) throws IOException {
        return start(socket, null, false);
    }

    /** A scripted agent; with {@code hangUp} it closes the connection after each reply (truncation tests). */
    static TestAgent start(Path socket, UnaryOperator<byte[]> script, boolean hangUp) throws IOException {
        TestAgent a = new TestAgent(bind(socket), script, hangUp);
        a.exec.execute(a::acceptLoop);
        return a;
    }

    private static ServerSocketChannel bind(Path socket) throws IOException {
        ServerSocketChannel s = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        s.bind(UnixDomainSocketAddress.of(socket));
        return s;
    }

    private void acceptLoop() {
        while (server.isOpen()) {
            try (SocketChannel ch = server.accept()) {
                serve(ch);
            } catch (IOException e) {
                if (server.isOpen()) {
                    errors.add(e);
                }
            }
        }
    }

    private void serve(SocketChannel ch) throws IOException {
        while (true) {
            ByteBuffer len = ByteBuffer.allocate(4);
            if (!fill(ch, len)) {
                return;
            }
            ByteBuffer body = ByteBuffer.allocate(len.getInt(0));
            if (!fill(ch, body)) {
                return;
            }
            requests.add(body.array());
            byte[] out = script == null ? frame(handle(body.array())) : script.apply(body.array());
            if (out.length == 0) {
                return;
            }
            ByteBuffer b = ByteBuffer.wrap(out);
            while (b.hasRemaining()) {
                ch.write(b);
            }
            if (hangUp) {
                return;
            }
        }
    }

    private static boolean fill(SocketChannel ch, ByteBuffer b) throws IOException {
        while (b.hasRemaining()) {
            if (ch.read(b) < 0) {
                return false;
            }
        }
        return true;
    }

    static byte[] frame(byte[] body) {
        return new KeyFixtures.W().str(body).bytes();
    }

    private byte[] handle(byte[] req) {
        try {
            WireReader r = WireReader.over(req, SshException.Code.BAD_REPLY);
            int type = r.u8();
            if (type == SshAgentClient.REQUEST_IDENTITIES) {
                KeyFixtures.W w = new KeyFixtures.W().u8(SshAgentClient.IDENTITIES_ANSWER).u32(held.size());
                for (Held h : held) {
                    w.str(h.blob).str(h.comment);
                }
                return w.bytes();
            }
            if (type == SshAgentClient.ADD_IDENTITY || type == SshAgentClient.ADD_ID_CONSTRAINED) {
                return add(r, req, type == SshAgentClient.ADD_ID_CONSTRAINED);
            }
            if (type == SshAgentClient.REMOVE_IDENTITY) {
                byte[] blob = r.string(SshKey.MAX_BLOB_BYTES);
                r.expectEnd();
                return held.removeIf(h -> ConstantTime.equals(h.blob, blob)) ? ok() : fail();
            }
            if (type == SshAgentClient.REMOVE_ALL_IDENTITIES) {
                held.clear();
                return ok();
            }
            return fail();
        } catch (SshException e) {
            errors.add(e);
            return fail();
        }
    }

    private byte[] add(WireReader r, byte[] req, boolean constrained) throws SshException {
        int start = r.position();
        String name = SshKey.ascii(r.string(64));
        KeyFixtures.W blob = new KeyFixtures.W().str(name);
        if (SshKeyType.fromWireName(name) == SshKeyType.ED25519) {
            blob.str(r.string(32));
            r.string(64);
        } else {
            blob.str(r.string(64)).str(r.string(65));
            r.string(33);
        }
        byte[] fields = Arrays.copyOfRange(req, start, r.position());
        String comment = SshKey.ascii(r.string(4096));
        long lifetime = 0;
        boolean confirm = false;
        while (constrained && r.remaining() > 0) {
            int c = r.u8();
            if (c == AgentConstraints.CONSTRAIN_LIFETIME) {
                lifetime = r.u32();
            } else if (c == AgentConstraints.CONSTRAIN_CONFIRM) {
                confirm = true;
            } else {
                return fail();
            }
        }
        r.expectEnd();
        held.removeIf(h -> ConstantTime.equals(h.blob, blob.bytes()));
        held.add(new Held(blob.bytes(), fields, comment, lifetime, confirm));
        return ok();
    }

    private static byte[] ok() {
        return new byte[] {SshAgentClient.SUCCESS};
    }

    private static byte[] fail() {
        return new byte[] {SshAgentClient.FAILURE};
    }

    @Override
    public void close() throws IOException {
        server.close();
        exec.shutdownNow();
        exec.close();
    }
}
