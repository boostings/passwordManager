package pm.cli;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import pm.crypto.ConstantTime;

/**
 * A minimal ssh-agent for the CLI tests (draft-miller-ssh-agent), Ed25519 only: request-identities,
 * add-identity, add-identity-constrained (lifetime, confirm), remove-identity and remove-all. It
 * serves one connection at a time on a single executor thread, on a Unix domain socket in an
 * owner-only temporary directory, so the real {@code SshAgentClient} socket checks pass. Any parse
 * problem answers {@code SSH_AGENT_FAILURE} and is recorded in {@link #errors}.
 */
// CE-045: the agent must answer while the client under test blocks; the server channel is closed in close()
@SuppressWarnings({"PMD.DoNotUseThreads", "PMD.CloseResource"})
final class TestSshAgent implements AutoCloseable {
    static final int FAILURE = 5;
    static final int SUCCESS = 6;
    static final int REQUEST_IDENTITIES = 11;
    static final int IDENTITIES_ANSWER = 12;
    static final int ADD_IDENTITY = 17;
    static final int REMOVE_IDENTITY = 18;
    static final int REMOVE_ALL = 19;
    static final int ADD_CONSTRAINED = 25;
    private static final int CONSTRAIN_LIFETIME = 1;
    private static final int CONSTRAIN_CONFIRM = 2;

    /** One identity the agent holds; {@code fields} are the private key fields it received. */
    static final class Held {
        private final byte[] blobBytes;
        private final byte[] fieldBytes;
        private final String commentText;
        private final long lifetimeSeconds;
        private final boolean confirmEach;

        Held(byte[] blob, byte[] fields, String comment, long lifetime, boolean confirm) {
            this.blobBytes = blob.clone();
            this.fieldBytes = fields.clone();
            this.commentText = comment;
            this.lifetimeSeconds = lifetime;
            this.confirmEach = confirm;
        }

        byte[] blob() {
            return blobBytes.clone();
        }

        byte[] fields() {
            return fieldBytes.clone();
        }

        String comment() {
            return commentText;
        }

        long lifetime() {
            return lifetimeSeconds;
        }

        boolean confirm() {
            return confirmEach;
        }
    }

    final List<Held> held = new CopyOnWriteArrayList<>();
    final List<Integer> requestTypes = new CopyOnWriteArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();
    private final ServerSocketChannel server;
    private final ExecutorService exec = Executors.newSingleThreadExecutor();

    private TestSshAgent(ServerSocketChannel server) {
        this.server = server;
    }

    static TestSshAgent start(Path socket) throws IOException {
        ServerSocketChannel s = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        s.bind(UnixDomainSocketAddress.of(socket));
        TestSshAgent a = new TestSshAgent(s);
        a.exec.execute(a::acceptLoop);
        return a;
    }

    private void acceptLoop() {
        while (server.isOpen()) {
            try (SocketChannel ch = server.accept()) {
                serve(ch);
            } catch (IOException e) {
                if (server.isOpen()) {
                    errors.add("io");
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
            byte[] reply = handle(body.array());
            ByteBuffer out = ByteBuffer.wrap(new SshTestKeys.W().str(reply).bytes());
            while (out.hasRemaining()) {
                ch.write(out);
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

    private byte[] handle(byte[] req) {
        Reader r = new Reader(req);
        int type = r.u8();
        requestTypes.add(type);
        try {
            if (type == REQUEST_IDENTITIES) {
                SshTestKeys.W w = new SshTestKeys.W().u8(IDENTITIES_ANSWER).u32(held.size());
                held.forEach(h -> w.str(h.blob()).str(h.comment()));
                return w.bytes();
            }
            if (type == ADD_IDENTITY || type == ADD_CONSTRAINED) {
                return add(r, req);
            }
            if (type == REMOVE_IDENTITY) {
                byte[] blob = r.string();
                return held.removeIf(h -> ConstantTime.equals(h.blob(), blob)) ? ok() : fail();
            }
            if (type == REMOVE_ALL) {
                held.clear();
                return ok();
            }
        } catch (IndexOutOfBoundsException e) {
            errors.add("parse");
        }
        return fail();
    }

    private byte[] add(Reader r, byte[] req) {
        int start = r.pos;
        String name = new String(r.string(), StandardCharsets.US_ASCII);
        byte[] pub = r.string();
        r.string(); // seed || public key
        byte[] fields = Arrays.copyOfRange(req, start, r.pos);
        String comment = new String(r.string(), StandardCharsets.UTF_8);
        long lifetime = 0;
        boolean confirm = false;
        while (r.pos < req.length) {
            int c = r.u8();
            if (c == CONSTRAIN_LIFETIME) {
                lifetime = r.u32();
            } else if (c == CONSTRAIN_CONFIRM) {
                confirm = true;
            } else {
                errors.add("constraint");
                return fail();
            }
        }
        byte[] blob = new SshTestKeys.W().str(name).str(pub).bytes();
        held.removeIf(h -> ConstantTime.equals(h.blob(), blob));
        held.add(new Held(blob, fields, comment, lifetime, confirm));
        return ok();
    }

    private static byte[] ok() {
        return new byte[] {SUCCESS};
    }

    private static byte[] fail() {
        return new byte[] {FAILURE};
    }

    @Override
    public void close() throws IOException {
        server.close();
        exec.shutdownNow();
        exec.close();
    }

    /** Bounds-checked (by the array) SSH wire reader. */
    private static final class Reader {
        private final byte[] buf;
        private int pos;

        Reader(byte[] buf) {
            this.buf = buf.clone();
        }

        int u8() {
            return buf[pos++] & 0xff;
        }

        long u32() {
            long v = 0;
            for (int i = 0; i < 4; i++) {
                v = (v << 8) | u8();
            }
            return v;
        }

        byte[] string() {
            int n = (int) u32();
            byte[] out = Arrays.copyOfRange(buf, pos, Math.addExact(pos, n));
            if (pos + n > buf.length) {
                throw new IndexOutOfBoundsException("short");
            }
            pos += n;
            return out;
        }
    }
}
