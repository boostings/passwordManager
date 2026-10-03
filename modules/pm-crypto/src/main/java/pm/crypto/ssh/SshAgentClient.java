package pm.crypto.ssh;

import java.io.IOException;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Client for the ssh-agent protocol (draft-miller-ssh-agent) over the Unix domain socket named by
 * {@code $SSH_AUTH_SOCK} (ADR 0013, SR-060 to SR-063). Supports listing, adding (optionally with a
 * lifetime and confirmation) and removing identities. The caller reads {@code SSH_AUTH_SOCK}
 * through {@code pm.domain.env.Env} (ENV02-J) and passes the path in.
 *
 * <p>Every reply is length-checked before it is read: a frame of 0 bytes or over
 * {@value #MAX_MESSAGE} bytes, a truncated frame, an unexpected message type, a field whose length
 * runs past the frame and trailing bytes are all {@code BAD_REPLY}. After a transport error or a
 * bad frame the connection is closed, since the stream can no longer be trusted to be in step.
 * The socket is blocking; a hung agent hangs the call (the agent is the user's own process, ADR
 * 0013). Not thread-safe.
 */
public final class SshAgentClient implements AutoCloseable {
    /** Largest reply accepted (and far above any request this client sends). */
    public static final int MAX_MESSAGE = 256 * 1024;
    /** Most identities accepted in one list reply. */
    public static final int MAX_IDENTITIES = 1024;
    static final int FAILURE = 5;
    static final int SUCCESS = 6;
    static final int REQUEST_IDENTITIES = 11;
    static final int IDENTITIES_ANSWER = 12;
    static final int ADD_IDENTITY = 17;
    static final int REMOVE_IDENTITY = 18;
    static final int REMOVE_ALL_IDENTITIES = 19;
    static final int ADD_ID_CONSTRAINED = 25;
    private static final int U32_BYTES = 4;

    private final SocketChannel channel;

    private SshAgentClient(SocketChannel channel) {
        this.channel = channel;
    }

    /**
     * Checks the socket path (owner, link, directory permissions) and connects.
     *
     * @throws SshException {@code NO_AGENT} if nothing is there or nothing listens,
     *     {@code UNSAFE_SOCKET} if a path check fails
     */
    public static SshAgentClient connect(Path socket) throws SshException {
        Objects.requireNonNull(socket, "socket");
        return connect(socket, AgentSocket.currentUser(socket));
    }

    /**
     * {@link #connect(Path)} with the expected owner given, so tests can prove the owner check. The
     * path is checked before connecting and the listening process is checked after
     * ({@code SO_PEERCRED}), so a socket swapped between the two cannot hand the key to another
     * user.
     */
    static SshAgentClient connect(Path socket, UserPrincipal owner) throws SshException {
        Path real = AgentSocket.check(socket, owner);
        SshAgentClient client;
        try {
            client = new SshAgentClient(SocketChannel.open(UnixDomainSocketAddress.of(real)));
        } catch (IOException e) {
            throw new SshException(SshException.Code.NO_AGENT);
        }
        try {
            AgentSocket.checkPeer(client.channel, owner);
        } catch (SshException e) {
            client.close();
            throw e;
        }
        return client;
    }

    /**
     * The agent's identities ({@code SSH_AGENTC_REQUEST_IDENTITIES}).
     *
     * @throws SshException {@code AGENT_REFUSED}, {@code BAD_REPLY} or {@code IO}
     */
    public List<AgentIdentity> list() throws SshException {
        byte[] reply;
        try (WireWriter w = new WireWriter()) {
            w.u8(REQUEST_IDENTITIES);
            reply = call(w);
        }
        WireReader r = WireReader.over(reply, SshException.Code.BAD_REPLY);
        int type = r.u8();
        if (type == FAILURE) {
            throw new SshException(SshException.Code.AGENT_REFUSED);
        }
        if (type != IDENTITIES_ANSWER) {
            throw new SshException(SshException.Code.BAD_REPLY);
        }
        long n = r.u32();
        if (n > MAX_IDENTITIES) {
            throw new SshException(SshException.Code.BAD_REPLY);
        }
        List<AgentIdentity> out = new ArrayList<>();
        for (long i = 0; i < n; i++) {
            byte[] blob = r.string(SshKey.MAX_BLOB_BYTES);
            String keyType = SshKey.ascii(WireReader.over(blob, SshException.Code.BAD_REPLY).string(SshKey.MAX_NAME_BYTES));
            String comment = displayable(new String(r.string(SshKey.MAX_COMMENT_BYTES), StandardCharsets.UTF_8));
            out.add(new AgentIdentity(blob, keyType, comment));
        }
        r.expectEnd();
        return List.copyOf(out);
    }

    /**
     * Adds {@code key} ({@code SSH_AGENTC_ADD_IDENTITY}, or {@code SSH_AGENTC_ADD_ID_CONSTRAINED}
     * when {@code constraints} is not {@link AgentConstraints#NONE}). The private fields go from
     * the key's secret buffer to the socket through a heap buffer and a pm-owned direct buffer,
     * both zero-filled afterwards, so no copy is left in the JDK's cached I/O buffers. Copies pm
     * cannot reach remain in the kernel's socket buffers until the agent reads them (ADR 0013).
     *
     * @throws SshException {@code AGENT_REFUSED}, {@code BAD_REPLY} or {@code IO}
     * @throws IllegalStateException if {@code key} is closed
     */
    public void add(SshKey key, AgentConstraints constraints) throws SshException {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(constraints, "constraints");
        try (WireWriter w = new WireWriter()) {
            w.u8(constraints.isNone() ? ADD_IDENTITY : ADD_ID_CONSTRAINED);
            key.writeFields(w);
            w.string(key.comment().getBytes(StandardCharsets.UTF_8));
            constraints.write(w);
            expectSuccess(call(w));
        }
    }

    /**
     * Removes the identity with this public key blob ({@code SSH_AGENTC_REMOVE_IDENTITY}).
     *
     * @throws SshException {@code AGENT_REFUSED} if the agent does not hold it, {@code BAD_REPLY} or {@code IO}
     * @throws IllegalArgumentException if the blob is empty or longer than an agent may list
     */
    public void remove(byte[] publicKeyBlob) throws SshException {
        Objects.requireNonNull(publicKeyBlob, "publicKeyBlob");
        if (publicKeyBlob.length == 0 || publicKeyBlob.length > SshKey.MAX_BLOB_BYTES) {
            throw new IllegalArgumentException("BAD_BLOB");
        }
        try (WireWriter w = new WireWriter()) {
            w.u8(REMOVE_IDENTITY);
            w.string(publicKeyBlob);
            expectSuccess(call(w));
        }
    }

    /** Removes {@code key}'s identity; see {@link #remove(byte[])}. */
    public void remove(SshKey key) throws SshException {
        remove(Objects.requireNonNull(key, "key").publicKeyBlob());
    }

    /**
     * Removes every identity ({@code SSH_AGENTC_REMOVE_ALL_IDENTITIES}).
     *
     * @throws SshException {@code AGENT_REFUSED}, {@code BAD_REPLY} or {@code IO}
     */
    public void removeAll() throws SshException {
        try (WireWriter w = new WireWriter()) {
            w.u8(REMOVE_ALL_IDENTITIES);
            expectSuccess(call(w));
        }
    }

    private static void expectSuccess(byte[] reply) throws SshException {
        if (reply.length == 1 && reply[0] == SUCCESS) {
            return;
        }
        if (reply.length == 1 && reply[0] == FAILURE) {
            throw new SshException(SshException.Code.AGENT_REFUSED);
        }
        throw new SshException(SshException.Code.BAD_REPLY);
    }

    /**
     * Agent comments are untrusted display text: control, format (bidi overrides, zero-width) and
     * line or paragraph separator characters become {@code '?'} (see {@link SshKey#unsafeToShow}).
     */
    static String displayable(String s) {
        StringBuilder out = new StringBuilder(s.length());
        s.codePoints().forEach(c -> out.appendCodePoint(SshKey.unsafeToShow(c) ? '?' : c));
        return out.toString();
    }

    /** Sends one framed request and returns the reply body; closes the connection on any failure. */
    private byte[] call(WireWriter request) throws SshException {
        try {
            request.writeFramed(channel);
            ByteBuffer header = ByteBuffer.allocate(U32_BYTES);
            fill(header);
            long n = Integer.toUnsignedLong(header.getInt(0));
            if (n == 0 || n > MAX_MESSAGE) {
                throw new SshException(SshException.Code.BAD_REPLY);
            }
            ByteBuffer body = ByteBuffer.allocate((int) n);
            fill(body);
            return body.array();
        } catch (IOException e) {
            close();
            throw new SshException(SshException.Code.IO);
        } catch (SshException e) {
            close();
            throw e;
        }
    }

    private void fill(ByteBuffer b) throws IOException, SshException {
        while (b.hasRemaining()) {
            if (channel.read(b) < 0) {
                throw new SshException(SshException.Code.BAD_REPLY);
            }
        }
    }

    /** Closes the connection. Idempotent; a failure to close is not reported (nothing is pending). */
    @Override
    public void close() {
        try {
            channel.close();
        } catch (IOException e) {
            // Closing a socket channel releases the descriptor even when it reports an error.
            Objects.requireNonNull(e);
        }
    }
}
