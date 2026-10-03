package pm.sharing.net;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.SSLSocket;
import pm.crypto.CryptoException;
import pm.crypto.Tls;
import pm.sharing.wire.Frames;
import pm.sharing.wire.Message;
import pm.sharing.wire.Messages;
import pm.sharing.wire.WireException;

/**
 * One authenticated TLS connection carrying framed messages. Every received frame is decoded
 * strictly before it is returned (SR-206). Not thread-safe: one reader, one writer, same thread.
 */
public final class PeerLink implements Closeable {
    private final SSLSocket socket;
    private final InputStream in;
    private final OutputStream out;
    private final byte[] provenKey;

    private PeerLink(SSLSocket socket, byte[] peerKey) throws IOException {
        this.socket = socket;
        this.in = new BufferedInputStream(socket.getInputStream());
        this.out = new BufferedOutputStream(socket.getOutputStream());
        this.provenKey = peerKey;
    }

    static PeerLink handshake(SSLSocket socket) throws IOException, CryptoException {
        try {
            socket.setSoTimeout(Math.toIntExact(Lan.READ_TIMEOUT.toMillis()));
            socket.startHandshake();
            return new PeerLink(socket, Tls.peerPublicKey(socket.getSession()));
        } catch (IOException | CryptoException e) {
            socket.close();
            throw e;
        }
    }

    /** The raw public key the peer proved in the handshake. */
    public byte[] peerKey() {
        return provenKey.clone();
    }

    /** Sends {@code messages} in order. */
    public void send(List<Message> messages) throws IOException {
        for (Message m : messages) {
            Frames.write(out, Messages.encode(m));
        }
    }

    /**
     * The next message.
     *
     * @throws WireException for a closed stream or any frame that does not decode
     */
    public Message receive() throws IOException, WireException {
        return Messages.decode(Frames.read(in));
    }

    /** Changes the read timeout, e.g. while a person compares digits. */
    public void readTimeout(Duration timeout) throws IOException {
        socket.setSoTimeout(Math.toIntExact(timeout.toMillis()));
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
