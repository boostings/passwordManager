package pm.approval.ipc;

import java.io.IOException;
import java.net.ConnectException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.SocketChannel;
import java.nio.file.NoSuchFileException;
import java.util.Arrays;
import pm.approval.ApprovalRequest;
import pm.crypto.SecretBytes;

/** Sends one request to a running broker and waits for its reply (up to the prompt timeout). */
public final class BrokerClient {
    private BrokerClient() {
    }

    /**
     * Sends {@code request} with the token from {@code dir}.
     *
     * @throws IpcException {@code NO_BROKER} if no broker is listening or the vault is locked,
     *     {@code UNSAFE_PATH} if the token file is unsafe, {@code MALFORMED} or {@code IO} otherwise
     */
    public static Reply call(RunDir dir, ApprovalRequest request) throws IpcException {
        byte[] frame;
        try (SecretBytes token = dir.readToken()) {
            frame = IpcCodec.encodeRequest(request, token);
        }
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(UnixDomainSocketAddress.of(dir.socketPath()));
            Frames.write(ch, frame);
            return IpcCodec.decodeReply(Frames.read(ch, Frames.MAX_REPLY));
        } catch (ConnectException | NoSuchFileException e) {
            throw new IpcException(IpcException.Code.NO_BROKER, e);
        } catch (IOException e) {
            throw new IpcException(IpcException.Code.IO, e);
        } finally {
            Arrays.fill(frame, (byte) 0);
        }
    }
}
