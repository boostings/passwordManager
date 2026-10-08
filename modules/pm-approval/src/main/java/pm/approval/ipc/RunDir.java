package pm.approval.ipc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import pm.approval.ApprovalBroker;
import pm.crypto.SecretBytes;
import pm.domain.env.Env;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;

/**
 * The broker's run directory: {@code $XDG_RUNTIME_DIR/pm} when set, otherwise {@code run} next to
 * the vault. It is created 0700, must not be a link and must be owned by this user; it holds the
 * socket {@value #SOCKET} and the 0600 token file {@value #AUTH_FILE}.
 */
public final class RunDir {
    /** Socket file name. */
    public static final String SOCKET = "broker.sock";
    /** Token file name. */
    public static final String AUTH_FILE = "token";

    private final Path dir;

    private RunDir(Path dir) {
        this.dir = dir;
    }

    /** The run directory for {@code env} and a vault stored in {@code vaultDir}; not yet checked. */
    public static Path locate(Env env, Path vaultDir) {
        return env.path(Env.Var.XDG_RUNTIME_DIR).map(p -> p.resolve("pm")).orElse(vaultDir.resolve("run"));
    }

    /**
     * Creates {@code dir} if needed (0700) and checks it.
     *
     * @throws IpcException {@code UNSAFE_PATH} if it is a link, not a directory or not owner-only
     */
    public static RunDir prepare(Path dir) throws IpcException {
        Objects.requireNonNull(dir, "dir");
        try {
            if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
                Path parent = Objects.requireNonNull(dir.toAbsolutePath().getParent(), "parent");
                Files.createDirectories(parent);
                try {
                    // Owner-only from creation (0700, or an ACL naming only the owner), then exact.
                    Files.createDirectory(dir, OwnerOnly.creationAttributes(parent, true));
                    OwnerOnly.apply(dir);
                } catch (FileAlreadyExistsException e) {
                    // Raced with another process; checked below like any existing directory.
                    Objects.requireNonNull(e);
                }
            }
            return open(dir);
        } catch (IOException | StorageException e) {
            throw new IpcException(IpcException.Code.UNSAFE_PATH, e);
        }
    }

    /**
     * Checks an existing run directory without creating anything (the client side).
     *
     * @throws IpcException {@code NO_BROKER} if it is absent, {@code UNSAFE_PATH} if unsafe
     */
    public static RunDir existing(Path dir) throws IpcException {
        if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            throw new IpcException(IpcException.Code.NO_BROKER, null);
        }
        return open(dir);
    }

    private static RunDir open(Path dir) throws IpcException {
        try {
            BasicFileAttributes a = Files.readAttributes(dir, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            // Read without following links, so a link is never a directory.
            if (!a.isDirectory() || !OwnerOnly.isOwnerOnly(dir)) {
                throw new IpcException(IpcException.Code.UNSAFE_PATH, null);
            }
        } catch (IOException | StorageException e) {
            throw new IpcException(IpcException.Code.UNSAFE_PATH, e);
        }
        return new RunDir(dir);
    }

    /** The directory. */
    public Path path() {
        return dir;
    }

    /** The socket path. */
    public Path socketPath() {
        return dir.resolve(SOCKET);
    }

    /** Writes the broker's current token, replacing any old one atomically. */
    void writeToken(ApprovalBroker broker) throws IpcException {
        Path tmp = dir.resolve(AUTH_FILE + ".new");
        try {
            Files.deleteIfExists(tmp);
            try (FileChannel ch = createOwnerOnly(tmp)) {
                broker.withToken(t -> {
                    try {
                        ch.write(ByteBuffer.wrap(t));
                        ch.force(true);
                        return null;
                    } catch (IOException e) {
                        throw new IllegalStateException(e);
                    }
                });
            }
            Files.move(tmp, dir.resolve(AUTH_FILE), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException | IllegalStateException | StorageException e) {
            throw new IpcException(IpcException.Code.IO, e);
        }
    }

    /** Removes the token file (on lock). */
    void deleteToken() throws IpcException {
        try {
            Files.deleteIfExists(dir.resolve(AUTH_FILE));
        } catch (IOException e) {
            throw new IpcException(IpcException.Code.IO, e);
        }
    }

    /**
     * Reads the token file.
     *
     * @throws IpcException {@code NO_BROKER} if absent (vault locked or no broker),
     *     {@code UNSAFE_PATH} if it is a link or open to others, {@code MALFORMED} if the wrong size
     */
    SecretBytes readToken() throws IpcException {
        Path file = dir.resolve(AUTH_FILE);
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IpcException(IpcException.Code.NO_BROKER, null);
        }
        try {
            // isOwnerOnly reads without following links and refuses a link.
            if (!OwnerOnly.isOwnerOnly(file)) {
                throw new IpcException(IpcException.Code.UNSAFE_PATH, null);
            }
            try (SeekableByteChannel ch = Files.newByteChannel(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                // Room for one byte more than a token, so a longer file is told apart while the
                // count read is final: the size is never checked apart from the read.
                ByteBuffer buf = ByteBuffer.allocate(ApprovalBroker.TOKEN_BYTES + 1);
                while (buf.hasRemaining()) {
                    if (ch.read(buf) < 0) {
                        break;
                    }
                }
                byte[] read = buf.array();
                try {
                    if (buf.position() != ApprovalBroker.TOKEN_BYTES) {
                        throw new IpcException(IpcException.Code.MALFORMED, null);
                    }
                    return SecretBytes.takeOwnership(Arrays.copyOf(read, ApprovalBroker.TOKEN_BYTES));
                } finally {
                    Arrays.fill(read, (byte) 0);
                }
            }
        } catch (NoSuchFileException e) {
            throw new IpcException(IpcException.Code.NO_BROKER, e);
        } catch (StorageException e) {
            // OwnerOnly reports a link, other kinds of file and unreadable permissions alike.
            throw new IpcException(IpcException.Code.UNSAFE_PATH, e);
        } catch (IOException e) {
            throw new IpcException(IpcException.Code.IO, e);
        }
    }

    private static FileChannel createOwnerOnly(Path path) throws IOException, StorageException {
        Set<OpenOption> opts = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        Path parent = Objects.requireNonNull(path.toAbsolutePath().getParent(), "parent");
        FileChannel ch = FileChannel.open(path, opts, OwnerOnly.creationAttributes(parent, false));
        try {
            OwnerOnly.apply(path);
        } catch (StorageException e) {
            ch.close();
            throw e;
        }
        return ch;
    }
}
