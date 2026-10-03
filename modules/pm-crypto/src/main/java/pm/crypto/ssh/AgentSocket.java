package pm.crypto.ssh;

import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Objects;
import java.util.Set;
import jdk.net.ExtendedSocketOptions;
import jdk.net.UnixDomainPrincipal;

/**
 * CERT FIO rules for the agent socket path (FIO00-J, FIO15-J, FIO16-J; SR-061). The directory is
 * canonicalised first ({@code toRealPath}), then both it and the socket are read with
 * {@code NOFOLLOW_LINKS}: the directory must not be group- or world-writable, and the socket must
 * be a socket (not a link or a regular file) owned by the current user. The canonical path is what
 * the client connects to. File systems without POSIX attributes are refused; Windows agents use
 * named pipes, which are out of scope (ADR 0013).
 */
final class AgentSocket {
    private AgentSocket() {
    }

    /**
     * The canonical socket path, after the checks.
     *
     * @throws SshException {@code NO_AGENT} if the socket or its directory does not exist,
     *     {@code UNSAFE_SOCKET} if any check fails
     */
    static Path check(Path socket, UserPrincipal me) throws SshException {
        Path parent = socket.getParent();
        if (!socket.isAbsolute() || parent == null) {
            throw new SshException(SshException.Code.UNSAFE_SOCKET);
        }
        // An absolute path with a parent always has a file name.
        Path name = Objects.requireNonNull(socket.getFileName(), "name");
        try {
            Path dir = parent.toRealPath();
            PosixFileAttributes d = Files.readAttributes(dir, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            Set<PosixFilePermission> perms = d.permissions();
            if (!d.isDirectory() || perms.contains(PosixFilePermission.GROUP_WRITE)
                    || perms.contains(PosixFilePermission.OTHERS_WRITE)) {
                throw new SshException(SshException.Code.UNSAFE_SOCKET);
            }
            Path real = dir.resolve(name);
            PosixFileAttributes s = Files.readAttributes(real, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!s.isOther() || !s.owner().equals(me)) {
                throw new SshException(SshException.Code.UNSAFE_SOCKET);
            }
            return real;
        } catch (NoSuchFileException e) {
            throw new SshException(SshException.Code.NO_AGENT);
        } catch (IOException | UnsupportedOperationException e) {
            throw new SshException(SshException.Code.UNSAFE_SOCKET);
        }
    }

    /**
     * Checks the process at the other end of a connected socket ({@code SO_PEERCRED}, as the
     * approval broker does on its server side): it must run as {@code me}. This closes the window
     * between {@link #check} and connecting, in which the socket could be replaced.
     *
     * @throws SshException {@code UNSAFE_SOCKET} if the peer is another user or cannot be read
     */
    static void checkPeer(SocketChannel ch, UserPrincipal me) throws SshException {
        try {
            UnixDomainPrincipal peer = ch.getOption(ExtendedSocketOptions.SO_PEERCRED);
            if (!peer.user().getName().equals(me.getName())) {
                throw new SshException(SshException.Code.UNSAFE_SOCKET);
            }
        } catch (IOException | UnsupportedOperationException e) {
            throw new SshException(SshException.Code.UNSAFE_SOCKET);
        }
    }

    /**
     * The account named by {@code user.name} on {@code socket}'s file system.
     *
     * @throws SshException {@code UNSAFE_SOCKET} if the account database does not know it
     */
    static UserPrincipal currentUser(Path socket) throws SshException {
        try {
            return socket.getFileSystem().getUserPrincipalLookupService()
                    .lookupPrincipalByName(System.getProperty("user.name", ""));
        } catch (IOException e) {
            throw new SshException(SshException.Code.UNSAFE_SOCKET);
        }
    }
}
