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
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import jdk.net.ExtendedSocketOptions;
import jdk.net.UnixDomainPrincipal;

/**
 * CERT FIO rules for the agent socket path (FIO00-J, FIO15-J, FIO16-J; SR-061, SR-140). The
 * directory is canonicalised first ({@code toRealPath}), then both it and the socket are read with
 * {@code NOFOLLOW_LINKS}: the directory must be owned by the current user or root and must not be
 * group- or world-writable, and the socket must be a socket (not a link or a regular file) owned by
 * the current user. The canonical path is what the client connects to. File systems without POSIX
 * attributes are refused; Windows agents use named pipes, which are out of scope (ADR 0013).
 */
final class AgentSocket {
    /** The superuser's account name; root is trusted with everything already (threat model AT-2). */
    static final String ROOT = "root";
    /** Where launchd creates the per-login listener folders on macOS. */
    static final Path LAUNCHD_RUN = Path.of("/private/var/run");
    private static final String LAUNCHD_FOLDER = "com.apple.launchd.";
    private static final String LISTENERS = "Listeners";
    private static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);

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
            if (!d.isDirectory() || !trusted(d.owner(), me) || perms.contains(PosixFilePermission.GROUP_WRITE)
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
     * approval broker does on its server side). This closes the window between {@link #check} and
     * connecting, in which the socket could be replaced by another user. The peer must run as
     * {@code me}; it may run as root only if {@code real} is macOS's own agent socket
     * ({@link #launchdListener}). That socket is held by launchd, pid 1, which starts
     * {@code ssh-agent} on the first connection. launchd holds every user's job sockets the same
     * way, so a root peer elsewhere could be another user's launchd job, and is refused.
     *
     * @param real the canonical path {@link #check} returned and the client connected to
     * @throws SshException {@code UNSAFE_SOCKET} if the peer is another user, is root anywhere
     *     else, or cannot be read
     */
    static void checkPeer(SocketChannel ch, UserPrincipal me, Path real) throws SshException {
        boolean launchd = launchdListener(real, me, LAUNCHD_RUN);
        try {
            UnixDomainPrincipal peer = ch.getOption(ExtendedSocketOptions.SO_PEERCRED);
            if (!peerTrusted(peer.user(), me, launchd)) {
                throw new SshException(SshException.Code.UNSAFE_SOCKET);
            }
        } catch (IOException | UnsupportedOperationException e) {
            throw new SshException(SshException.Code.UNSAFE_SOCKET);
        }
    }

    /** Whether a folder owned by {@code who} may hold the socket: {@code me} or root, by account name. */
    static boolean trusted(UserPrincipal who, UserPrincipal me) {
        String name = who.getName();
        return name.equals(me.getName()) || ROOT.equals(name);
    }

    /** Whether a peer running as {@code peer} may serve the socket: {@code me}, or root where allowed. */
    static boolean peerTrusted(UserPrincipal peer, UserPrincipal me, boolean rootAllowed) {
        String name = peer.getName();
        return name.equals(me.getName()) || (rootAllowed && ROOT.equals(name));
    }

    /**
     * Whether {@code real} is launchd's listener for {@code me}: a socket named {@code Listeners}
     * in a {@code com.apple.launchd.*} folder directly inside {@code run}, the folder owned by
     * {@code me} with mode {@code 0700} and nothing else, read without following links. Only
     * {@code me} and root can change such a folder (another user cannot add an ACL to it), and
     * {@code run} is writable only by root and the daemon group.
     */
    static boolean launchdListener(Path real, UserPrincipal me, Path run) {
        Path dir = real.getParent();
        if (dir == null || !run.equals(dir.getParent())
                || !LISTENERS.equals(Objects.requireNonNull(real.getFileName(), "name").toString())
                || !Objects.requireNonNull(dir.getFileName(), "folder").toString().startsWith(LAUNCHD_FOLDER)) {
            return false;
        }
        try {
            PosixFileAttributes d = Files.readAttributes(dir, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return d.isDirectory() && d.owner().equals(me) && d.permissions().equals(OWNER_ONLY);
        } catch (IOException | UnsupportedOperationException e) {
            return false;
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
