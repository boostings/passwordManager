package pm.tui.lan;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import pm.approval.ipc.IpcException;
import pm.approval.ipc.RunDir;
import pm.crypto.Csprng;
import pm.sharing.pair.Lockout;

/**
 * LAN sharing state that every pm process of the user must see (lan-share.md §5 step 6, §8.1). It
 * holds no secret and nothing a peer could use:
 *
 * <ul>
 *   <li>a <em>removed-device marker</em> per device taken off the trust list, named by its public
 *       key, in an owner-only directory next to the vault file ({@value #VAULT_SUFFIX} after the
 *       vault's real file name, links resolved). Its place depends only on the vault file, never on
 *       the environment, so the remover and every sender of that vault agree on it however each
 *       was started (SR-205). A share window asks {@link #isRemoved} when the device connects and
 *       again just before the data is released. Pairing the same key again clears the marker.
 *   <li>the <em>pairing lockout</em> (SR-203) in the user's run directory ({@code RunDir}), shared
 *       by every pairing of the user, whatever the vault. Every update is a read-merge-write under
 *       an exclusive lock: failure counts and lock ends are merged by maximum, so a pairing that
 *       started earlier never writes back a weaker state, and a success clears the count only if
 *       no other process changed it since this pairing read it. A lock more than one hour ahead is cut to one hour
 *       (clock-safe); a file that cannot be read or is not owner-only counts as locked for the
 *       full hour (fail closed).
 * </ul>
 *
 * Without a vault file (tests, or a TUI started with no approval host) the same state lives in
 * memory for the one process.
 */
public final class LanState {
    /** File-name prefix of a removed-device marker; the rest is the key as 64 lowercase hex. */
    public static final String REMOVED_PREFIX = "removed-";
    /** The pairing lockout file in the run directory. */
    public static final String LOCKOUT_FILE = "pair-lockout";
    /** Appended to the vault's file name to name its removed-device directory. */
    public static final String VAULT_SUFFIX = ".lan";
    private static final String LOCK_SUFFIX = ".lock";
    private static final Pattern LOCKOUT_LINE = Pattern.compile("1 (0|[1-9][0-9]{0,8}) (0|[1-9][0-9]{0,11})\n");
    private static final int MAX_LOCKOUT_BYTES = 64;
    private static final Set<PosixFilePermission> OWNER_RW =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final List<FileAttribute<?>> OWNER_ONLY =
            List.of(PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    /** File locks are per process, so threads of one JVM (and tests) queue here first. */
    private static final ReentrantLock IN_PROCESS = new ReentrantLock();

    private final Optional<Path> removedDir;
    private final Optional<Path> lockoutDir;
    /** In-memory form only: the removed keys and the one lockout of this process. */
    private final Set<String> removedKeys = ConcurrentHashMap.newKeySet();
    private final Lockout processLockout = new Lockout();
    /** The stored lockout as last read or written here, to tell another process's change apart. */
    private final AtomicReference<Saved> seen = new AtomicReference<>(Saved.NONE);
    /** Whether another process changed the stored lockout since this one last read it. */
    private final AtomicBoolean foreign = new AtomicBoolean();

    private LanState(Optional<Path> removedDir, Optional<Path> lockoutDir) {
        this.removedDir = removedDir;
        this.lockoutDir = lockoutDir;
    }

    /**
     * The state of the vault in {@code vaultFile}: removal markers next to its real path, created
     * owner-only (mode 0700) if needed, and the lockout in {@code runDir}, which the caller has
     * prepared.
     *
     * @throws IOException the vault file cannot be resolved, or the directory is a link, not a
     *     directory, or not owner-only
     */
    public static LanState forVault(Path vaultFile, Path runDir) throws IOException {
        Objects.requireNonNull(runDir, "runDir");
        Path real = vaultFile.toRealPath();
        Path parent = Objects.requireNonNull(real.getParent(), "vault dir");
        Path dir = parent.resolve(real.getFileName() + VAULT_SUFFIX);
        try {
            RunDir.prepare(dir);
        } catch (IpcException e) {
            throw new IOException("unsafe LAN state directory", e);
        }
        return new LanState(Optional.of(dir), Optional.of(runDir));
    }

    /** State for this process only. */
    public static LanState memory() {
        return new LanState(Optional.empty(), Optional.empty());
    }

    /**
     * Marks the device with public key {@code key} as removed. Call it before the vault forgets the
     * device: once this returns, no window of this vault, in any process, releases data to it.
     *
     * @throws IOException the marker could not be written; the caller must not report the device as
     *     cut off
     */
    public void removed(byte[] key) throws IOException {
        String name = hex(key);
        if (removedDir.isEmpty()) {
            removedKeys.add(name);
            return;
        }
        try {
            Files.createFile(removedDir.get().resolve(REMOVED_PREFIX + name), attributes(removedDir.get()));
        } catch (FileAlreadyExistsException e) {
            // already marked
            Objects.requireNonNull(e);
        }
    }

    /**
     * The device with {@code key} is trusted again (paired, or its removal was undone). A marker
     * that cannot be deleted keeps the device's windows closed, which is the safe side.
     */
    public void pinned(byte[] key) {
        String name = hex(key);
        if (removedDir.isEmpty()) {
            removedKeys.remove(name);
            return;
        }
        try {
            Files.deleteIfExists(removedDir.get().resolve(REMOVED_PREFIX + name));
        } catch (IOException e) {
            // see above: the device simply stays cut off from windows opened before
            Objects.requireNonNull(e);
        }
    }

    /** Whether the device with {@code key} was removed; a marker whose presence is unknown counts. */
    public boolean isRemoved(byte[] key) {
        String name = hex(key);
        return removedDir.map(d -> !Files.notExists(d.resolve(REMOVED_PREFIX + name), LinkOption.NOFOLLOW_LINKS))
                .orElseGet(() -> removedKeys.contains(name));
    }

    /** {@link #isRemoved} negated, for a share window's checks. */
    public Predicate<byte[]> stillTrusted() {
        return key -> !isRemoved(key);
    }

    /**
     * The pairing lockout as of {@code now}. In memory it is one instance for the process; on disk
     * a new instance restored from the stored state. Hand it to {@link #save} after a failure and
     * when the pairing ends.
     */
    public Lockout lockout(Instant now) {
        Objects.requireNonNull(now, "now");
        if (lockoutDir.isEmpty()) {
            return processLockout;
        }
        Saved stored = locked(lockoutDir.get(), () -> read(lockoutDir.get(), now))
                .orElseGet(() -> Saved.tampered(now));
        seen.set(stored);
        foreign.set(false);
        return Lockout.restore(stored.failures(), stored.lockedUntil(), now);
    }

    /**
     * Merges {@code lockout} into the stored state for the next pairing in any process: the larger
     * failure count and the later lock end win. A count that went down here (a success) is written
     * only if no other process changed the stored state since this process's {@link #lockout}
     * call; otherwise the other process's failures stay.
     *
     * @return false if it could not be written; the lock still holds in this process
     */
    public boolean save(Lockout lockout, Instant now) {
        Objects.requireNonNull(lockout, "lockout");
        Objects.requireNonNull(now, "now");
        if (lockoutDir.isEmpty()) {
            return true;
        }
        Path dir = lockoutDir.get();
        Saved mine = new Saved(lockout.failures(), lockout.lockedUntil());
        return locked(dir, () -> {
            Saved stored = read(dir, now).orElseGet(() -> Saved.tampered(now));
            if (!stored.equals(seen.get())) {
                foreign.set(true);
            }
            boolean success = mine.failures() < seen.get().failures();
            Saved next = success && !foreign.get() ? mine : stored.max(mine);
            boolean written = write(dir, next);
            if (written) {
                seen.set(next);
            }
            return Optional.of(written);
        }).orElse(false);
    }

    /** A stored lockout state; {@link #NONE} is an absent file. */
    private record Saved(int failures, Instant lockedUntil) {
        static final Saved NONE = new Saved(0, Instant.EPOCH);

        /** Whole seconds, as stored, so a state read back equals the one written. */
        Saved {
            lockedUntil = Instant.ofEpochSecond(Math.max(0, lockedUntil.getEpochSecond()));
        }

        static Saved tampered(Instant now) {
            return new Saved(Lockout.FREE_FAILURES + 1, now.plus(Lockout.CAP));
        }

        Saved max(Saved other) {
            return new Saved(Math.max(failures, other.failures),
                    lockedUntil.isAfter(other.lockedUntil) ? lockedUntil : other.lockedUntil);
        }
    }

    /**
     * Runs {@code body} holding the exclusive lock on the lockout's lock file.
     *
     * @return what {@code body} returned, or empty if the lock could not be taken
     */
    private static <T> Optional<T> locked(Path dir, Supplier<Optional<T>> body) {
        IN_PROCESS.lock();
        try (FileChannel channel = FileChannel.open(dir.resolve(LOCKOUT_FILE + LOCK_SUFFIX), Set.of(
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS), attributes(dir));
                FileLock held = channel.lock()) {
            Objects.requireNonNull(held);
            return body.get();
        } catch (IOException e) {
            return Optional.empty();
        } finally {
            IN_PROCESS.unlock();
        }
    }

    /**
     * The stored state: {@link Saved#NONE} if there is no file, empty if the file is not a plain
     * owner-only file of this user or does not parse (the caller then locks).
     */
    private static Optional<Saved> read(Path dir, Instant now) {
        Path file = dir.resolve(LOCKOUT_FILE);
        try {
            if (Files.notExists(file, LinkOption.NOFOLLOW_LINKS)) {
                return Optional.of(Saved.NONE);
            }
            if (!ownerOnlyRegularFile(dir, file) || Files.size(file) > MAX_LOCKOUT_BYTES) {
                return Optional.empty();
            }
            Matcher m = LOCKOUT_LINE.matcher(Files.readString(file, StandardCharsets.US_ASCII));
            if (!m.matches()) {
                return Optional.empty();
            }
            Lockout capped = Lockout.restore(Integer.parseInt(m.group(1)),
                    Instant.ofEpochSecond(Long.parseLong(m.group(2))), now);
            return Optional.of(new Saved(capped.failures(), capped.lockedUntil()));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private static boolean ownerOnlyRegularFile(Path dir, Path file) throws IOException {
        if (!dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS);
        }
        PosixFileAttributes a = Files.readAttributes(file, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return a.isRegularFile() && OWNER_RW.containsAll(a.permissions())
                && a.owner().equals(Files.getOwner(dir, LinkOption.NOFOLLOW_LINKS));
    }

    private static boolean write(Path dir, Saved state) {
        long until = Math.max(0, state.lockedUntil().getEpochSecond());
        byte[] line = ("1 " + state.failures() + " " + until + "\n").getBytes(StandardCharsets.US_ASCII);
        Path temp = dir.resolve(LOCKOUT_FILE + "." + HexFormat.of().formatHex(Csprng.bytes(8)));
        try {
            Files.write(Files.createFile(temp, attributes(dir)), line);
            Files.move(temp, dir.resolve(LOCKOUT_FILE), StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException e) {
            deleteQuietly(temp);
            return false;
        }
    }

    private static void deleteQuietly(Path temp) {
        try {
            Files.deleteIfExists(temp);
        } catch (IOException e) {
            // a stray temporary file in the owner-only directory holds only a count and a time
            Objects.requireNonNull(e);
        }
    }

    private static FileAttribute<?>[] attributes(Path dir) {
        boolean posix = dir.getFileSystem().supportedFileAttributeViews().contains("posix");
        return posix ? OWNER_ONLY.toArray(FileAttribute<?>[]::new) : new FileAttribute<?>[0];
    }

    private static String hex(byte[] key) {
        return HexFormat.of().formatHex(Objects.requireNonNull(key, "key"));
    }
}
