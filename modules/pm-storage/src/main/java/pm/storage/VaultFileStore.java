package pm.storage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Stores already encrypted vault bytes with exclusive locking and atomic replacement.
 * Implements ADR 0003, SR-040/041/501 and CERT FIO00/01/02/03/04/10/16-J.
 * Callers must close the store explicitly. Operations on a single instance are serialized;
 * this class does not encrypt data.
 *
 * <p>Directory policy (FIO00-J, FIO01-J). A missing parent directory is created owner-only, and
 * every file the store creates (vault, {@code .tmp}, {@code .bak.N}, {@code .lock}) is
 * owner-only before it holds a byte. A parent directory that already exists is never modified:
 * it must be a secure directory as defined by {@link OwnerOnly}, that is, writable only by its
 * owner and the operating system's administrators, otherwise the store refuses it with
 * {@code PERMISSIONS}. Ownership by the current user is enforced through the files: each store
 * file must be owned by the directory's owner (on Windows also by the current user when an
 * administrative account owns the directory), so a directory that belongs to somebody else
 * cannot be used. The directory and the files are checked again on every operation.
 *
 * <p>Path policy (FIO16-J). The parent is canonicalized, a vault, lock, staging or backup path
 * that is a symbolic link is refused, and an existing vault is addressed by the name stored on
 * disk so that alternate spellings of one file share one lock.
 */
public final class VaultFileStore implements AutoCloseable {
    /** Maximum accepted file size, as specified by ADR 0003. */
    public static final long MAX_FILE_BYTES = 256L * 1024 * 1024;
    private static final int BUFFER_BYTES = 8192;
    private static final int BACKUP_COUNT = 3;
    private static final String LOCK_SUFFIX = ".lock";
    private static final String TMP_SUFFIX = ".tmp";
    // Avoid opening a second channel: closing one can drop another channel's OS lock.
    private static final Set<Path> OPEN_PATHS = ConcurrentHashMap.newKeySet();
    private final Path file;
    private final Path directory;
    private final long byteLimit;
    private final FileChannel lockChannel;
    private final FileLock fileLock;
    private final ReentrantLock operationLock = new ReentrantLock();
    private final CrashHook crashHook;
    private boolean closed;

    enum Step { TMP_CREATED, TMP_WRITTEN, TMP_SYNCED, RENAMED, DIR_SYNCED }

    @FunctionalInterface
    interface CrashHook {
        void at(Step step) throws IOException;
    }

    @FunctionalInterface
    private interface Operation<T> {
        T run() throws IOException, StorageException;
    }

    private VaultFileStore(Path file, Path directory, long byteLimit, FileChannel channel,
            FileLock fileLock, CrashHook hook) {
        this.file = file;
        this.directory = directory;
        this.byteLimit = byteLimit;
        lockChannel = channel;
        this.fileLock = fileLock;
        crashHook = hook;
    }

    /**
     * Opens a store and exclusively locks its sibling lock file until close.
     * Missing directories are created owner-only. An existing directory is left untouched and
     * must be secure (FIO00-J): writable only by its owner and the system's administrators.
     *
     * @param vaultFile the vault path, which must not itself be a symbolic link
     * @return the open store (the vault need not exist yet)
     * @throws StorageException if the path, permissions, or exclusive lock is unsafe
     */
    public static VaultFileStore open(Path vaultFile) throws StorageException {
        return open(vaultFile, MAX_FILE_BYTES, step -> { /* Production checkpoint: no action. */ });
    }

    // Package-only limits and checkpoints allow small, deterministic failure tests.
    static VaultFileStore open(Path vaultFile, long limit, CrashHook hook)
            throws StorageException {
        Objects.requireNonNull(vaultFile, "PATH");
        Objects.requireNonNull(hook, "HOOK");
        if (limit < 1 || limit > MAX_FILE_BYTES) {
            throw new IllegalArgumentException("LIMIT");
        }
        try {
            Path absolute = vaultFile.toAbsolutePath();
            Path name = absolute.getFileName();
            Path requested = absolute.getParent();
            if (name == null || requested == null || !usableName(name.toString())) {
                throw new StorageException(StorageException.Code.IO, null);
            }
            Path parent = prepareDirectory(requested);
            Path canonical = canonicalFile(parent, name);
            checkRegularFile(canonical, true);
            if (!OPEN_PATHS.add(canonical)) {
                throw new StorageException(StorageException.Code.LOCKED_BY_OTHER, null);
            }
            boolean opened = false;
            try {
                VaultFileStore store = acquire(canonical, parent, limit, hook);
                opened = true;
                return store;
            } finally {
                if (!opened) {
                    boolean unused = OPEN_PATHS.remove(canonical);
                }
            }
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw translated(ex);
        }
    }

    private static VaultFileStore acquire(Path canonical, Path parent, long limit, CrashHook hook)
            throws IOException, StorageException {
        Path lockPath = sibling(canonical, LOCK_SUFFIX);
        boolean created = false;
        FileChannel channel;
        try {
            channel = FileChannel.open(lockPath,
                    Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                            LinkOption.NOFOLLOW_LINKS),
                    OwnerOnly.creationAttributes(parent, false));
            created = true;
        } catch (FileAlreadyExistsException ex) {
            checkRegularFile(lockPath, false);
            channel = FileChannel.open(lockPath, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        }
        boolean validated = false;
        try {
            if (created) {
                ensurePrivate(lockPath);
            }
            checkRegularFile(lockPath, false);
            validated = true;
            FileLock held = channel.tryLock();
            if (held == null) {
                throw new StorageException(StorageException.Code.LOCKED_BY_OTHER, null);
            }
            return new VaultFileStore(canonical, parent, limit, channel, held, hook);
        } catch (IOException | StorageException | OverlappingFileLockException | SecurityException ex) {
            try {
                channel.close();
                // A lock file this call created but could not validate is unusable by anyone;
                // leaving it would make every later open fail (FIO03-J).
                if (created && !validated) {
                    discard(lockPath);
                }
            } catch (IOException cleanupFailure) {
                ex.addSuppressed(cleanupFailure);
            }
            if (ex instanceof StorageException storage) {
                throw storage;
            }
            throw translated(ex);
        }
    }

    /**
     * Checks whether a safe vault file exists without treating inspection errors as absence.
     * @return whether a safe regular vault file currently exists
     * @throws IllegalStateException with a safe code if closed or inspection fails
     */
    public boolean exists() {
        try {
            return guarded(() -> checkRegularFile(file, true));
        } catch (StorageException ex) {
            throw new IllegalStateException(ex.code().name(), ex);
        }
    }

    /**
     * Reads a fresh byte array, checking both initial size and bytes actually read.
     * @return encrypted file contents owned by the caller
     * @throws StorageException if missing, unsafe, oversized, or unreadable
     */
    public byte[] readAll() throws StorageException {
        return guarded(() -> readFile(file));
    }

    private byte[] readFile(Path source) throws IOException, StorageException {
        checkRegularFile(source, false);
        if (Files.size(source) > byteLimit) {
            throw new StorageException(StorageException.Code.TOO_LARGE, null);
        }
        try (InputStream input = Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS)) {
            return readBounded(input, byteLimit);
        }
    }

    static byte[] readBounded(InputStream input, long limit) throws IOException, StorageException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[BUFFER_BYTES];
        long count = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (read == 0) {
                throw new StorageException(StorageException.Code.IO, null);
            }
            count += read;
            if (count > limit) {
                throw new StorageException(StorageException.Code.TOO_LARGE, null);
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    /**
     * Replaces the vault using a private sibling, a flushed write, and an atomic move.
     * An error after rename may mean the complete new version is already installed.
     *
     * @param data already encrypted bytes, copied before use (CERT OBJ06-J)
     * @throws StorageException if unsafe, oversized, or atomic replacement fails
     */
    public void writeAtomically(byte[] data) throws StorageException {
        Objects.requireNonNull(data, "DATA");
        guarded(() -> {
            if (data.length > byteLimit) {
                throw new StorageException(StorageException.Code.TOO_LARGE, null);
            }
            return writeFile(file, data.clone(), false);
        });
    }

    // Stages the complete new content in a private sibling, then installs it with one rename
    // and returns the path now holding it. When the target is the newest backup, older
    // generations move only after the staged copy is safely on disk, so a failed write cannot
    // cost a generation.
    private Path writeFile(Path target, byte[] data, boolean rotateFirst)
            throws IOException, StorageException {
        checkRegularFile(target, true);
        Path tmp = sibling(target, TMP_SUFFIX);
        if (checkPlainFile(tmp)) {
            Files.delete(tmp);
        }
        Path created = Files.createFile(tmp, OwnerOnly.creationAttributes(directory, false));
        try (TemporaryPath staging = new TemporaryPath(created)) {
            ensurePrivate(staging.path());
            checkRegularFile(staging.path(), false);
            try (FileChannel output = FileChannel.open(staging.path(),
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                crashHook.at(Step.TMP_CREATED);
                ByteBuffer bytes = ByteBuffer.wrap(data);
                while (bytes.hasRemaining()) {
                    if (output.write(bytes) <= 0) {
                        throw new StorageException(StorageException.Code.IO, null);
                    }
                }
                crashHook.at(Step.TMP_WRITTEN);
                output.force(true);
                crashHook.at(Step.TMP_SYNCED);
            }
            if (rotateFirst) {
                rotateBackups();
            }
            checkRegularFile(target, true);
            // No non-atomic fallback: unsupported filesystems fail closed.
            Files.move(staging.path(), target, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            crashHook.at(Step.RENAMED);
            syncDirectory();
            crashHook.at(Step.DIR_SYNCED);
        }
        return target;
    }

    /**
     * Preserves the current vault as .bak.1, retaining at most three backup generations.
     * Call before writeAtomically; this is a no-op before the first vault is created, and also
     * when .bak.1 already holds exactly the current vault (a save that failed after its backup
     * is being retried), so repeated calls cannot push older generations out.
     *
     * @throws StorageException if reading, validating, rotating, or writing backups fails
     */
    public void backup() throws StorageException {
        guarded(() -> {
            if (!checkRegularFile(file, true)) {
                return file;
            }
            byte[] contents = readFile(file);
            // Validate every generation before anything moves; the last one checked is .bak.1.
            boolean newestPresent = false;
            for (int index = BACKUP_COUNT; index >= 1; index--) {
                newestPresent = checkRegularFile(backupPath(index), true);
            }
            Path newest = backupPath(1);
            if (newestPresent && sameContents(newest, contents)) {
                return newest;
            }
            return writeFile(newest, contents, true);
        });
    }

    private boolean sameContents(Path path, byte[] contents) throws IOException, StorageException {
        if (Files.size(path) != contents.length) {
            return false;
        }
        byte[] previous = readFile(path);
        if (previous.length != contents.length) {
            return false;
        }
        // SR-016: every byte is visited, so the comparison does not stop at the first difference.
        int difference = 0;
        for (int index = 0; index < previous.length; index++) {
            difference |= previous[index] ^ contents[index];
        }
        return difference == 0;
    }

    private void rotateBackups() throws IOException, StorageException {
        for (int index = BACKUP_COUNT - 1; index >= 1; index--) {
            Path from = backupPath(index);
            if (checkRegularFile(from, true)) {
                Path moved = Files.move(from, backupPath(index + 1),
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                OwnerOnly.apply(moved);
            }
        }
    }

    private Path backupPath(int index) throws StorageException {
        return sibling(file, ".bak." + index);
    }

    /**
     * Releases the channel and its file lock; repeated calls are harmless.
     * The lock file remains in place so other processes always lock the same inode.
     * @throws IllegalStateException with code IO if resource release fails
     */
    @Override
    public void close() {
        final ReentrantLock lock = operationLock;
        lock.lock();
        try {
            if (!closed) {
                try {
                    lockChannel.close(); // Also invalidates and releases fileLock.
                } catch (IOException ex) {
                    throw new IllegalStateException("IO", translated(ex));
                } finally {
                    closed = true;
                    boolean unused = OPEN_PATHS.remove(file);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    private <T> T guarded(Operation<T> operation) throws StorageException {
        final ReentrantLock lock = operationLock;
        lock.lock();
        try {
            return checked(operation);
        } finally {
            lock.unlock();
        }
    }

    private <T> T checked(Operation<T> operation) throws StorageException {
        try {
            ensureOpen();
            checkDirectory();
            return operation.run();
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw translated(ex);
        }
    }

    private void ensureOpen() {
        if (closed || !lockChannel.isOpen() || !fileLock.isValid()) {
            throw new IllegalStateException("CLOSED");
        }
    }

    private void checkDirectory() throws IOException, StorageException {
        if (Files.isSymbolicLink(directory) || !directory.toRealPath().equals(directory)) {
            throw new StorageException(StorageException.Code.SYMLINK_REFUSED, null);
        }
        if (!OwnerOnly.isSecureDirectory(directory)) {
            throw new StorageException(StorageException.Code.PERMISSIONS, null);
        }
    }

    private static Path prepareDirectory(Path requested) throws IOException, StorageException {
        Deque<Path> missing = new ArrayDeque<>();
        Path existing = requested;
        while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            Path name = existing.getFileName();
            Path above = existing.getParent();
            if (name == null || above == null) {
                // The filesystem root itself is absent, for example an unplugged drive.
                throw new StorageException(StorageException.Code.NOT_FOUND, null);
            }
            missing.push(name);
            existing = above;
        }
        Path resolved = existing.toRealPath();
        while (!missing.isEmpty()) {
            Path next = resolved.resolve(missing.pop());
            try {
                Path created = Files.createDirectory(next, OwnerOnly.creationAttributes(resolved, true));
                // Clear any ACL inheritance added by the provider before creating children.
                OwnerOnly.apply(created);
            } catch (FileAlreadyExistsException ex) {
                if (Files.isSymbolicLink(next)) {
                    throw new StorageException(StorageException.Code.SYMLINK_REFUSED, ex);
                }
            }
            // The stored spelling can differ from the requested one (FIO16-J), for example a
            // trailing dot on Windows; later checks compare against the canonical path.
            resolved = next.toRealPath();
        }
        // Created directories are owner-only, which is also secure; one that already existed is
        // judged as found and never modified (FIO00-J).
        if (!Files.isDirectory(resolved, LinkOption.NOFOLLOW_LINKS)
                || !OwnerOnly.isSecureDirectory(resolved)) {
            throw new StorageException(StorageException.Code.PERMISSIONS, null);
        }
        return resolved;
    }

    // A name the filesystem may silently alter (Windows drops trailing dots and spaces) would
    // give one vault two spellings, and so two lock files; "." and ".." are not files at all.
    private static boolean usableName(String name) {
        return !name.isEmpty() && !name.endsWith(".") && !name.endsWith(" ");
    }

    // FIO16-J: an existing vault, or the lock of one not yet written, is addressed by the name
    // stored on disk, so case variants and Windows short names share one lock and registry key.
    private static Path canonicalFile(Path parent, Path name) throws IOException, StorageException {
        Path candidate = parent.resolve(name);
        if (Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) {
            return parent.resolve(nameOf(candidate.toRealPath(LinkOption.NOFOLLOW_LINKS)));
        }
        Path lock = sibling(candidate, LOCK_SUFFIX);
        if (Files.exists(lock, LinkOption.NOFOLLOW_LINKS)) {
            String stored = nameOf(lock.toRealPath(LinkOption.NOFOLLOW_LINKS)).toString();
            if (stored.endsWith(LOCK_SUFFIX)) {
                return parent.resolve(stored.substring(0, stored.length() - LOCK_SUFFIX.length()));
            }
        }
        return candidate;
    }

    // A regular, non-link store file that is owner-only and owned like its directory.
    private static boolean checkRegularFile(Path path, boolean allowMissing)
            throws IOException, StorageException {
        if (!checkPlainFile(path)) {
            if (allowMissing) {
                return false;
            }
            throw new StorageException(StorageException.Code.NOT_FOUND, null);
        }
        if (!OwnerOnly.isOwnerOnly(path) || !OwnerOnly.ownedLike(path, parentOf(path))) {
            throw new StorageException(StorageException.Code.PERMISSIONS, null);
        }
        return true;
    }

    // Whether a regular file exists at the path; a link or any other kind of entry is refused.
    private static boolean checkPlainFile(Path path) throws IOException, StorageException {
        try {
            BasicFileAttributes attributes = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isSymbolicLink()) {
                throw new StorageException(StorageException.Code.SYMLINK_REFUSED, null);
            }
            if (!attributes.isRegularFile()) {
                throw new StorageException(StorageException.Code.IO, null);
            }
            return true;
        } catch (NoSuchFileException absent) {
            return false;
        }
    }

    // The creation attributes name the directory's owner. If this process creates files under
    // another identity (an administrator-owned directory), restrict the file to its real owner
    // before anything is written to it (FIO01-J).
    private static void ensurePrivate(Path created) throws StorageException {
        if (!OwnerOnly.isOwnerOnly(created)) {
            OwnerOnly.apply(created);
        }
    }

    private void syncDirectory() {
        if (directory.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            try (FileChannel parent = FileChannel.open(directory, StandardOpenOption.READ)) {
                parent.force(true);
            } catch (IOException | UnsupportedOperationException ex) {
                // M1 explicitly permits unsupported directory fsync. The file itself was
                // flushed and atomically renamed; power-loss durability is provider-dependent.
                return;
            }
        }
    }

    private static Path sibling(Path path, String suffix) throws StorageException {
        return path.resolveSibling(nameOf(path).toString() + suffix);
    }

    private static Path nameOf(Path path) throws StorageException {
        Path name = path.getFileName();
        if (name == null) {
            throw new StorageException(StorageException.Code.IO, null);
        }
        return name;
    }

    private static Path parentOf(Path path) throws StorageException {
        Path parent = path.getParent();
        if (parent == null) {
            throw new StorageException(StorageException.Code.IO, null);
        }
        return parent;
    }

    private static void discard(Path path) throws IOException {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            Files.delete(path);
        }
    }

    private static StorageException translated(Throwable error) {
        StorageException.Code code = StorageException.Code.IO;
        if (error instanceof NoSuchFileException) {
            code = StorageException.Code.NOT_FOUND;
        } else if (error instanceof AccessDeniedException || error instanceof SecurityException) {
            code = StorageException.Code.PERMISSIONS;
        } else if (error instanceof OverlappingFileLockException) {
            code = StorageException.Code.LOCKED_BY_OTHER;
        }
        return new StorageException(code, error);
    }

    private record TemporaryPath(Path path) implements AutoCloseable {
        @Override
        public void close() throws IOException {
            discard(path);
        }
    }
}
