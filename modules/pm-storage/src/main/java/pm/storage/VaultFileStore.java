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
 * Callers must use a dedicated owner-only directory and close the store explicitly.
 * Operations on a single instance are serialized; this class does not encrypt data.
 */
public final class VaultFileStore implements AutoCloseable {
    /** Maximum accepted file size, as specified by ADR 0003. */
    public static final long MAX_FILE_BYTES = 256L * 1024 * 1024;
    private static final int BUFFER_BYTES = 8192;
    private static final int BACKUP_COUNT = 3;
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

    private VaultFileStore(Path file, long byteLimit, FileChannel channel,
            FileLock fileLock, CrashHook hook) {
        this.file = file;
        directory = parentOf(file);
        this.byteLimit = byteLimit;
        lockChannel = channel;
        this.fileLock = fileLock;
        crashHook = hook;
    }

    /**
     * Opens a store and exclusively locks its sibling lock file until close.
     * Missing directories are created owner-only; existing shared directories are rejected.
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
            Path requestedParent = absolute.getParent();
            if (name == null || requestedParent == null
                    || name.toString().equals(".") || name.toString().equals("..")) {
                throw new StorageException(StorageException.Code.IO, null);
            }
            Path parent = prepareDirectory(requestedParent);
            Path canonical = parent.resolve(name);
            checkRegularFile(canonical, true);
            if (!OPEN_PATHS.add(canonical)) {
                throw new StorageException(StorageException.Code.LOCKED_BY_OTHER, null);
            }
            boolean opened = false;
            try {
                VaultFileStore store = acquire(canonical, limit, hook);
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

    private static VaultFileStore acquire(Path canonical, long limit, CrashHook hook)
            throws IOException, StorageException {
        Path lockPath = sibling(canonical, ".lock");
        FileChannel channel;
        try {
            channel = FileChannel.open(lockPath,
                    Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                            LinkOption.NOFOLLOW_LINKS),
                    OwnerOnly.creationAttributes(parentOf(canonical), false));
        } catch (FileAlreadyExistsException ex) {
            checkRegularFile(lockPath, false);
            channel = FileChannel.open(lockPath, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        }
        try {
            checkRegularFile(lockPath, false);
            FileLock held = channel.tryLock();
            if (held == null) {
                throw new StorageException(StorageException.Code.LOCKED_BY_OTHER, null);
            }
            return new VaultFileStore(canonical, limit, channel, held, hook);
        } catch (IOException | StorageException | OverlappingFileLockException | SecurityException ex) {
            try {
                channel.close();
            } catch (IOException closeFailure) {
                ex.addSuppressed(closeFailure);
            }
            if (ex instanceof StorageException storage) {
                throw storage;
            }
            throw translated(ex);
        }
    }

    /**
     * Checks whether a safe vault file exists. I/O errors are not treated as absence, but a
     * path holding anything other than a safe regular file reports false: {@link #readAll},
     * {@link #backup} and {@link #writeAtomically} then refuse it with a {@link StorageException}.
     * @return whether a safe regular vault file currently exists
     * @throws IllegalStateException with a safe code if closed or inspection fails
     */
    public boolean exists() {
        try {
            return locked(() -> {
                checkDirectory();
                try {
                    return checkRegularFile(file, true);
                } catch (StorageException unsafe) {
                    // Something other than a safe regular file (a directory, link, or shared
                    // file) is not a vault. Every read and write re-checks and fails closed.
                    return false;
                }
            });
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
        return locked(() -> {
            checkDirectory();
            return readFile(file);
        });
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
        locked(() -> {
            if (data.length > byteLimit) {
                throw new StorageException(StorageException.Code.TOO_LARGE, null);
            }
            checkDirectory();
            writeFile(file, data.clone());
            return null;
        });
    }

    private void writeFile(Path target, byte[] data) throws IOException, StorageException {
        checkRegularFile(target, true);
        Path tmp = sibling(target, ".tmp");
        if (checkRegularFile(tmp, true)) {
            Files.delete(tmp);
        }
        Path created = Files.createFile(tmp, OwnerOnly.creationAttributes(directory, false));
        try (TemporaryPath staging = new TemporaryPath(created)) {
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
            checkRegularFile(target, true);
            // No non-atomic fallback: unsupported filesystems fail closed.
            Files.move(staging.path(), target, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            crashHook.at(Step.RENAMED);
            syncDirectory();
            crashHook.at(Step.DIR_SYNCED);
        }
    }

    /**
     * Preserves the current vault as .bak.1, retaining at most three backup generations.
     * Call before writeAtomically; this is a no-op before the first vault is created.
     *
     * @throws StorageException if reading, validating, rotating, or writing backups fails
     */
    public void backup() throws StorageException {
        locked(() -> {
            checkDirectory();
            if (!checkRegularFile(file, true)) {
                return null;
            }
            byte[] contents = readFile(file);
            for (int index = 1; index <= BACKUP_COUNT; index++) {
                checkRegularFile(backupPath(index), true);
            }
            checkRegularFile(sibling(backupPath(1), ".tmp"), true);
            for (int index = BACKUP_COUNT - 1; index >= 1; index--) {
                Path from = backupPath(index);
                if (checkRegularFile(from, true)) {
                    Path moved = Files.move(from, backupPath(index + 1),
                            StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                    OwnerOnly.apply(moved);
                }
            }
            writeFile(backupPath(1), contents);
            return null;
        });
    }

    /**
     * Runs {@code action} on an open store under {@link #operationLock}, translating I/O
     * failures to code-only {@link StorageException}s (SR-501). The only place the lock is
     * taken besides {@link #close} (LCK08-J).
     */
    private <T> T locked(StoreAction<T> action) throws StorageException {
        operationLock.lock();
        try {
            ensureOpen();
            return action.run();
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw translated(ex);
        } finally {
            operationLock.unlock();
        }
    }

    /** Body of a locked store operation. */
    @FunctionalInterface
    private interface StoreAction<T> {
        T run() throws IOException, StorageException;
    }

    private Path backupPath(int index) {
        return sibling(file, ".bak." + index);
    }

    /**
     * Releases the channel and its file lock; repeated calls are harmless.
     * The lock file remains in place so other processes always lock the same inode.
     * @throws IllegalStateException with code IO if resource release fails
     */
    @Override
    public void close() {
        operationLock.lock();
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
            operationLock.unlock();
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
        if (!OwnerOnly.isOwnerOnly(directory)) {
            throw new StorageException(StorageException.Code.PERMISSIONS, null);
        }
    }

    private static Path prepareDirectory(Path requested) throws IOException, StorageException {
        Deque<Path> missing = new ArrayDeque<>();
        Path existing = requested;
        while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            Path missingName = existing.getFileName();
            existing = existing.getParent();
            if (missingName == null || existing == null) {
                throw new StorageException(StorageException.Code.IO, null);
            }
            missing.push(missingName);
        }
        Path resolved = existing.toRealPath();
        while (!missing.isEmpty()) {
            Path next = resolved.resolve(missing.pop());
            try {
                resolved = Files.createDirectory(next, OwnerOnly.creationAttributes(resolved, true));
                // Clear any ACL inheritance added by the provider before creating children.
                OwnerOnly.apply(resolved);
            } catch (FileAlreadyExistsException ex) {
                if (Files.isSymbolicLink(next)) {
                    throw new StorageException(StorageException.Code.SYMLINK_REFUSED, ex);
                }
                resolved = next.toRealPath();
            }
            if (!OwnerOnly.isOwnerOnly(resolved)) {
                throw new StorageException(StorageException.Code.PERMISSIONS, null);
            }
        }
        if (!Files.isDirectory(resolved, LinkOption.NOFOLLOW_LINKS)
                || !OwnerOnly.isOwnerOnly(resolved)) {
            throw new StorageException(StorageException.Code.PERMISSIONS, null);
        }
        return resolved;
    }

    private static boolean checkRegularFile(Path path, boolean allowMissing)
            throws IOException, StorageException {
        try {
            BasicFileAttributes attributes = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isSymbolicLink()) {
                throw new StorageException(StorageException.Code.SYMLINK_REFUSED, null);
            }
            if (!attributes.isRegularFile()) {
                throw new StorageException(StorageException.Code.IO, null);
            }
            if (!OwnerOnly.isOwnerOnly(path)
                    || !Files.getOwner(path, LinkOption.NOFOLLOW_LINKS)
                            .equals(Files.getOwner(parentOf(path), LinkOption.NOFOLLOW_LINKS))) {
                throw new StorageException(StorageException.Code.PERMISSIONS, null);
            }
            return true;
        } catch (NoSuchFileException ex) {
            if (allowMissing) {
                return false;
            }
            throw ex;
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

    private static Path sibling(Path path, String suffix) {
        return path.resolveSibling(Objects.requireNonNull(path.getFileName(), "NAME") + suffix);
    }

    /** Parent of an absolute vault-related path; never null for paths built by {@link #open}. */
    private static Path parentOf(Path path) {
        return Objects.requireNonNull(path.getParent(), "PARENT");
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
            Files.deleteIfExists(path);
        }
    }
}
