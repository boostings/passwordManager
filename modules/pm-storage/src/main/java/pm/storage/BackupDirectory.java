package pm.storage;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A user-chosen directory of already encrypted backup files (ADR 0015, plan.md §18).
 *
 * <p>Same directory and file policy as {@link VaultFileStore} (FIO00/01/02/03/16-J): a missing
 * directory is created owner-only, an existing one is never modified and must be secure, every
 * file is owner-only before it holds a byte, links are refused, and a new file is staged in a
 * private {@code .tmp} sibling, flushed and installed by one atomic rename, so a reader never sees
 * a partial file. Files are only ever created new, never replaced. Names are restricted to
 * {@code [A-Za-z0-9][A-Za-z0-9._-]{0,127}} so they cannot leave the directory.
 *
 * <p>There is no lock. {@link #createNew} refuses a name that exists, but the check and the
 * rename are two steps, and {@code rename(2)} replaces a file created in between. This race is
 * accepted (ADR 0015): the directory is secure, so only the owner (or an administrator) can
 * create files in it, and the only realistic racer is a second backup of the same user picking
 * the same name in the same second; the loser's complete file replaces the winner's complete
 * file, and no reader ever sees a partial one. A hard link would close the race but is not
 * supported on the FAT and exFAT drives backups are often written to. This class does not
 * encrypt or authenticate anything.
 */
public final class BackupDirectory {
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final String TMP_SUFFIX = ".tmp";

    private final Path directory;
    private final VaultFileStore.CrashHook crashHook;

    private BackupDirectory(Path directory, VaultFileStore.CrashHook crashHook) {
        this.directory = directory;
        this.crashHook = crashHook;
    }

    /**
     * Opens a backup directory, creating it and any missing parents owner-only.
     *
     * @param dir the directory
     * @return the opened directory
     * @throws StorageException {@code PERMISSIONS} if an existing directory is not secure,
     *                          {@code SYMLINK_REFUSED} or {@code IO} for anything unsafe
     */
    public static BackupDirectory open(Path dir) throws StorageException {
        return open(dir, step -> { /* Production checkpoint: no action. */ });
    }

    // Package-only checkpoints allow deterministic crash tests.
    static BackupDirectory open(Path dir, VaultFileStore.CrashHook hook) throws StorageException {
        Objects.requireNonNull(dir, "DIR");
        Objects.requireNonNull(hook, "HOOK");
        try {
            return new BackupDirectory(VaultFileStore.prepareDirectory(dir.toAbsolutePath()), hook);
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw VaultFileStore.translated(ex);
        }
    }

    /**
     * Returns the canonical directory path.
     *
     * @return the directory
     */
    public Path path() {
        return directory;
    }

    /**
     * Creates {@code name} holding {@code data}: owner-only staging file, full write, fsync,
     * atomic rename, directory sync. A failure at any point leaves no file under {@code name}
     * and no staging file.
     *
     * @param name a file name matching {@code [A-Za-z0-9][A-Za-z0-9._-]{0,127}}, not ending in
     *             {@code .tmp}
     * @param data bytes to store, copied before use (OBJ06-J)
     * @throws StorageException {@code IO} if the name exists,
     *                          {@code TOO_LARGE} beyond {@link VaultFileStore#MAX_FILE_BYTES}
     *                          plus one mebibyte, otherwise as the failure
     */
    public void createNew(String name, byte[] data) throws StorageException {
        Path target = resolve(name);
        byte[] copy = Objects.requireNonNull(data, "DATA").clone();
        if (copy.length > maxBytes()) {
            throw new StorageException(StorageException.Code.TOO_LARGE, null);
        }
        checked(() -> {
            if (VaultFileStore.checkPlainFile(target)) {
                throw new StorageException(StorageException.Code.IO, null);
            }
            Path tmp = directory.resolve(name + TMP_SUFFIX);
            if (VaultFileStore.checkPlainFile(tmp)) {
                Files.delete(tmp);
            }
            Path created = Files.createFile(tmp, OwnerOnly.creationAttributes(directory, false));
            boolean installed = false;
            try {
                VaultFileStore.ensurePrivate(created);
                VaultFileStore.checkRegularFile(created, false);
                try (FileChannel out = FileChannel.open(created, StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS)) {
                    crashHook.at(VaultFileStore.Step.TMP_CREATED);
                    ByteBuffer bytes = ByteBuffer.wrap(copy);
                    while (bytes.hasRemaining()) {
                        if (out.write(bytes) <= 0) {
                            throw new StorageException(StorageException.Code.IO, null);
                        }
                    }
                    crashHook.at(VaultFileStore.Step.TMP_WRITTEN);
                    out.force(true);
                    crashHook.at(VaultFileStore.Step.TMP_SYNCED);
                }
                if (VaultFileStore.checkPlainFile(target)) {
                    throw new StorageException(StorageException.Code.IO, null);
                }
                Files.move(created, target, StandardCopyOption.ATOMIC_MOVE);
                installed = true;
                crashHook.at(VaultFileStore.Step.RENAMED);
                syncDirectory();
                crashHook.at(VaultFileStore.Step.DIR_SYNCED);
            } finally {
                if (!installed) {
                    VaultFileStore.discard(created);
                }
            }
            return null;
        });
    }

    /**
     * The entries whose names match a prefix and suffix, split by whether this class would read
     * or delete them.
     *
     * @param usable  owner-only regular files owned like the directory, sorted by name
     * @param refused matching entries that are links, not regular files, or not owner-only,
     *                sorted by name; they are never read or deleted
     */
    public record Listing(List<String> usable, List<String> refused) {
        /** Copies both lists. */
        public Listing {
            usable = List.copyOf(usable);
            refused = List.copyOf(refused);
        }
    }

    /**
     * Lists the owner-only regular files whose names start with {@code prefix} and end with
     * {@code suffix}, sorted by name. Shorthand for {@code scan(prefix, suffix).usable()}.
     *
     * @param prefix required name prefix
     * @param suffix required name suffix
     * @return the matching names
     * @throws StorageException if the directory cannot be read
     */
    public List<String> list(String prefix, String suffix) throws StorageException {
        return scan(prefix, suffix).usable();
    }

    /**
     * Lists the entries whose names start with {@code prefix}, end with {@code suffix} and match
     * the name pattern, applying the same checks as {@link #read} and {@link #delete}: owner-only
     * regular files are usable; links, directories and files with other permissions or owners
     * are refused.
     *
     * @param prefix required name prefix
     * @param suffix required name suffix
     * @return usable and refused names
     * @throws StorageException if the directory cannot be read
     */
    public Listing scan(String prefix, String suffix) throws StorageException {
        Objects.requireNonNull(prefix, "PREFIX");
        Objects.requireNonNull(suffix, "SUFFIX");
        return checked(() -> {
            List<String> usable = new ArrayList<>();
            List<String> refused = new ArrayList<>();
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                for (Path entry : entries) {
                    String name = String.valueOf(entry.getFileName());
                    if (name.startsWith(prefix) && name.endsWith(suffix) && NAME.matcher(name).matches()) {
                        (isUsable(entry) ? usable : refused).add(name);
                    }
                }
            }
            Collections.sort(usable);
            Collections.sort(refused);
            return new Listing(usable, refused);
        });
    }

    private static boolean isUsable(Path entry) throws IOException {
        try {
            return VaultFileStore.checkRegularFile(entry, false);
        } catch (StorageException refused) {
            return false;
        }
    }

    /**
     * Reads {@code name}, which must be an owner-only regular file within the size bound.
     *
     * @param name file name, as for {@link #createNew}
     * @return the bytes, owned by the caller
     * @throws StorageException {@code NOT_FOUND}, {@code PERMISSIONS}, {@code TOO_LARGE} or
     *                          {@code IO}
     */
    public byte[] read(String name) throws StorageException {
        Path target = resolve(name);
        return checked(() -> {
            VaultFileStore.checkRegularFile(target, false);
            return readFile(target);
        });
    }

    /**
     * Deletes {@code name} if it exists. A link or a file that is not owner-only is refused.
     *
     * @param name file name, as for {@link #createNew}
     * @return whether a file was deleted
     * @throws StorageException if the file is unsafe or cannot be deleted
     */
    public boolean delete(String name) throws StorageException {
        Path target = resolve(name);
        return checked(() -> {
            if (!VaultFileStore.checkRegularFile(target, true)) {
                return false;
            }
            Files.delete(target);
            syncDirectory();
            return true;
        });
    }

    /**
     * Reads a single file anywhere, for example a backup the user names on the command line. The
     * file must be a regular file, not a link, within the size bound; its permissions are not
     * checked, because a copied backup may have arrived with other permissions and its content is
     * authenticated by the caller.
     *
     * @param file the file
     * @return the bytes, owned by the caller
     * @throws StorageException {@code NOT_FOUND}, {@code SYMLINK_REFUSED}, {@code TOO_LARGE} or
     *                          {@code IO}
     */
    public static byte[] readFile(Path file) throws StorageException {
        Objects.requireNonNull(file, "PATH");
        try {
            if (!VaultFileStore.checkPlainFile(file)) {
                throw new StorageException(StorageException.Code.NOT_FOUND, null);
            }
            if (Files.size(file) > maxBytes()) {
                throw new StorageException(StorageException.Code.TOO_LARGE, null);
            }
            try (InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
                return VaultFileStore.readBounded(input, maxBytes());
            }
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw VaultFileStore.translated(ex);
        }
    }

    /**
     * Largest accepted backup file: a maximal vault plus room for the backup's own framing.
     *
     * @return the limit in bytes
     */
    public static long maxBytes() {
        return VaultFileStore.MAX_FILE_BYTES + 1024L * 1024;
    }

    private Path resolve(String name) {
        Objects.requireNonNull(name, "NAME");
        if (!NAME.matcher(name).matches() || name.endsWith(TMP_SUFFIX)) {
            throw new IllegalArgumentException("NAME");
        }
        return directory.resolve(name);
    }

    private <T> T checked(Operation<T> operation) throws StorageException {
        try {
            if (Files.isSymbolicLink(directory) || !directory.toRealPath().equals(directory)) {
                throw new StorageException(StorageException.Code.SYMLINK_REFUSED, null);
            }
            if (!OwnerOnly.isSecureDirectory(directory)) {
                throw new StorageException(StorageException.Code.PERMISSIONS, null);
            }
            return operation.run();
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw VaultFileStore.translated(ex);
        }
    }

    private void syncDirectory() {
        if (directory.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            try (FileChannel parent = FileChannel.open(directory, StandardOpenOption.READ)) {
                parent.force(true);
            } catch (IOException | UnsupportedOperationException ex) {
                // As in VaultFileStore: directory fsync is best effort where unsupported.
                return;
            }
        }
    }

    @FunctionalInterface
    private interface Operation<T> {
        T run() throws IOException, StorageException;
    }
}
