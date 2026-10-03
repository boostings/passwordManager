package pm.crypto.ssh;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Objects;
import java.util.Set;
import pm.crypto.SecretBytes;

/**
 * The explicit fallback for when no agent is available (plan.md §13 M4, ADR 0013, SR-063): writes
 * a key as an unencrypted OpenSSH private key file that {@code ssh -i} and {@code ssh-add} read.
 * This is the only path by which private key bytes leave pm-crypto, and only to a new file:
 * {@code CREATE_NEW} (an existing file or a dangling link is refused, never overwritten or
 * followed), {@code NOFOLLOW_LINKS}, and mode 0600 set atomically at creation (FIO01-J, FIO02-J).
 */
public final class SshKeyExport {
    private static final Set<OpenOption> CREATE =
            Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);

    /** How the encoded file reaches the open channel; replaced in tests to inject a failure. */
    @FunctionalInterface
    interface Sink {
        void write(FileChannel ch, byte[] text) throws IOException;
    }

    /** Writes through a zero-filled pm-owned direct buffer (no copy in the JDK's buffer cache), then syncs. */
    static final Sink DISK = (ch, text) -> {
        WireWriter.writeDirect(ch, text);
        ch.force(true);
    };

    private SshKeyExport() {
    }

    /**
     * Writes {@code key} to the new file {@code target} and syncs it to disk. If writing fails after
     * the file was created, the partial file is deleted (best effort).
     *
     * @throws SshException {@code TARGET_EXISTS} if anything (including a link) is already there,
     *     {@code UNSAFE_TARGET} if the file system cannot create a 0600 file, {@code IO} otherwise
     * @throws IllegalStateException if {@code key} is closed
     */
    public static void write(SshKey key, Path target) throws SshException {
        write(key, target, DISK);
    }

    /** {@link #write(SshKey, Path)} with the writing step given, so tests can make it fail. */
    static void write(SshKey key, Path target, Sink sink) throws SshException {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(target, "target");
        try (SecretBytes text = OpenSshFormat.encode(key)) {
            FileChannel ch = openNew(target);
            try (ch) {
                text.withBytes(b -> {
                    try {
                        sink.write(ch, b);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                });
            } catch (IOException | UncheckedIOException e) {
                deletePartial(target);
                throw new SshException(SshException.Code.IO);
            }
        }
    }

    private static FileChannel openNew(Path target) throws SshException {
        try {
            return FileChannel.open(target, CREATE,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (FileAlreadyExistsException e) {
            throw new SshException(SshException.Code.TARGET_EXISTS);
        } catch (UnsupportedOperationException e) {
            throw new SshException(SshException.Code.UNSAFE_TARGET);
        } catch (IOException e) {
            throw new SshException(SshException.Code.IO);
        }
    }

    /** Removes what this call created: the name was opened with CREATE_NEW, so the file is ours. */
    private static void deletePartial(Path target) {
        try {
            Files.deleteIfExists(target);
        } catch (IOException e) {
            // Best effort: the export already failed with IO, which is what the caller sees.
            Objects.requireNonNull(e);
        }
    }
}
