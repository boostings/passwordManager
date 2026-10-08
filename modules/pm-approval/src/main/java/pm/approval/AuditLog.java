package pm.approval;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;
import pm.crypto.ConstantTime;
import pm.crypto.Hash;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * The append-only, hash-chained audit log (approval-model.md §7). One deterministic-CBOR entry per
 * line, base64-encoded; entry {@code n} carries {@code seq = n} and {@code prev}, the SHA-256 of the
 * encoded entry {@code n - 1} (32 zero bytes for the first). The whole chain is verified on open.
 *
 * <p>A chain alone cannot notice entries cut from the end, so a sidecar {@code <log>.head} records
 * the last sequence number and its hash after every append. The head may lag the log by one entry
 * after a crash, never lead it. Both files are 0600. This detects accidents and naive edits; a
 * process running as the same user can rewrite both files, which the threat model accepts (T-12).
 *
 * <p>Writers in different processes share one log (SR-150): each holds an exclusive lock on the log
 * from reading the chain to updating the head, and readers hold a shared lock. On POSIX systems the
 * lock is a record lock that belongs to the process and is dropped when the process closes any
 * descriptor of the file, so the log is read and written only through the one locked channel, and
 * one lock per JVM keeps other threads from opening any log meanwhile. Locks are polled, never
 * awaited without end: a caller that cannot get them within {@link #LOCK_WAIT} gets {@code BUSY}.
 *
 * <p>An append is all or nothing: if the entry, its flush or the head update fails, the log is cut
 * back to its length before the append, still under the lock, so a refused operation leaves no
 * entry. Only if that cut fails too does the entry stay, with the head one behind; the next append
 * first brings such a head up to date, so it never falls further behind.
 */
public final class AuditLog implements AuditSink, AutoCloseable {
    /** A log larger than this is refused on open; the user archives it. */
    public static final long MAX_FILE_BYTES = 64L * 1024 * 1024;
    private static final int MAX_LINE_BYTES = 8 * 1024;
    private static final CborLimits LIMITS = new CborLimits(4, 64, 1024, MAX_LINE_BYTES);
    private static final byte NEWLINE = '\n';
    /** Conventional file name, in the vault directory (approval-model §7). */
    public static final String FILE_NAME = "audit.log";
    /** How long a caller waits for other users of a log before giving up with {@code BUSY}. */
    public static final Duration LOCK_WAIT = Duration.ofSeconds(10);
    private static final long FIRST_PAUSE_NANOS = TimeUnit.MILLISECONDS.toNanos(1);
    private static final long LONGEST_PAUSE_NANOS = TimeUnit.MILLISECONDS.toNanos(50);
    /**
     * Serializes every use of a log within this JVM: closing a second descriptor of a locked log
     * would release the file lock, so no thread opens a log while another holds its lock. The file
     * lock serializes processes.
     */
    private static final ReentrantLock FILE_USERS = new ReentrantLock();
    private static final Set<OpenOption> NEW_LOG = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
            StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
    private static final Set<OpenOption> NEW_HEAD = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
            StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS);
    private static final Set<String> KINDS = Set.of("unlock", "lock", "approval", "prompt", "policy", "share",
            "pair", "revoke", "export", "slot");

    private final Path file;
    private final Clock clock;
    private final AtomicLong seq;

    private AuditLog(Path file, Clock clock, long seq) {
        this.file = file;
        this.clock = clock;
        this.seq = new AtomicLong(seq);
    }

    /**
     * Opens {@code file}, creating it 0600 if absent, after verifying the whole chain.
     *
     * @throws AuditException {@code TAMPERED} or {@code TRUNCATED} with the last intact entry (a
     *     head whose log is gone is {@code TRUNCATED}, and no log is created),
     *     {@code UNSAFE_FILE}, {@code TOO_LARGE}, {@code BUSY} or {@code IO}
     */
    public static AuditLog open(Path file, Clock clock) throws AuditException {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(clock, "clock");
        return new AuditLog(file, clock, withWriteLock(file, LOCK_WAIT, (channel, state) -> state.entries()));
    }

    /**
     * Verifies the chain and appends one event while holding an exclusive lock on the file, so the
     * TUI's broker and CLI commands in other processes can share one log without forking the chain:
     * every writer re-reads the tail through the locked channel, and the lock is held from that read
     * to the head update. Within this JVM appends are serialized too.
     *
     * @throws AuditException as for {@link #open}, or {@code IO} if the entry cannot be written; the
     *     log is then as it was before the call
     */
    public static void append(Path file, Clock clock, AuditEvent event) throws AuditException {
        append(file, clock, event, LOCK_WAIT, AuditLog::writeHead);
    }

    /** As {@link #append(Path, Clock, AuditEvent)}, waiting at most {@code wait}, the head written by {@code head}. */
    static void append(Path file, Clock clock, AuditEvent event, Duration wait, HeadWriter head) throws AuditException {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(clock, "clock");
        checkKind(Objects.requireNonNull(event, "event"));
        appendLocked(file, clock, event, wait, head);
    }

    /**
     * Verifies {@code file} without writing it, under a shared lock, so an append in progress in
     * another process is never mistaken for a cut line.
     *
     * @return the number of entries
     * @throws AuditException as for {@link #open}
     */
    public static long check(Path file) throws AuditException {
        return check(file, LOCK_WAIT);
    }

    /** As {@link #check(Path)}, waiting at most {@code wait} for other users of the log. */
    static long check(Path file, Duration wait) throws AuditException {
        Objects.requireNonNull(file, "file");
        return inThisJvm(wait, deadline -> {
            refuseLostLog(file);
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                return 0L;
            }
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
                    FileLock shared = lock(channel, true, deadline)) {
                Objects.requireNonNull(shared); // held until the try block ends
                return verify(file, channel).entries();
            }
        });
    }

    /** Number of entries after this instance's last open or append. */
    public long entries() {
        return seq.get();
    }

    /**
     * Appends {@code event} as {@link #append} does, flushed to disk before returning, so a decision
     * is never acted on without its record. The tail is re-read on every append, so other writers
     * since {@link #open} are continued, never forked.
     *
     * @throws IllegalStateException {@code AUDIT_WRITE} if the entry cannot be written: the broker
     *     then fails the request closed
     */
    @Override
    public void record(AuditEvent event) {
        Objects.requireNonNull(event, "event");
        checkKind(event);
        long n;
        try {
            n = appendLocked(file, clock, event, LOCK_WAIT, AuditLog::writeHead);
        } catch (AuditException e) {
            throw new IllegalStateException("AUDIT_WRITE", e);
        }
        seq.accumulateAndGet(n, Math::max); // appends by two threads may return out of order
    }

    private static void checkKind(AuditEvent event) {
        if (!KINDS.contains(event.kind())) {
            throw new IllegalArgumentException("BAD_KIND");
        }
    }

    /**
     * Appends one entry under the exclusive lock and returns its sequence number. A head left one
     * behind is brought up to date first; if that fails, nothing is written. If the entry or its
     * head cannot be written, the log is cut back to its verified length before the lock goes.
     */
    private static long appendLocked(Path file, Clock clock, AuditEvent event, Duration wait, HeadWriter head)
            throws AuditException {
        return withWriteLock(file, wait, (channel, state) -> {
            if (state.headLags()) {
                head.write(headOf(file), state.entries(), state.lastHash());
            }
            long n = state.entries() + 1;
            byte[] entry = encode(event, n, clock.instant().getEpochSecond(), state.lastHash());
            ByteBuffer line = ByteBuffer.wrap((Base64.getEncoder().encodeToString(entry) + "\n")
                    .getBytes(StandardCharsets.US_ASCII));
            long at = state.bytes(); // right after the verified bytes: the end of the file while locked
            try {
                while (line.hasRemaining()) {
                    at += channel.write(line, at);
                }
                channel.force(true);
                head.write(headOf(file), n, Hash.sha256(entry));
            } catch (IOException e) {
                rollBack(channel, state.bytes(), e);
                throw e;
            }
            return n;
        });
    }

    /**
     * Cuts the log back to {@code length} after a failed append, so the refused operation leaves no
     * entry. If the cut fails too, its failure is kept with {@code failure}: the entry then stays
     * with the head one behind, which the next open accepts and the next append repairs.
     */
    private static void rollBack(FileChannel channel, long length, IOException failure) {
        try {
            channel.truncate(length);
            channel.force(true);
        } catch (IOException e) {
            failure.addSuppressed(e);
        }
    }

    /**
     * Nothing stays open between appends: each one opens, locks and closes the log. Kept so callers
     * can scope a log with try-with-resources.
     */
    @Override
    public void close() {
        // every entry was forced to disk, and its channel closed, before record returned
    }

    /** The log's path. */
    public Path path() {
        return file;
    }

    /**
     * Opens {@code file} (creating it 0600 if absent and no head is left), takes the exclusive lock,
     * verifies the chain through the locked channel and runs {@code step} before the lock is released.
     */
    private static <T> T withWriteLock(Path file, Duration wait, LockedStep<T> step) throws AuditException {
        return inThisJvm(wait, deadline -> {
            refuseLostLog(file);
            try (FileChannel channel = openLog(file); FileLock exclusive = lock(channel, false, deadline)) {
                Objects.requireNonNull(exclusive); // held until the try block ends
                return step.run(channel, verify(file, channel));
            }
        });
    }

    /**
     * Runs {@code step} while no other thread of this JVM uses a log; I/O errors become {@code IO}.
     * Both this and the file lock are polled until {@code wait} has passed, then {@code BUSY}.
     */
    private static <T> T inThisJvm(Duration wait, FileStep<T> step) throws AuditException {
        long deadline = System.nanoTime() + wait.toNanos();
        long pause = FIRST_PAUSE_NANOS;
        while (!FILE_USERS.tryLock()) {
            pause = pause(deadline, pause);
        }
        try {
            return step.run(deadline);
        } catch (IOException e) {
            throw new AuditException(AuditException.Code.IO, 0, e);
        } finally {
            FILE_USERS.unlock();
        }
    }

    /** Takes the file lock on {@code channel}, polling until {@code deadline} ({@link System#nanoTime}). */
    private static FileLock lock(FileChannel channel, boolean shared, long deadline)
            throws IOException, AuditException {
        for (long pause = FIRST_PAUSE_NANOS;; pause = pause(deadline, pause)) {
            FileLock held = tryLock(channel, shared);
            if (held != null) {
                return held;
            }
        }
    }

    /** The lock, or null while another process holds a conflicting one. */
    private static FileLock tryLock(FileChannel channel, boolean shared) throws IOException {
        try {
            return channel.tryLock(0L, Long.MAX_VALUE, shared);
        } catch (OverlappingFileLockException e) {
            return null; // held through another channel of this JVM, by code outside this class
        }
    }

    /**
     * Waits before the next attempt and returns the pause after that one, doubling up to 50 ms;
     * {@code BUSY} once {@code deadline} has passed. An interrupt ends the wait early, and the next
     * file operation then fails with {@code IO}.
     */
    private static long pause(long deadline, long pause) throws AuditException {
        long left = deadline - System.nanoTime();
        if (left <= 0) {
            throw new AuditException(AuditException.Code.BUSY, 0, null);
        }
        LockSupport.parkNanos(Math.min(pause, left));
        return Math.min(2 * pause, LONGEST_PAUSE_NANOS);
    }

    /** A step on the locked log after its chain was verified. */
    @FunctionalInterface
    private interface LockedStep<T> {
        T run(FileChannel channel, Verified state) throws IOException;
    }

    /** A step that may fail verification or I/O, given the deadline for taking the file lock. */
    @FunctionalInterface
    private interface FileStep<T> {
        T run(long deadline) throws IOException, AuditException;
    }

    /** Writes the head for entry {@code n}; replaced in tests to make it fail. */
    @FunctionalInterface
    interface HeadWriter {
        void write(Path headFile, long n, byte[] entryHash) throws IOException;
    }

    private static void refuseLink(Path file) throws AuditException {
        if (Files.isSymbolicLink(file)) {
            throw new AuditException(AuditException.Code.UNSAFE_FILE, 0, null);
        }
    }

    /**
     * A head without its log means the log was moved or deleted: {@code TRUNCATED}, and no new
     * log is created in its place (approval-model §7: both files are archived together).
     */
    private static void refuseLostLog(Path file) throws AuditException {
        refuseLink(file);
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS) && Files.exists(headOf(file), LinkOption.NOFOLLOW_LINKS)) {
            throw new AuditException(AuditException.Code.TRUNCATED, 0, null);
        }
    }

    static Path headOf(Path log) {
        return log.resolveSibling(Objects.requireNonNull(log.getFileName(), "file name") + ".head");
    }

    /**
     * Replaces the head atomically. Called only under the log's exclusive lock; the head is another
     * file, so its descriptors neither carry nor release the log's lock.
     */
    static void writeHead(Path headFile, long n, byte[] entryHash) throws IOException {
        Path tmp = headFile.resolveSibling(Objects.requireNonNull(headFile.getFileName(), "head") + ".new");
        Files.deleteIfExists(tmp);
        try (FileChannel ch = create(tmp, NEW_HEAD)) {
            ch.write(ByteBuffer.wrap((n + " " + java.util.HexFormat.of().formatHex(entryHash) + "\n")
                    .getBytes(StandardCharsets.US_ASCII)));
            ch.force(true);
        }
        Files.move(tmp, headFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE);
    }

    static byte[] encode(AuditEvent e, long seq, long ts, byte[] prev) {
        Map<String, CborValue> m = new LinkedHashMap<>();
        m.put("seq", new CborValue.UInt(seq));
        m.put("ts", new CborValue.UInt(ts));
        m.put("prev", new CborValue.Bytes(prev));
        m.put("kind", new CborValue.Text(e.kind()));
        e.requestId().ifPresent(id -> m.put("request_id", new CborValue.Text(id.toString())));
        e.requesterKind().ifPresent(v -> m.put("requester_kind", new CborValue.Text(v)));
        e.osUser().ifPresent(v -> m.put("os_user", new CborValue.Text(v)));
        e.project().ifPresent(v -> m.put("project", new CborValue.Text(v)));
        e.profile().ifPresent(v -> m.put("profile", new CborValue.Text(v)));
        if (e.varCount() >= 0) {
            m.put("var_count", new CborValue.UInt(e.varCount()));
        }
        e.decision().ifPresent(v -> m.put("decision", new CborValue.Text(v)));
        e.argv0().ifPresent(v -> m.put("argv0", new CborValue.Text(v)));
        return CborWriter.encode(new CborValue.MapV(m), LIMITS);
    }

    /** Verifies the chain read through {@code channel}, which the caller has locked. */
    private static Verified verify(Path file, FileChannel channel) throws IOException, AuditException {
        try {
            if (!OwnerOnly.isOwnerOnly(file)) {
                throw new AuditException(AuditException.Code.UNSAFE_FILE, 0, null);
            }
        } catch (StorageException e) {
            throw new AuditException(AuditException.Code.IO, 0, e);
        }
        byte[] all = readAll(channel);
        List<byte[]> chain = new ArrayList<>();
        byte[] prev = new byte[Hash.SHA256_BYTES];
        int start = 0;
        while (start < all.length) {
            int end = start;
            while (end < all.length && all[end] != NEWLINE) {
                end++;
            }
            long n = chain.size();
            if (end == all.length || end - start > MAX_LINE_BYTES) {
                throw new AuditException(AuditException.Code.TRUNCATED, n, null); // cut mid-line
            }
            byte[] entry = decodeLine(all, start, end, n);
            CborValue.MapV map = parse(entry, n);
            if (!(map.entries().get("seq") instanceof CborValue.UInt s) || s.value() != n + 1
                    || !(map.entries().get("prev") instanceof CborValue.Bytes p)
                    || !ConstantTime.equals(p.value(), prev)
                    || !(map.entries().get("kind") instanceof CborValue.Text k) || !KINDS.contains(k.value())) {
                throw new AuditException(AuditException.Code.TAMPERED, n, null);
            }
            prev = Hash.sha256(entry);
            chain.add(prev);
            start = end + 1;
        }
        boolean headLags = checkHead(file, chain);
        return new Verified(chain.size(), prev, all.length, headLags);
    }

    /**
     * Reads the whole log through the locked channel. A second descriptor (such as
     * {@code Files.readAllBytes}) would drop the lock when closed.
     */
    private static byte[] readAll(FileChannel channel) throws IOException, AuditException {
        long size = channel.size();
        if (size > MAX_FILE_BYTES) {
            throw new AuditException(AuditException.Code.TOO_LARGE, 0, null);
        }
        ByteBuffer buf = ByteBuffer.allocate((int) size + 1); // one spare byte, so the end of the file is seen
        int n;
        do {
            n = channel.read(buf, buf.position());
        } while (n > 0);
        return Arrays.copyOf(buf.array(), buf.position());
    }

    /** Checks the head against the chain; true if it is one entry behind (accepted). */
    private static boolean checkHead(Path file, List<byte[]> chain) throws AuditException {
        Path head = headOf(file);
        long count = chain.size();
        String text;
        try {
            if (Files.isSymbolicLink(head)) {
                throw new AuditException(AuditException.Code.UNSAFE_FILE, count, null);
            }
            text = Files.readString(head, StandardCharsets.US_ASCII).strip();
        } catch (NoSuchFileException e) {
            if (count == 0) {
                return false;
            }
            throw new AuditException(AuditException.Code.TAMPERED, count, null); // head removed
        } catch (IOException e) {
            throw new AuditException(AuditException.Code.IO, count, e);
        }
        int space = text.indexOf(' ');
        long headSeq;
        byte[] recorded;
        try {
            headSeq = Long.parseLong(text.substring(0, Math.max(space, 0)));
            recorded = java.util.HexFormat.of().parseHex(text.substring(space + 1));
        } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            throw new AuditException(AuditException.Code.TAMPERED, count, null);
        }
        if (headSeq > count) {
            throw new AuditException(AuditException.Code.TRUNCATED, count, null);
        }
        // The head may lag by one entry after a crash between the append and the head update.
        if (headSeq < count - 1 || headSeq < 1) {
            throw new AuditException(AuditException.Code.TAMPERED, Math.min(headSeq, count), null);
        }
        boolean headMatches = ConstantTime.equals(chain.get((int) headSeq - 1), recorded);
        if (!headMatches) {
            throw new AuditException(AuditException.Code.TAMPERED, Math.min(headSeq, count), null);
        }
        return headSeq < count;
    }

    private static byte[] decodeLine(byte[] all, int start, int end, long n) throws AuditException {
        try {
            return Base64.getDecoder().decode(Arrays.copyOfRange(all, start, end));
        } catch (IllegalArgumentException e) {
            throw new AuditException(AuditException.Code.TAMPERED, n, null);
        }
    }

    private static CborValue.MapV parse(byte[] entry, long n) throws AuditException {
        CborValue value;
        try {
            value = CborReader.decode(entry, LIMITS);
        } catch (CborException e) {
            throw new AuditException(AuditException.Code.TAMPERED, n, null);
        }
        if (value instanceof CborValue.MapV map) {
            return map;
        }
        throw new AuditException(AuditException.Code.TAMPERED, n, null);
    }

    /** Opens the log for reading and writing, creating it 0600 if absent; never through a link. */
    private static FileChannel openLog(Path file) throws IOException {
        try {
            return create(file, NEW_LOG);
        } catch (FileAlreadyExistsException e) {
            return FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        }
    }

    /** Creates {@code path} exclusively with owner-only permissions. */
    private static FileChannel create(Path path, Set<OpenOption> opts) throws IOException {
        boolean posix = Files.getFileStore(Objects.requireNonNull(path.toAbsolutePath().getParent(), "parent"))
                .supportsFileAttributeView("posix");
        if (posix) {
            FileAttribute<?> mode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
            return FileChannel.open(path, opts, mode);
        }
        FileChannel ch = FileChannel.open(path, opts);
        try {
            OwnerOnly.apply(path);
        } catch (StorageException e) {
            ch.close();
            throw new IOException("PERMISSIONS", e);
        }
        return ch;
    }

    /** The verified chain: its length, the last entry's hash, the bytes it occupies, and whether the head is behind. */
    @SuppressWarnings("ArrayRecordComponent") // private; the hash is public data and never shared
    private record Verified(long entries, byte[] lastHash, long bytes, boolean headLags) {
    }
}
