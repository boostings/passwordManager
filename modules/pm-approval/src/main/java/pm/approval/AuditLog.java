package pm.approval;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
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
 */
public final class AuditLog implements AuditSink, AutoCloseable {
    /** A log larger than this is refused on open; the user archives it. */
    public static final long MAX_FILE_BYTES = 64L * 1024 * 1024;
    private static final int MAX_LINE_BYTES = 8 * 1024;
    private static final CborLimits LIMITS = new CborLimits(4, 64, 1024, MAX_LINE_BYTES);
    private static final byte NEWLINE = '\n';
    /** Conventional file name, in the vault directory (approval-model §7). */
    public static final String FILE_NAME = "audit.log";
    /** Serializes {@link #append} within this JVM; the file lock serializes processes. */
    private static final ReentrantLock APPENDERS = new ReentrantLock();
    private static final Set<String> KINDS = Set.of("unlock", "lock", "approval", "prompt", "policy", "share",
            "pair", "revoke", "export", "slot");

    private final ReentrantLock guard = new ReentrantLock();
    private final Path file;
    private final Path headFile;
    private final Clock clock;
    /** Guarded by {@code guard}. */
    private final FileChannel out;
    /** Guarded by {@code guard}. */
    private long seq;
    /** Guarded by {@code guard}. */
    private byte[] last;

    private AuditLog(Path file, Clock clock, FileChannel out, long seq, byte[] last) {
        this.file = file;
        this.headFile = headOf(file);
        this.clock = clock;
        this.out = out;
        this.seq = seq;
        this.last = last;
    }

    /**
     * Opens {@code file}, creating it 0600 if absent, after verifying the whole chain.
     *
     * @throws AuditException {@code TAMPERED} or {@code TRUNCATED} with the last intact entry,
     *     {@code UNSAFE_FILE}, {@code TOO_LARGE} or {@code IO}
     */
    public static AuditLog open(Path file, Clock clock) throws AuditException {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(clock, "clock");
        Verified state = verify(file);
        FileChannel channel;
        try {
            channel = openAppend(file);
        } catch (IOException e) {
            throw new AuditException(AuditException.Code.IO, state.entries(), e);
        }
        return new AuditLog(file, clock, channel, state.entries(), state.lastHash());
    }

    /**
     * Verifies the chain and appends one event while holding an exclusive lock on the file, so the
     * TUI's broker and short-lived CLI commands can share one log without breaking the chain:
     * every writer re-reads the tail under the lock. Within this JVM appends are serialized too.
     *
     * @throws AuditException as for {@link #open}, or {@code IO} if the entry cannot be written
     */
    public static void append(Path file, Clock clock, AuditEvent event) throws AuditException {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(clock, "clock");
        checkKind(Objects.requireNonNull(event, "event"));
        try {
            withAppendLock(() -> {
                try (FileChannel channel = openAppend(file); FileLock exclusive = channel.lock()) {
                    Objects.requireNonNull(exclusive); // held until the try block ends
                    Verified state = verify(file);
                    new AuditLog(file, clock, channel, state.entries(), state.lastHash()).append(event);
                }
            });
        } catch (IOException e) {
            throw new AuditException(AuditException.Code.IO, 0, e);
        }
    }

    /** One locked append step; it may fail verification or I/O. */
    @FunctionalInterface
    private interface AppendStep {
        void run() throws IOException, AuditException;
    }

    private static void withAppendLock(AppendStep step) throws IOException, AuditException {
        APPENDERS.lock();
        try {
            step.run();
        } finally {
            APPENDERS.unlock();
        }
    }

    /**
     * Verifies {@code file} without opening it for writing.
     *
     * @return the number of entries
     * @throws AuditException as for {@link #open}
     */
    public static long check(Path file) throws AuditException {
        return verify(file).entries();
    }

    /** Number of entries written so far. */
    public long entries() {
        try {
            return locked(() -> seq);
        } catch (IOException e) {
            throw new IllegalStateException(e); // unreachable: reading a field
        }
    }

    /**
     * Appends {@code event}, flushed to disk before returning, so a decision is never acted on
     * without its record.
     *
     * @throws IllegalStateException {@code AUDIT_WRITE} if the entry cannot be written: the broker
     *     then fails the request closed
     */
    @Override
    public void record(AuditEvent event) {
        Objects.requireNonNull(event, "event");
        checkKind(event);
        try {
            locked(() -> {
                append(event);
                return null;
            });
        } catch (IOException e) {
            throw new IllegalStateException("AUDIT_WRITE", e);
        }
    }

    private static void checkKind(AuditEvent event) {
        if (!KINDS.contains(event.kind())) {
            throw new IllegalArgumentException("BAD_KIND");
        }
    }

    private void append(AuditEvent event) throws IOException {
        byte[] entry = encode(event, seq + 1, clock.instant().getEpochSecond(), last);
        byte[] line = (Base64.getEncoder().encodeToString(entry) + "\n").getBytes(StandardCharsets.US_ASCII);
        ByteBuffer buf = ByteBuffer.wrap(line);
        while (buf.hasRemaining()) {
            out.write(buf);
        }
        out.force(true);
        seq++;
        last = Hash.sha256(entry);
        writeHead(seq, last);
    }

    @Override
    public void close() {
        try {
            locked(() -> {
                out.close();
                return null;
            });
        } catch (IOException e) {
            throw new IllegalStateException("AUDIT_CLOSE", e); // every entry was already forced to disk
        }
    }

    /** The log's path. */
    public Path path() {
        return file;
    }

    private <T> T locked(IoAction<T> body) throws IOException {
        guard.lock();
        try {
            return body.run();
        } finally {
            guard.unlock();
        }
    }

    /** A step that may fail with an I/O error. */
    @FunctionalInterface
    private interface IoAction<T> {
        T run() throws IOException;
    }

    static Path headOf(Path log) {
        return log.resolveSibling(Objects.requireNonNull(log.getFileName(), "file name") + ".head");
    }

    private void writeHead(long n, byte[] entryHash) throws IOException {
        Path tmp = headFile.resolveSibling(Objects.requireNonNull(headFile.getFileName(), "head") + ".new");
        Files.deleteIfExists(tmp);
        try (FileChannel ch = create(tmp)) {
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

    private static Verified verify(Path file) throws AuditException {
        byte[] all;
        try {
            if (Files.isSymbolicLink(file)) {
                throw new AuditException(AuditException.Code.UNSAFE_FILE, 0, null);
            }
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.exists(headOf(file), LinkOption.NOFOLLOW_LINKS)) {
                    throw new AuditException(AuditException.Code.TRUNCATED, 0, null); // log deleted
                }
                return new Verified(0, new byte[Hash.SHA256_BYTES]);
            }
            if (!OwnerOnly.isOwnerOnly(file)) {
                throw new AuditException(AuditException.Code.UNSAFE_FILE, 0, null);
            }
            if (Files.size(file) > MAX_FILE_BYTES) {
                throw new AuditException(AuditException.Code.TOO_LARGE, 0, null);
            }
            all = Files.readAllBytes(file);
        } catch (IOException | StorageException e) {
            throw new AuditException(AuditException.Code.IO, 0, e);
        }
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
        checkHead(file, chain);
        return new Verified(chain.size(), prev);
    }

    private static void checkHead(Path file, List<byte[]> chain) throws AuditException {
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
                return;
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
    }

    private static byte[] decodeLine(byte[] all, int start, int end, long n) throws AuditException {
        try {
            return Base64.getDecoder().decode(java.util.Arrays.copyOfRange(all, start, end));
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

    private static FileChannel openAppend(Path file) throws IOException {
        try {
            return create(file);
        } catch (FileAlreadyExistsException e) {
            return FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS);
        }
    }

    /** Creates {@code path} exclusively with owner-only permissions. */
    private static FileChannel create(Path path) throws IOException {
        Set<OpenOption> opts = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS);
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

    @SuppressWarnings("ArrayRecordComponent") // private; the hash is public data and never shared
    private record Verified(long entries, byte[] lastHash) {
    }
}
