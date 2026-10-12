# Conclusion

## What the team learned

Building a password manager made the team see that secure coding is not a set of isolated
checklist items. A safe operation depends on several layers working together: validate input
before trusting it, keep mutable state inside a narrow boundary, protect secrets while they are
in memory and on disk, make updates atomic, and report failures without disclosing private data.
A correct check in one layer can be undone by a later conversion, copy, log statement, or cleanup
path.

The rules and recommendations discussed in this report are a selected set, not every rule
demonstrated by the project. The examples below combine all 25 listed rules and all 15 listed
recommendations (40 unique entries). They are teaching examples, not drop-in cryptography or
storage implementations: `VaultCipher`, `VaultCodec`, `OwnerOnly`, and `ApprovedExecutables`
stand for narrowly defined, reviewed project components. In particular, encryption must use a
reviewed authenticated-encryption implementation and correct key management; it should not be
invented from the example.

The main conclusions are:

1. **Keep trust boundaries explicit.** Canonicalize and validate data at the boundary, allow only
   deliberate data and capability flows, and never send secrets to logs, exception messages,
   subprocess arguments, or plaintext files.
2. **Own mutable data.** Copy mutable inputs before validation or use, do not expose internal
   arrays or collections, and make resource lifecycles explicit. `final` protects a reference,
   not the contents of the object it points to.
3. **Make failure safe and visible.** Validate before mutation, commit durable state before
   publishing new in-memory state, clean up resources on every path, and report success or a
   typed failure rather than silently continuing.
4. **Treat file and process APIs as security boundaries.** Use restrictive private directories,
   use the path returned by atomic temporary-file creation, verify file identity where supported,
   and invoke only fixed allowlisted executables with validated argument lists.
5. **Combine automation with review.** Static checks can catch many patterns, but normalization,
   lifecycle, trust-boundary, and rollback decisions still need tests and deliberate code review.

## Example 1: validate and encapsulate a sensitive record

This example keeps the record's state private, copies byte arrays on entry and exit, rejects use
after destruction, and exposes only immutable results. The payload represents already-encrypted
record bytes; plaintext passwords should use a dedicated secret type rather than `String`.

```java
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

// final prevents a subclass from weakening lifecycle or validation invariants.
final class VaultRecord implements AutoCloseable {
    private final UUID id;
    private final String canonicalLabel;
    private final byte[] encryptedPayload;
    private boolean destroyed;

    // Private construction keeps callers from observing a half-built record.
    // All checks and defensive copies happen in create() before this constructor is called.
    private VaultRecord(UUID id, String canonicalLabel, byte[] ownedCiphertext) {
        this.id = id;
        this.canonicalLabel = canonicalLabel;
        this.encryptedPayload = ownedCiphertext;
    }

    static VaultRecord create(UUID id, String label, byte[] ciphertext) {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(ciphertext, "ciphertext");
        byte[] ownedCiphertext = Arrays.copyOf(ciphertext, ciphertext.length);

        // Apply every transformation before validation so the checked value is exactly the
        // canonical representation stored and compared later.
        String canonical = Normalizer.normalize(label, Normalizer.Form.NFC)
                .strip()
                .toLowerCase(Locale.ROOT);
        if (canonical.isEmpty() || canonical.length() > 120) {
            Arrays.fill(ownedCiphertext, (byte) 0);
            throw new IllegalArgumentException("Invalid record label");
        }
        if (ownedCiphertext.length == 0 || ownedCiphertext.length > 1_048_576) {
            Arrays.fill(ownedCiphertext, (byte) 0);
            throw new IllegalArgumentException("Invalid encrypted payload size");
        }

        // The array was copied before any validation/use. For reference-typed mutable
        // parameters, never trust a caller-overridable clone() implementation.
        return new VaultRecord(id, canonical, ownedCiphertext);
    }

    UUID id() {
        ensureUsable();
        return id;
    }

    String label() {
        ensureUsable();
        return canonicalLabel;
    }

    byte[] encryptedPayloadCopy() {
        ensureUsable();
        // Never return the private mutable array; the caller receives an isolated copy.
        return Arrays.copyOf(encryptedPayload, encryptedPayload.length);
    }

    private void ensureUsable() {
        if (destroyed) {
            throw new IllegalStateException("Record is no longer available");
        }
    }

    @Override
    public void close() {
        if (!destroyed) {
            Arrays.fill(encryptedPayload, (byte) 0);
            destroyed = true;
        }
    }
}

final class RecordQueries {
    private RecordQueries() {}

    // Return an immutable view, not the mutable closeable record itself.
    record RecordView(UUID id, String label) {}

    // Absence is an ordinary outcome, so model it with Optional rather than exceptions,
    // null, -1, or another value that might also be valid data.
    static java.util.Optional<RecordView> find(
            java.util.Map<UUID, VaultRecord> records, UUID id) {
        Objects.requireNonNull(records, "records");
        Objects.requireNonNull(id, "id");
        return java.util.Optional.ofNullable(records.get(id))
                .map(record -> new RecordView(record.id(), record.label()));
    }

    // Collection-returning APIs use an empty immutable collection, never null.
    static java.util.List<RecordView> recordsForDisplay(
            java.util.Collection<VaultRecord> records) {
        Objects.requireNonNull(records, "records");
        return records.stream()
                .map(record -> new RecordView(record.id(), record.label()))
                .toList();
    }

    static boolean sameDigest(byte[] expected, byte[] actual) {
        Objects.requireNonNull(expected, "expected");
        Objects.requireNonNull(actual, "actual");
        // Compare array contents, not array identity; this API is suitable for authentication
        // material because it performs a constant-time comparison for equal-length inputs.
        return java.security.MessageDigest.isEqual(expected, actual);
    }

}
```

The private fields and narrow constructor illustrate **OBJ01-J** and **OBJ11-J**. Copying the
payload at the boundary and when returning it addresses **OBJ05-J**, **OBJ06-J**, and **OBJ13-J**;
the same copied-input pattern also follows **MET52-J**. The final class, final fields, immutable
label, and copy-on-output behavior demonstrate **OBJ50-J**, **OBJ56-J**, and **OBJ58-J**. The
destroyed-state guard demonstrates **OBJ14-J**. Null checks and normalized-before-validated input
apply **MET00-J** and **IDS01-J**; using `Locale.ROOT` applies **STR02-J**. The code treats the
payload as bytes, not text, which applies **STR03-J**. Finally, the helper compares array
contents correctly without using `Object.equals()` on an array, covering **EXP02-J**. A caller
should identify records by their explicit ID or other controlled fields, not by calling an
untrusted object's overridable `toString()` in a security
decision (**OBJ57-J**).

## Example 2: stage, encrypt, and atomically persist a vault update

The service below does not publish an in-memory update until the encrypted bytes have been
persisted. On failure, it leaves the old map intact and closes temporary records. The store
creates a private temporary file, writes only ciphertext, and atomically replaces the vault.
`TemporaryFile` is an `AutoCloseable` wrapper whose `close()` deletes an unmoved file and lets
try-with-resources preserve cleanup failures as suppressed exceptions.

```java
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

final class VaultException extends Exception {
    enum Code { STORAGE, CORRUPT, CRYPTO }

    private final Code code;

    VaultException(Code code, String safeMessage) {
        // Do not attach an underlying exception that could disclose a path or provider detail.
        super(safeMessage);
        this.code = Objects.requireNonNull(code, "code");
    }

    Code code() {
        return code;
    }
}

interface VaultCodec {
    // A constrained format such as the project's CBOR codec; never Java native serialization.
    byte[] encode(Map<UUID, VaultRecord> records) throws IOException;
}

interface VaultCipher {
    // Implement with reviewed authenticated encryption and managed keys.
    byte[] encrypt(byte[] serializedRecords) throws GeneralSecurityException;
}

final class VaultService {
    private final ReentrantLock stateLock = new ReentrantLock();
    private final VaultFileStore store;
    private final VaultCodec codec;
    private final VaultCipher cipher;
    private Map<UUID, VaultRecord> records = Map.of();

    VaultService(VaultFileStore store, VaultCodec codec, VaultCipher cipher) {
        this.store = Objects.requireNonNull(store, "store");
        this.codec = Objects.requireNonNull(codec, "codec");
        this.cipher = Objects.requireNonNull(cipher, "cipher");
    }

    // true means the durable commit succeeded. Checked failures are translated into a
    // project-specific exception; the caller never receives a raw path or secret-bearing error.
    boolean put(UUID id, String label, byte[] ciphertext)
            throws VaultException {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(ciphertext, "ciphertext");

        Map<UUID, VaultRecord> staged = new HashMap<>();
        stateLock.lock();
        boolean committed = false;
        try {
            // Build an entirely separate state snapshot. Existing live records are not mutated.
            for (Map.Entry<UUID, VaultRecord> entry : records.entrySet()) {
                VaultRecord old = entry.getValue();
                byte[] payloadCopy = old.encryptedPayloadCopy();
                try {
                    staged.put(entry.getKey(), VaultRecord.create(
                            old.id(), old.label(), payloadCopy));
                } finally {
                    java.util.Arrays.fill(payloadCopy, (byte) 0);
                }
            }
            VaultRecord replacement = VaultRecord.create(id, label, ciphertext);
            VaultRecord replaced = staged.put(id, replacement);
            if (replaced != null) {
                replaced.close();
            }

            byte[] encoded = Objects.requireNonNull(codec.encode(staged), "encoded vault");
            byte[] encrypted = null;
            try {
                encrypted = Objects.requireNonNull(cipher.encrypt(encoded), "encrypted vault");
                // Store only encrypted bytes. The storage implementation never writes encoded
                // plaintext records or key material to disk.
                if (!store.writeEncrypted(encrypted)) {
                    throw new IOException("Vault replacement did not complete");
                }
            } finally {
                java.util.Arrays.fill(encoded, (byte) 0);
                if (encrypted != null) {
                    java.util.Arrays.fill(encrypted, (byte) 0);
                }
            }

            Map<UUID, VaultRecord> previous = records;
            records = Map.copyOf(staged); // Publish only after durable write succeeds.
            staged.clear();               // Ownership of the new records has transferred.
            committed = true;

            // Remove short-lived objects held by the old long-lived map after commit.
            previous.values().forEach(VaultRecord::close);
            return true;                  // Explicit success feedback (MET54-J).
        } catch (IOException failure) {
            // Record only a fixed event; never log or return the provider/path details.
            System.getLogger(VaultService.class.getName()).log(
                    System.Logger.Level.WARNING, "Vault update failed");
            throw new VaultException(VaultException.Code.STORAGE,
                    "Vault update could not be saved");
        } catch (GeneralSecurityException failure) {
            System.getLogger(VaultService.class.getName()).log(
                    System.Logger.Level.WARNING, "Vault encryption failed");
            throw new VaultException(VaultException.Code.CRYPTO,
                    "Vault update could not be completed");
        } finally {
            if (!committed) {
                staged.values().forEach(VaultRecord::close);
            }
            // Unlock on success and on every exception. Do not swallow fatal Errors; the
            // staged/live-state separation still keeps the prior in-memory map intact.
            stateLock.unlock();
        }
    }

    Optional<RecordQueries.RecordView> find(UUID id) {
        Objects.requireNonNull(id, "id");
        stateLock.lock();
        try {
            return Optional.ofNullable(records.get(id))
                    .map(record -> new RecordQueries.RecordView(record.id(), record.label()));
        } finally {
            stateLock.unlock();
        }
    }

    void lockVault() {
        stateLock.lock();
        try {
            records.values().forEach(VaultRecord::close);
            records = Map.of();
        } finally {
            stateLock.unlock();
        }
    }
}

final class VaultFileStore {
    private final Path privateDirectory;
    private final Path vaultPath;

    VaultFileStore(Path privateDirectory, Path vaultPath) {
        this.privateDirectory = Objects.requireNonNull(privateDirectory, "privateDirectory");
        this.vaultPath = Objects.requireNonNull(vaultPath, "vaultPath");
        if (!vaultPath.normalize().startsWith(privateDirectory.normalize())) {
            throw new IllegalArgumentException("Vault path must be inside the private directory");
        }
    }

    boolean writeEncrypted(byte[] ciphertext) throws IOException {
        Objects.requireNonNull(ciphertext, "ciphertext");
        byte[] stableCiphertext = java.util.Arrays.copyOf(ciphertext, ciphertext.length);

        // create() uses Files.createTempFile in this owner-only directory and passes
        // restrictive creation attributes where the platform supports them. Use its exact
        // returned path; never guess a temporary name or assume a file was created.
        try {
            try (TemporaryFile temporary =
                         TemporaryFile.create(privateDirectory, OwnerOnly.fileAttributes())) {
                try (FileChannel channel = FileChannel.open(
                        temporary.path(), StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                    ByteBuffer bytes = ByteBuffer.wrap(stableCiphertext);
                    while (bytes.hasRemaining()) {
                        channel.write(bytes);
                    }
                    channel.force(true);
                }

                // Refuse a non-atomic fallback: a partial replacement could leave the vault
                // inconsistent. A failure is surfaced explicitly to the service.
                temporary.moveTo(vaultPath);
                return true;
            } catch (AtomicMoveNotSupportedException unsupported) {
                throw new IOException("Atomic vault replacement is unavailable", unsupported);
            }
        } finally {
            java.util.Arrays.fill(stableCiphertext, (byte) 0);
        }
    }

    byte[] readEncrypted() throws IOException {
        // NOFOLLOW_LINKS rejects a symbolic-link path. Check several attributes around the
        // read to detect replacement or modification where file identity is available.
        BasicFileAttributes before = Files.readAttributes(
                vaultPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile()) {
            throw new IOException("Vault is not a regular file");
        }

        byte[] bytes;
        try (var input = Files.newInputStream(
                vaultPath, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readAllBytes();
        }

        BasicFileAttributes after = Files.readAttributes(
                vaultPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        boolean sameIdentity = Objects.equals(before.fileKey(), after.fileKey())
                && before.size() == after.size()
                && before.lastModifiedTime().equals(after.lastModifiedTime())
                && after.isRegularFile();
        if (!sameIdentity) {
            java.util.Arrays.fill(bytes, (byte) 0);
            throw new IOException("Vault changed while it was being read");
        }
        return bytes;
    }
}

// This adapter uses the exact file created by createTempFile, allows only an atomic commit,
// and treats an unexpected missing temp file as a cleanup failure rather than success.
final class TemporaryFile implements AutoCloseable {
    private final Path path;
    private boolean moved;

    private TemporaryFile(Path path) {
        this.path = path;
    }

    static TemporaryFile create(
            Path directory, java.nio.file.attribute.FileAttribute<?>... attributes)
            throws IOException {
        return new TemporaryFile(Files.createTempFile(
                directory, ".vault-", ".tmp", attributes));
    }

    Path path() {
        return path;
    }

    void moveTo(Path destination) throws IOException {
        Files.move(path, destination,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        moved = true;
    }

    @Override
    public void close() throws IOException {
        if (!moved && !Files.deleteIfExists(path)) {
            throw new java.nio.file.NoSuchFileException(
                    "Temporary vault file disappeared before cleanup");
        }
    }
}
```

The private lock and `finally` release demonstrate **LCK00-J** and **LCK08-J**. The staged map
and delayed pointer replacement demonstrate **ERR03-J**; closing staged state and always releasing
the lock preserve a usable state on ordinary failures and support best-effort recovery from
system errors (**ERR53-J**). Checked failures are handled and translated rather than ignored
(**ERR00-J**), and the public exception has a specific project type and safe message
(**ERR01-J**, **ERR07-J**, and **ERR51-J**). The method reports success and absence as explicit
values (**MET54-J**, **ERR50-J**, and **ERR52-J**); callers of collection APIs receive empty
collections rather than `null` (**MET55-J**).

The code stores only authenticated-encrypted bytes, not a plaintext sensitive object graph
(**SER03-J** and **FIO52-J**), and it avoids logging those bytes or secret-bearing exceptions
(**FIO13-J** and **IDS15-J**). It uses the actual path returned by atomic temporary-file creation
instead of guessing about file creation (**FIO50-J**), verifies multiple file attributes on reads
(**FIO51-J**), checks the write/commit result and propagates file failures (**FIO02-J**), and
cleans temporary files through a closeable resource (**FIO03-J** and **ERR54-J**). Try-with-
resources also ensures that a close failure does not replace the primary failure (**ERR05-J**).
When the vault locks, it closes held records and clears the long-lived collection
(**OBJ55-J**).

## Example 3: decode complete text and run only an approved process

Text and binary data have different contracts. Decode a complete message with an explicit
charset; do not split UTF-8 bytes at arbitrary positions or turn binary key material into text.
Likewise, a user-provided process argument is data, not part of a shell command.

```java
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

final class BoundaryHelpers {
    private BoundaryHelpers() {}

    static String decodeLabel(byte[] completeUtf8Message)
            throws CharacterCodingException {
        Objects.requireNonNull(completeUtf8Message, "completeUtf8Message");
        byte[] stableMessage = java.util.Arrays.copyOf(
                completeUtf8Message, completeUtf8Message.length);

        // Decode only the complete frame. For streaming input, retain an incomplete trailing
        // UTF-8 sequence for the next read rather than making a string from partial bytes.
        String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(stableMessage))
                    .toString();
        } finally {
            java.util.Arrays.fill(stableMessage, (byte) 0);
        }

        // Finish all transformations before validating, so no later decoding or normalization
        // can create a value that escaped the allowlist.
        String canonical = Normalizer.normalize(decoded, Normalizer.Form.NFC)
                .strip()
                .toLowerCase(Locale.ROOT);
        if (!canonical.matches("[a-z0-9][a-z0-9 ._-]{0,119}")) {
            throw new IllegalArgumentException("Invalid label");
        }
        return canonical;
    }

    static int runApprovedGitStatus(List<String> untrustedOptions)
            throws IOException, InterruptedException {
        Objects.requireNonNull(untrustedOptions, "untrustedOptions");
        List<String> options = List.copyOf(untrustedOptions);
        if (options.size() > 8) {
            throw new IllegalArgumentException("Too many options");
        }

        // This is a fixed executable, not user input. Each option is validated and remains
        // one argument; no shell string or concatenation is involved.
        List<String> command = new ArrayList<>();
        // ApprovedExecutables.GIT is an absolute, deployment-validated path held by the
        // trusted platform module; do not resolve a request-provided executable via PATH.
        command.add(ApprovedExecutables.GIT.toString());
        command.add("status");
        for (String option : options) {
            Objects.requireNonNull(option, "option");
            if (!option.matches("--short|--branch|--porcelain")) {
                throw new IllegalArgumentException("Unsupported status option");
            }
            command.add(option);
        }
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start();
        boolean finished = process.waitFor(5, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            process.waitFor();
            throw new IOException("Approved status command timed out");
        }
        // A nonzero exit status is an ordinary reported outcome, not a thrown exception.
        return process.exitValue();
    }
}
```

The complete-frame UTF-8 decoder and explicit charset avoid partial variable-width characters
and platform-default encoding (**STR00-J**). The example also reinforces normalization before
validation and locale-independent canonicalization (**IDS01-J** and **STR02-J**). The process
runner uses a fixed executable, a strict option allowlist, and a `ProcessBuilder` argument list
instead of a shell command assembled from input (**IDS07-J**); its exit code is returned as
feedback rather than hidden.

## Coverage of the team's assigned entries

| Member | Rules | Recommendations |
| --- | --- | --- |
| Ben | SER03-J, LCK08-J, ERR03-J, OBJ06-J, EXP02-J | OBJ58-J, ERR54-J, FIO50-J |
| Naren | ERR01-J, IDS01-J, OBJ14-J, LCK00-J, FIO03-J | OBJ50-J, ERR50-J, ERR52-J |
| Mohammed | ERR07-J, ERR00-J, STR00-J, STR02-J, MET00-J | FIO52-J, OBJ57-J, MET54-J |
| Jacob | IDS07-J, OBJ05-J, OBJ11-J, OBJ13-J, FIO02-J | MET55-J, ERR51-J, FIO51-J |
| Jimmy | IDS15-J, STR03-J, OBJ01-J, ERR05-J, FIO13-J | OBJ56-J, MET52-J, ERR53-J |

Together, the examples cover every entry in the table, but they do not claim to represent every
CERT rule or every implementation detail in the password manager. The broader lesson is that
secure software comes from preserving invariants across the entire lifecycle—from input and
object construction, through concurrent changes and storage, to error reporting and cleanup.
The team's strongest result is not simply knowing individual rule names; it is being able to
recognize how several rules reinforce one another in one design and to verify those guarantees
with tests, automated checks, and review.
