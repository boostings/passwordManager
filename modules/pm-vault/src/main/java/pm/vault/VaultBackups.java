package pm.vault;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;
import pm.crypto.ConstantTime;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.BackupDirectory;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.VaultRecord;

/**
 * Encrypted vault backups with verified restore and bounded rotation (ADR 0015, plan.md §18,
 * SR-700, SR-703, SR-704).
 *
 * <p>A backup is the vault file exactly as last saved (still encrypted under the vault key and
 * authenticated by its own AES-GCM tag) inside a small header holding the creation time, the
 * vault's format version and its SHA-256, all authenticated by an HMAC under a key derived from
 * the vault key ({@link BackupFormat}). Plaintext is never written. Changes not yet saved are not
 * in the backup.
 *
 * <p>Backups are written into a user-chosen directory as
 * {@code pm-backup-<yyyyMMdd'T'HHmmss'Z'>-<nnn>.pmbackup}, owner-only and by atomic rename
 * ({@link BackupDirectory}). After each new backup the oldest are deleted until {@code keep}
 * remain; the new one is never deleted, and files with any other name are never touched.
 * Rotation orders by the time in the name, except that a name dated more than a day after the
 * current clock (clock skew) or with an impossible date counts as the oldest, so it cannot hold
 * a slot forever. A backup-named entry that is not an owner-only regular file is never deleted
 * or counted; it is reported as skipped, as is one whose deletion fails, and the backup that was
 * just written is still returned.
 *
 * <p>{@link #verify} authenticates and fully decodes a backup without writing anything.
 * {@link #restore} does the same first, then installs the vault file at the target in one atomic
 * rename, keeping the replaced vault as {@code .bak.1}; it replaces an existing vault only when
 * the caller passes {@code overwrite}. Every failure before the rename leaves the target as it
 * was, and the rename itself is atomic, so a restore never leaves a partial vault.
 *
 * <p><b>Passkey counters (ADR 0016 addendum, AC-51).</b> A backup holds the counters of the day it
 * was taken; assertions signed since then carried higher ones. If the backup holds a passkey,
 * {@link #restore} does not install it byte for byte: it re-seals the records as the next save
 * with every passkey counter raised to {@code max(backup + 2^20, existing + 1)}, where
 * {@code existing} is the counter of the same record in the vault being overwritten, if that vault
 * opens with the same passphrase ({@link #RESTORE_COUNTER_MARGIN}). A value that would reach
 * 2^32 - 1 becomes 2^32 - 1, which is exhausted, so the credential stops rather than repeats a
 * counter. A relying party sees no counter it has already seen unless more than 2^20 assertions
 * were signed after the backup on a vault that is not the one overwritten (another machine, or a
 * target that does not open with this passphrase).
 *
 * <p>Failures are {@link VaultException}s with the existing codes: {@code CORRUPT} for a damaged,
 * truncated or tampered backup, {@code WRONG_CREDENTIAL} for a wrong passphrase,
 * {@code UNSUPPORTED_VERSION} for a backup or vault format this build cannot read,
 * {@code ALREADY_EXISTS} for a restore onto an existing vault without {@code overwrite},
 * {@code LOCKED} for a locked vault and {@code STORAGE} for file system failures.
 */
public final class VaultBackups {

    /** File name extension of backups; gitleaks refuses committed files with it. */
    public static final String EXTENSION = ".pmbackup";
    /** File name prefix of backups written by {@link #create}. */
    public static final String PREFIX = "pm-backup-";

    private static final Pattern NAME = Pattern.compile("pm-backup-\\d{8}T\\d{6}Z-\\d{3}\\.pmbackup");
    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("uuuuMMdd'T'HHmmss'Z'", Locale.ROOT).withZone(ZoneOffset.UTC);
    private static final int NAMES_PER_SECOND = 1000;
    private static final int MIN_KEEP = 1;
    private static final int STAMP_LENGTH = 16;
    private static final long FUTURE_SLACK_SECONDS = 24L * 60 * 60;
    /** How far {@link #restore} raises every passkey counter: 2^20 assertions. */
    static final long RESTORE_COUNTER_MARGIN = 1L << 20;

    private final Clock clock;
    private final VaultReader reader;
    private final PayloadCodec codec;
    private final StoreOpener opener;

    /** Opens the restore target; replaced in tests to inject storage failures. */
    @FunctionalInterface
    interface StoreOpener {
        /**
         * Opens and locks the store at {@code target}.
         *
         * @param target vault path
         * @return the open store, owned by the caller
         * @throws StorageException if it cannot be opened
         */
        VaultFileStore open(Path target) throws StorageException;
    }

    /**
     * Facts about a backup. Before {@link #verify} succeeds they are unauthenticated.
     *
     * @param created       when the backup was made
     * @param formatVersion format version of the embedded vault file
     * @param vaultBytes    size of the embedded vault file
     * @param saveSeq       the embedded vault's save counter (ADR 0003 rollback detection)
     */
    public record Info(Instant created, int formatVersion, long vaultBytes, long saveSeq) {
        /** Rejects a null time. */
        public Info {
            Objects.requireNonNull(created, "created");
        }
    }

    /**
     * Result of {@link #create}.
     *
     * @param file    the new backup
     * @param info    its header facts
     * @param rotation what rotation did after the backup was written
     */
    public record Created(Path file, Info info, Rotation rotation) {
        /** Rejects nulls. */
        public Created {
            Objects.requireNonNull(file, "file");
            Objects.requireNonNull(info, "info");
            Objects.requireNonNull(rotation, "rotation");
        }
    }

    /**
     * Result of a rotation.
     *
     * @param removed  backups deleted, in deletion order
     * @param skipped  backup-named entries left in place: not owner-only regular files, or their
     *                 deletion failed; the user should look at them
     * @param complete false if the directory could not be listed after the backup was written, so
     *                 nothing was rotated
     */
    public record Rotation(List<Path> removed, List<Path> skipped, boolean complete) {
        /** Copies both lists. */
        public Rotation {
            removed = List.copyOf(removed);
            skipped = List.copyOf(skipped);
        }
    }

    /**
     * Result of {@link #verify}.
     *
     * @param info    the now authenticated header facts
     * @param records number of records the backup decodes to
     */
    public record Verified(Info info, int records) {
        /** Rejects a null info. */
        public Verified {
            Objects.requireNonNull(info, "info");
        }
    }

    /**
     * Result of {@link #restore}.
     *
     * @param info             the restored backup's facts
     * @param replacedExisting whether a vault was replaced (it is kept as {@code .bak.1})
     * @param lowersSaveSeq    whether the replaced vault had a higher save counter, so the restore
     *                         rolled the vault back to older content (ADR 0003); callers should say so
     */
    public record Restored(Info info, boolean replacedExisting, boolean lowersSaveSeq) {
        /** Rejects a null info. */
        public Restored {
            Objects.requireNonNull(info, "info");
        }
    }

    /**
     * Creates the service for the current format.
     *
     * @param clock source of backup creation times
     */
    public VaultBackups(Clock clock) {
        this(clock, MigrationRegistry.PRODUCTION, PayloadCodec.RECORDS, VaultFileStore::open);
    }

    VaultBackups(Clock clock, MigrationRegistry migrations, PayloadCodec codec, StoreOpener opener) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.reader = new VaultReader(migrations, codec);
        this.codec = codec;
        this.opener = Objects.requireNonNull(opener, "opener");
    }

    /**
     * Backs up the vault as last saved into {@code dir}, then deletes the oldest backups there
     * until {@code keep} remain. The saved file is first opened in full with the vault's key, so a
     * damaged file on disk is never backed up. {@code dir} is created owner-only if missing; an
     * existing one must be secure (writable by its owner only).
     *
     * @param vault an unlocked vault
     * @param dir   backup directory
     * @param keep  number of backups to keep, at least 1
     * @return the new backup and what rotation did; rotation problems never fail a backup that
     *         was written
     * @throws VaultException {@code LOCKED}, {@code CORRUPT} if the saved file does not open with
     *                        the vault's key, {@code STORAGE} if the backup could not be written
     */
    public Created create(Vault vault, Path dir, int keep) throws VaultException {
        Objects.requireNonNull(vault, "vault");
        Objects.requireNonNull(dir, "dir");
        if (keep < MIN_KEEP) {
            throw new IllegalArgumentException("keep");
        }
        long now = VaultService.epochSeconds(clock);
        byte[] backup = vault.withSavedFile((file, vk) -> {
            VaultReader.Envelope env = reader.parse(file);
            closeAll(reader.records(env, vk));
            BackupFormat.Header header = BackupFormat.Header.of(now, file, Csprng.bytes(BackupFormat.SALT_LENGTH));
            return BackupFormat.assemble(header, file, vk);
        });
        Info info = info(BackupFormat.parse(backup));
        try {
            BackupDirectory directory = BackupDirectory.open(dir);
            String name = freeName(directory, now);
            directory.createNew(name, backup);
            return new Created(directory.path().resolve(name), info, rotateAfterWrite(directory, keep, name, now));
        } catch (StorageException e) {
            throw new VaultException(VaultException.Code.STORAGE, e);
        }
    }

    /**
     * Lists the backups in {@code dir} written by {@link #create}, oldest first. A missing
     * directory has none.
     *
     * @param dir backup directory
     * @return backup paths
     * @throws VaultException {@code STORAGE} if the directory is unsafe or unreadable
     */
    public List<Path> list(Path dir) throws VaultException {
        Objects.requireNonNull(dir, "dir");
        if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            return List.of();
        }
        try {
            BackupDirectory directory = BackupDirectory.open(dir);
            return backupNames(directory).stream().map(directory.path()::resolve).toList();
        } catch (StorageException e) {
            throw new VaultException(VaultException.Code.STORAGE, e);
        }
    }

    /**
     * Reads a backup's header and checks its framing and content hash, without a passphrase.
     * The facts are not authenticated; use {@link #verify} before trusting them.
     *
     * @param backup backup file
     * @return its facts
     * @throws VaultException {@code CORRUPT}, {@code UNSUPPORTED_VERSION} or {@code STORAGE}
     */
    public Info inspect(Path backup) throws VaultException {
        return info(BackupFormat.parse(read(backup)));
    }

    /**
     * Authenticates a backup and decodes every record in it, writing nothing: framing and
     * content hash, then the passphrase against the embedded vault's slot, then the backup HMAC,
     * then the vault's AES-GCM tag and a full record decode (including any format migration).
     *
     * @param backup     backup file
     * @param passphrase the vault's master passphrase at the time of the backup; not closed
     * @return the authenticated facts and the record count
     * @throws VaultException {@code CORRUPT}, {@code WRONG_CREDENTIAL},
     *                        {@code UNSUPPORTED_VERSION}, {@code INSUFFICIENT_MEMORY} or
     *                        {@code STORAGE}
     */
    public Verified verify(Path backup, SecretChars passphrase) throws VaultException {
        Checked checked = check(backup, passphrase, false, Map.of());
        return new Verified(checked.info(), checked.records());
    }

    /**
     * Verifies {@code backup} as {@link #verify} does, then installs its vault file at
     * {@code target}; if it holds a passkey, the file installed is the backup re-sealed with every
     * passkey counter raised (see the class comment). An existing vault there is replaced only if {@code overwrite} is true, and
     * is then kept as {@code .bak.1}. The target must not be open in this or another process.
     * As with every save (ADR 0003), {@code .bak.1} is written before the vault is replaced, so a
     * write that then fails leaves the target unchanged but has already shifted the older
     * {@code .bak.N} generations, dropping the oldest; accepted, because the target itself and
     * its newest backup are intact.
     *
     * @param backup     backup file
     * @param target     vault path to restore to
     * @param passphrase the backup's master passphrase; not closed
     * @param overwrite  explicit confirmation to replace an existing vault
     * @return what was restored
     * @throws VaultException as {@link #verify}, {@code ALREADY_EXISTS} if a vault exists and
     *                        {@code overwrite} is false, {@code STORAGE} if the target cannot be
     *                        written (it is then unchanged) or does not read back identically
     */
    public Restored restore(Path backup, Path target, SecretChars passphrase, boolean overwrite)
            throws VaultException {
        Objects.requireNonNull(target, "target");
        Checked checked = check(backup, passphrase, true, Map.of());
        byte[] vaultFile = checked.install();
        try (VaultFileStore store = opener.open(target)) {
            boolean exists = exists(store);
            boolean lowers = false;
            if (exists) {
                if (!overwrite) {
                    throw new VaultException(VaultException.Code.ALREADY_EXISTS, null);
                }
                byte[] existing = store.readAll();
                lowers = saveSeqOf(existing) > checked.info().saveSeq();
                if (checked.passkeys()) {
                    Map<UUID, Long> floors = passkeyCounters(existing, passphrase);
                    if (!floors.isEmpty()) {
                        vaultFile = check(backup, passphrase, true, floors).install();
                    }
                }
                store.backup();
            }
            store.writeAtomically(vaultFile);
            if (!ConstantTime.equals(store.readAll(), vaultFile)) {
                throw new VaultException(VaultException.Code.STORAGE, null);
            }
            return new Restored(checked.info(), exists, lowers);
        } catch (StorageException e) {
            throw new VaultException(VaultException.Code.STORAGE, e);
        }
    }

    /**
     * Deletes the oldest backups in {@code dir} until {@code keep} remain, ordered as described
     * in the class comment.
     *
     * @param dir  backup directory
     * @param keep number to keep, at least 1
     * @return what was deleted and what was skipped
     * @throws VaultException {@code STORAGE} if the directory is unsafe or cannot be listed
     */
    public Rotation rotate(Path dir, int keep) throws VaultException {
        Objects.requireNonNull(dir, "dir");
        if (keep < MIN_KEEP) {
            throw new IllegalArgumentException("keep");
        }
        try {
            return rotate(BackupDirectory.open(dir), keep, null, VaultService.epochSeconds(clock));
        } catch (StorageException e) {
            throw new VaultException(VaultException.Code.STORAGE, e);
        }
    }

    // ---- internals -----------------------------------------------------------------------------

    /** A backup that passed every check, and the vault file a restore installs. */
    private static final class Checked {
        private final Info facts;
        private final int count;
        private final byte[] file;
        private final boolean holdsPasskeys;

        Checked(Info facts, int count, byte[] file, boolean holdsPasskeys) {
            this.facts = facts;
            this.count = count;
            this.file = file.clone();
            this.holdsPasskeys = holdsPasskeys;
        }

        boolean passkeys() {
            return holdsPasskeys;
        }

        Info info() {
            return facts;
        }

        int records() {
            return count;
        }

        byte[] install() {
            return file.clone();
        }
    }

    private Checked check(Path backup, SecretChars passphrase, boolean forRestore, Map<UUID, Long> floors)
            throws VaultException {
        Objects.requireNonNull(passphrase, "passphrase");
        BackupFormat.Parsed parsed = BackupFormat.parse(read(backup));
        VaultReader.Envelope env = reader.parse(parsed.vault());
        try (SecretBytes vk = VaultReader.keyFromPassphrase(env.header(), passphrase)) {
            if (!parsed.tagValid(vk)) {
                throw new VaultException(VaultException.Code.CORRUPT, null);
            }
            List<VaultRecord> records = reader.records(env, vk);
            int count = records.size();
            byte[] install = parsed.vault();
            boolean passkeys = records.stream().anyMatch(PasskeyRecord.class::isInstance);
            if (forRestore && passkeys) {
                install = Vault.raisedForRestore(env.header(), vk, codec, records, RESTORE_COUNTER_MARGIN, floors,
                        VaultService.epochSeconds(clock));
            } else {
                closeAll(records);
            }
            return new Checked(info(parsed.header(), env), count, install, passkeys);
        }
    }

    private Info info(BackupFormat.Parsed parsed) throws VaultException {
        return info(parsed.header(), reader.parse(parsed.vault()));
    }

    private static Info info(BackupFormat.Header header, VaultReader.Envelope env) {
        return new Info(Instant.ofEpochSecond(header.created()), header.formatVersion(),
                header.vaultLength(), env.header().saveSeq());
    }

    /**
     * The passkey counters of the vault a restore overwrites, by record id; empty if it does not
     * open with {@code passphrase} or is unreadable (the restore then raises from the backup alone;
     * ADR 0016 addendum).
     */
    private Map<UUID, Long> passkeyCounters(byte[] existing, SecretChars passphrase) {
        Map<UUID, Long> counters = new HashMap<>();
        try {
            VaultReader.Envelope env = reader.parse(existing);
            try (SecretBytes vk = VaultReader.keyFromPassphrase(env.header(), passphrase)) {
                List<VaultRecord> records = reader.records(env, vk);
                records.stream().filter(PasskeyRecord.class::isInstance).map(PasskeyRecord.class::cast)
                        .forEach(p -> counters.put(p.id(), p.signCount()));
                closeAll(records);
            }
        } catch (VaultException unreadable) {
            return Map.of();
        }
        return counters;
    }

    private long saveSeqOf(byte[] existing) {
        try {
            return reader.parse(existing).header().saveSeq();
        } catch (VaultException unreadable) {
            // An unreadable vault that the caller confirmed replacing has no counter to compare.
            return -1;
        }
    }

    private static byte[] read(Path backup) throws VaultException {
        Objects.requireNonNull(backup, "backup");
        try {
            return BackupDirectory.readFile(backup);
        } catch (StorageException e) {
            throw new VaultException(VaultException.Code.STORAGE, e);
        }
    }

    private static boolean exists(VaultFileStore store) throws VaultException {
        try {
            return store.exists();
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof StorageException storageFailure) {
                throw new VaultException(VaultException.Code.STORAGE, storageFailure);
            }
            throw e;
        }
    }

    private static String freeName(BackupDirectory directory, long now) throws StorageException, VaultException {
        String stem = PREFIX + STAMP.format(Instant.ofEpochSecond(now)) + "-";
        List<String> taken = directory.list(stem, EXTENSION);
        for (int counter = 0; counter < NAMES_PER_SECOND; counter++) {
            String name = stem + String.format(Locale.ROOT, "%03d", counter) + EXTENSION;
            if (!taken.contains(name)) {
                return name;
            }
        }
        throw new VaultException(VaultException.Code.STORAGE, null);
    }

    private static List<String> backupNames(BackupDirectory directory) throws StorageException {
        return directory.list(PREFIX, EXTENSION).stream().filter(n -> NAME.matcher(n).matches()).toList();
    }

    private static Rotation rotateAfterWrite(BackupDirectory directory, int keep, String protect, long now) {
        try {
            return rotate(directory, keep, protect, now);
        } catch (StorageException e) {
            // The backup is written; a listing failure only means nothing was rotated this time.
            return new Rotation(List.of(), List.of(), false);
        }
    }

    /**
     * Deletes the oldest usable backups beyond {@code keep}, never {@code protect}. A failed
     * deletion is skipped rather than replaced by deleting a newer backup.
     */
    private static Rotation rotate(BackupDirectory directory, int keep, String protect, long now)
            throws StorageException {
        BackupDirectory.Listing listing = directory.scan(PREFIX, EXTENSION);
        List<Path> skipped = new ArrayList<>();
        listing.refused().stream().filter(n -> NAME.matcher(n).matches())
                .forEach(n -> skipped.add(directory.path().resolve(n)));
        List<String> names = listing.usable().stream().filter(n -> NAME.matcher(n).matches())
                .sorted(Comparator.comparing((String n) -> !misdated(n, now)).thenComparing(Comparator.naturalOrder()))
                .toList();
        int excess = names.size() - keep;
        List<Path> removed = new ArrayList<>();
        for (String name : names) {
            if (excess <= 0) {
                break;
            }
            if (name.equals(protect)) {
                continue;
            }
            Path path = directory.path().resolve(name);
            try {
                if (directory.delete(name)) {
                    removed.add(path);
                }
                excess--;
            } catch (StorageException e) {
                skipped.add(path);
            }
        }
        return new Rotation(removed, skipped, true);
    }

    /** Whether the name's time is impossible or more than a day after {@code now}. */
    static boolean misdated(String name, long now) {
        String stamp = name.substring(PREFIX.length(), PREFIX.length() + STAMP_LENGTH);
        try {
            return Instant.from(STAMP.parse(stamp)).getEpochSecond() > now + FUTURE_SLACK_SECONDS;
        } catch (DateTimeException e) {
            return true;
        }
    }

    private static void closeAll(List<VaultRecord> records) {
        records.forEach(VaultRecord::close);
    }
}
