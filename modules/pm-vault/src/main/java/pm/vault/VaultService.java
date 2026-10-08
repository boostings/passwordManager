package pm.vault;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.Argon2Params;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.KeyWrap;
import pm.crypto.RecoveryKey;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.EnvelopeHeader;
import pm.vault.envelope.KdfHeader;
import pm.vault.envelope.SlotHeader;
import pm.vault.record.VaultRecord;
import pm.vault.slot.SlotCrypto;

/**
 * Creates and unlocks the vault file behind one {@link VaultFileStore} (ADR 0003, ADR 0004).
 *
 * <p>Unlock order is fixed and security-relevant:
 * <ol>
 *   <li>Structural decode of the envelope; failures are {@code CORRUPT} or
 *       {@code UNSUPPORTED_VERSION} and reveal nothing about the credential.</li>
 *   <li>KEK derivation. For a passphrase this runs Argon2id to completion every time.</li>
 *   <li>AES-KWP unwrap of the VK. An integrity failure is {@code WRONG_CREDENTIAL}.</li>
 *   <li>DK = HKDF(VK, dataSalt, "pm/data/v1"), then AES-GCM open over the AAD. A tag
 *       failure is {@code CORRUPT}.</li>
 *   <li>Only after the tag verifies are the records decoded (SR-020).</li>
 * </ol>
 *
 * <p><b>Migration (ADR 0015).</b> A file whose format version is older than
 * {@link EnvelopeCodec#VERSION} is read through the registered migration chain after step 4, and
 * the result is decoded by the current codec. Only then is it written back: the original bytes
 * are kept as an owner-only rollback copy {@code <vault>.pre-migration-v<N>}, the vault is saved
 * at the current version (the save rotates the original into {@code .bak.1}), the new file is
 * re-read and opened in full, and the copy is deleted. On any failure the original bytes are put
 * back and the error is reported. A version newer than this build is refused with
 * {@code UNSUPPORTED_VERSION} (SR-701); there is no forced downgrade.
 *
 * <p>Internal crypto failures (for example HKDF or wrap errors) have no dedicated code in
 * the frozen contract. They surface as {@code CORRUPT}, with the {@link CryptoException}
 * code in the cause. Messages never carry key material or paths (SR-501).
 */
public final class VaultService {

    /** Rollback copy suffix; the source format version is appended. */
    static final String ROLLBACK_SUFFIX_PREFIX = ".pre-migration-v";

    /** Points in a migration where tests inject failures. */
    enum MigrationStep { ROLLBACK_COPY_WRITTEN, MIGRATED_WRITTEN }

    /** Test seam: called at each {@link MigrationStep}; production does nothing. */
    @FunctionalInterface
    interface MigrationProbe {
        /** No-op probe. */
        MigrationProbe NONE = step -> { /* Production checkpoint: no action. */ };

        void at(MigrationStep step) throws VaultException;
    }

    private final VaultFileStore store;
    private final Clock clock;
    private final Argon2Params kdf;
    private final PayloadCodec codec;
    private final VaultReader reader;
    private final MigrationProbe probe;

    /**
     * Creates a service for one vault file.
     *
     * @param store open file store for the vault path
     * @param clock source of {@code created}/{@code saved} timestamps
     * @param kdf   Argon2id parameters for new vaults, used only by {@link #create}; production
     *              passes {@code Kdf.tune(500 ms)}, tests pass {@link Argon2Params#FLOOR}
     */
    public VaultService(VaultFileStore store, Clock clock, Argon2Params kdf) {
        this(store, clock, kdf, PayloadCodec.RECORDS);
    }

    /** Test seam: injects the payload codec. */
    VaultService(VaultFileStore store, Clock clock, Argon2Params kdf, PayloadCodec codec) {
        this(store, clock, kdf, codec, MigrationRegistry.PRODUCTION, MigrationProbe.NONE);
    }

    /** Test seam: injects the payload codec, the migration registry and a failure probe. */
    VaultService(VaultFileStore store, Clock clock, Argon2Params kdf, PayloadCodec codec,
                 MigrationRegistry migrations, MigrationProbe probe) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.kdf = Objects.requireNonNull(kdf, "kdf");
        this.codec = Objects.requireNonNull(codec, "codec");
        this.reader = new VaultReader(migrations, codec);
        this.probe = Objects.requireNonNull(probe, "probe");
        if (kdf.parallelism() > EnvelopeCodec.MAX_PARALLELISM) {
            throw new IllegalArgumentException("parallelism");
        }
    }

    /**
     * Creates a new vault with a passphrase slot and a recovery slot, then saves it with
     * {@code save_seq = 1}.
     *
     * @param pw master passphrase; not closed by this method
     * @return the unlocked vault and the formatted recovery key, both owned by the caller
     * @throws VaultException {@code ALREADY_EXISTS} if a vault file exists, {@code STORAGE}
     *                        if the write fails, {@code INSUFFICIENT_MEMORY} if the heap cannot
     *                        hold the Argon2id run
     * @throws IllegalArgumentException {@code EMPTY_PASSPHRASE} or {@code MALFORMED_CHARS}
     *                        ({@link #checkNewPassphrase}); nothing is written
     */
    public CreatedVault create(SecretChars pw) throws VaultException {
        checkNewPassphrase(pw);
        try {
            if (store.exists()) {
                throw new VaultException(VaultException.Code.ALREADY_EXISTS, null);
            }
        } catch (IllegalStateException ex) {
            if (ex.getCause() instanceof StorageException storageFailure) {
                throw new VaultException(VaultException.Code.STORAGE, storageFailure);
            }
            throw ex;
        }
        long now = epochSeconds(clock);
        UUID masterSlot = Csprng.uuid();
        UUID recoverySlot = Csprng.uuid();
        KdfHeader kdfHeader = new KdfHeader(EnvelopeCodec.KDF_ALG,
                kdf.memoryKiB(), kdf.iterations(), kdf.parallelism(),
                Csprng.bytes(EnvelopeCodec.SALT_LENGTH));
        try (SecretBytes vk = Csprng.secretBytes(Vault.KEY_LENGTH);
             SecretBytes rk = RecoveryKey.generate();
             SecretBytes kekP = VaultReader.passphraseKek(pw, kdfHeader, masterSlot);
             SecretBytes kekR = SlotCrypto.kekFromRecovery(rk, recoverySlot)) {
            List<SlotHeader> slots = List.of(
                    new SlotHeader(masterSlot, SlotHeader.MASTER, KeyWrap.wrap(kekP, vk)),
                    new SlotHeader(recoverySlot, SlotHeader.RECOVERY, KeyWrap.wrap(kekR, vk)));
            // save_seq 0 is never written: the first save() bumps it to 1.
            EnvelopeHeader header = new EnvelopeHeader(kdfHeader, slots, now, now, 0L);
            return saveNew(new Vault(store, clock, codec, header, vk, List.of()), rk);
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    /**
     * Unlocks with the master passphrase. A file of an older format version is migrated first
     * (ADR 0015, see the class comment); a newer one is refused.
     *
     * @param pw master passphrase; not closed by this method
     * @return the unlocked vault, owned by the caller
     * @throws VaultException {@code WRONG_CREDENTIAL}, {@code CORRUPT},
     *                        {@code UNSUPPORTED_VERSION}, {@code STORAGE}, or
     *                        {@code INSUFFICIENT_MEMORY} if the heap cannot hold the header's
     *                        Argon2id memory
     */
    public Vault unlockWithPassphrase(SecretChars pw) throws VaultException {
        Objects.requireNonNull(pw, "pw");
        byte[] file = readFile();
        VaultReader.Envelope env = reader.parse(file);
        try (SecretBytes vk = VaultReader.keyFromPassphrase(env.header(), pw)) {
            return openOrMigrate(file, env, vk);
        }
    }

    /**
     * Unlocks with the recovery key. A key that fails to parse (typo, bad checksum) is
     * {@code WRONG_CREDENTIAL} whose cause is the {@code BAD_INPUT} {@link CryptoException}.
     * An older format version is migrated first, as for {@link #unlockWithPassphrase}.
     *
     * @param typed the typed recovery key; not closed by this method
     * @return the unlocked vault, owned by the caller
     * @throws VaultException {@code WRONG_CREDENTIAL}, {@code CORRUPT},
     *                        {@code UNSUPPORTED_VERSION} or {@code STORAGE}
     */
    public Vault unlockWithRecoveryKey(SecretChars typed) throws VaultException {
        Objects.requireNonNull(typed, "typed");
        byte[] file = readFile();
        VaultReader.Envelope env = reader.parse(file);
        try (SecretBytes vk = VaultReader.keyFromRecovery(env.header(), typed)) {
            return openOrMigrate(file, env, vk);
        }
    }

    /**
     * Changes the master passphrase of an unlocked vault (ADR 0004 addendum, SR-130, SR-131).
     *
     * <p><b>What changes.</b> The same vault key is wrapped again under a KEK derived from
     * {@code newPassphrase} with a fresh 32-byte Argon2id salt and the Argon2id parameters already
     * in the vault's header. m, t and p stay as they are: ADR 0007 tunes them only at creation or
     * by an explicit re-tune, and this service's own {@code kdf} is not used (the CLI passes the
     * floor for every command but {@code init}). The passphrase slot keeps its id. The recovery
     * slot, the vault key and every record are unchanged. The vault is then saved like any
     * {@link Vault#save()}: {@code save_seq} + 1, pending edits included, the previous file rotated
     * into {@code .bak.1}, then one atomic rename. Afterwards the old passphrase is refused with
     * {@code WRONG_CREDENTIAL} like any wrong one, the new one and the recovery key unlock, and
     * {@code vault} stays unlocked and usable. The file written is the one {@code vault} was
     * unlocked from or created as.
     *
     * <p><b>Who may call it.</b> Any unlocked vault, including one unlocked with the recovery key:
     * that is the way back from a forgotten passphrase. The current passphrase is not asked for
     * here; a UI holding a long-lived session asks for the current passphrase or the recovery key
     * again first, so an unattended unlocked session cannot be used to lock its owner out.
     *
     * <p><b>Policy.</b> {@code newPassphrase} must pass the check {@link #create} applies
     * ({@link #checkNewPassphrase}); the UI also asks for it twice, as {@code pm init} does.
     *
     * <p><b>Locking.</b> Runs under the vault lock and the store's save lock, Argon2id included.
     * Inside a {@link Vault#signWithPasskey} port it is refused with {@code REENTRANT}, like
     * {@link Vault#save()}, before any work. If the file is not the one {@code vault} last read or
     * wrote (another vault over the same file saved since), it is refused with {@code CONFLICT}
     * before the KDF runs and nothing is written (SR-151); so is a later {@code save()} of a vault
     * that still holds the header from before the change.
     *
     * <p><b>Failure.</b> On a failure the file is put back as it was, then read back, and the
     * exception says which passphrase it holds (SR-152). A failure that comes after the new file
     * is in place (in production only an Error, since the store does not report a failed directory
     * sync) writes the old bytes back; a failure of that write, an Error included, is attached to
     * the failure as suppressed. Then:
     * <ul>
     *   <li>the old passphrase slot is on disk: the failure itself is thrown ({@code STORAGE} for
     *       a failed write, or as {@link Vault#save()}); not changed, the old passphrase and the
     *       recovery key open the file, and {@code vault} keeps its old header;</li>
     *   <li>the new slot is on disk: {@code PASSPHRASE_CHANGED_UNCONFIRMED}; changed, the new
     *       passphrase and the recovery key open the file, and {@code vault} now holds the header
     *       on disk, so its later saves keep the new passphrase;</li>
     *   <li>the file cannot be read back or holds neither: {@code PASSPHRASE_CHANGE_UNKNOWN}; the
     *       recovery key, which a change never alters, opens any file this vault wrote, and
     *       {@code vault} keeps its old header.</li>
     * </ul>
     * In every case {@code vault} stays open.
     *
     * <p><b>Not affected.</b> Backups made earlier keep the passphrase they were made under:
     * {@code .bak.N} files (the {@code .bak.1} this save writes is the file as it was before the
     * change) and {@link VaultBackups} files open with the old passphrase, which
     * {@link VaultBackups#verify} and {@link VaultBackups#restore} need since they take no recovery
     * key, and with the unchanged recovery key. The LAN device identity and the paired-device trust
     * list are records in the payload and are saved unchanged under the same vault key, so no
     * device needs pairing again. No audit log exists at this layer; the caller records the change.
     *
     * @param vault         an unlocked vault; it stays unlocked
     * @param newPassphrase the new master passphrase; not closed by this method
     * @throws VaultException {@code LOCKED} if {@code vault} is locked, {@code CONFLICT} if the
     *     file changed since {@code vault} last read or wrote it, {@code STORAGE} if the file
     *     cannot be read or written, {@code INSUFFICIENT_MEMORY} if this JVM's heap cannot hold the
     *     header's Argon2id memory (possible after a recovery-key unlock, which runs no Argon2id;
     *     ADR 0007), {@code CORRUPT} if the save counter is exhausted or a crypto step fails; all of
     *     these mean not changed. {@code PASSPHRASE_CHANGED_UNCONFIRMED} or
     *     {@code PASSPHRASE_CHANGE_UNKNOWN} as described under Failure
     * @throws IllegalArgumentException {@code EMPTY_PASSPHRASE} or {@code MALFORMED_CHARS}; nothing
     *     is written
     * @throws IllegalStateException {@code REENTRANT} from inside a {@link Vault#signWithPasskey}
     *     port, or {@code SECRET_CLOSED} if {@code newPassphrase} is closed; nothing is written
     */
    public void changePassphrase(Vault vault, SecretChars newPassphrase) throws VaultException {
        changePassphrase(vault, newPassphrase, Vault.WriteProbe.NONE);
    }

    /** {@link #changePassphrase(Vault, SecretChars)} with a test probe in the save. */
    void changePassphrase(Vault vault, SecretChars newPassphrase, Vault.WriteProbe writeProbe)
            throws VaultException {
        Objects.requireNonNull(vault, "vault");
        checkNewPassphrase(newPassphrase);
        vault.changePassphraseSlot((current, vk) -> rewrapped(current, vk, newPassphrase), writeProbe);
    }

    /**
     * The passphrase rule {@link #create} and {@link #changePassphrase} share (SR-131): not empty,
     * the rule {@code pm init} has applied since M1 ({@code EMPTY_PASSPHRASE}). Well-formed UTF-16
     * is the other half: the Argon2id input is the UTF-8 encoding, so an unpaired surrogate is
     * refused with {@code MALFORMED_CHARS} by the same derivation in both, before anything is
     * written. No strength rule exists yet (SR-011 is planned, not implemented).
     *
     * @param pw the passphrase to check; not closed
     * @throws IllegalArgumentException {@code EMPTY_PASSPHRASE}
     */
    static void checkNewPassphrase(SecretChars pw) {
        Objects.requireNonNull(pw, "pw");
        if (pw.length() == 0) {
            throw new IllegalArgumentException("EMPTY_PASSPHRASE");
        }
    }

    /**
     * {@code current} with a fresh KDF salt and the passphrase slot wrapping {@code vk} under the
     * KEK from {@code pw}; m, t, p, the slot id and every other slot are unchanged.
     */
    private static EnvelopeHeader rewrapped(EnvelopeHeader current, SecretBytes vk, SecretChars pw)
            throws VaultException {
        KdfHeader old = current.kdf();
        KdfHeader fresh = new KdfHeader(old.alg(), old.m(), old.t(), old.p(),
                Csprng.bytes(EnvelopeCodec.SALT_LENGTH));
        UUID slotId = current.firstSlot(SlotHeader.MASTER).id();
        try (SecretBytes kek = VaultReader.passphraseKek(pw, fresh, slotId)) {
            SlotHeader replacement = new SlotHeader(slotId, SlotHeader.MASTER, KeyWrap.wrap(kek, vk));
            List<SlotHeader> slots = current.slots().stream()
                    .map(s -> SlotHeader.MASTER.equals(s.type()) ? replacement : s)
                    .toList();
            return new EnvelopeHeader(fresh, slots, current.created(), current.saved(), current.saveSeq());
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    /**
     * Returns the format version of the vault file on disk, from its unauthenticated prefix. A
     * caller compares it with {@link #currentFormatVersion()} to tell the user, before unlocking,
     * that the unlock will migrate the file (plan.md §21: explain changes in plain language).
     *
     * @return the on-disk format version
     * @throws VaultException {@code STORAGE} if the file cannot be read, {@code CORRUPT} if it is
     *                        not a vault file
     */
    public int fileFormatVersion() throws VaultException {
        return VaultReader.versionOf(readFile());
    }

    /** Returns the format version this build writes. */
    public static int currentFormatVersion() {
        return EnvelopeCodec.VERSION;
    }

    /**
     * Opens a vault file at the VK layer, skipping slot unwrap. Test seam for TamperTest,
     * which flips every byte without paying for Argon2 each time.
     *
     * @param file complete file bytes
     * @param vk   vault key; copied, the caller keeps ownership
     */
    Vault openWithVaultKey(byte[] file, SecretBytes vk) throws VaultException {
        return open(reader.parse(file), vk);
    }

    /** Returns the clock time in epoch seconds; a clock before 1970 is a configuration error. */
    static long epochSeconds(Clock clock) {
        long now = clock.instant().getEpochSecond();
        if (now < 0) {
            throw new IllegalStateException("clock before epoch");
        }
        return now;
    }

    /**
     * Authenticates, then decodes. No record byte is parsed unless the GCM tag verified
     * (SR-020). A record that fails its own validation after authentication is CORRUPT.
     */
    private Vault open(VaultReader.Envelope env, SecretBytes vk) throws VaultException {
        List<VaultRecord> decoded = reader.records(env, vk);
        try {
            return new Vault(store, clock, codec, env.header(), vk, decoded);
        } catch (IllegalArgumentException e) {
            decoded.forEach(VaultRecord::close);
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    private Vault openOrMigrate(byte[] file, VaultReader.Envelope env, SecretBytes vk) throws VaultException {
        Vault vault = open(env, vk);
        if (!env.needsMigration()) {
            // The current file just opened in full, so a copy left by an interrupted migration
            // is no longer needed (ADR 0015).
            removeStaleRollbackCopies();
            return vault;
        }
        // Closes the vault (wiping the VK and records) on every failure, Errors included.
        try (LockUnlessKept guard = new LockUnlessKept(vault)) {
            installMigrated(file, env.version(), vault, vk);
            guard.keep();
            return vault;
        }
    }

    /** Locks a vault on close unless {@link #keep()} ran first. */
    private static final class LockUnlessKept implements AutoCloseable {
        private final Vault vault;
        private boolean kept;

        LockUnlessKept(Vault vault) {
            this.vault = vault;
        }

        void keep() {
            kept = true;
        }

        @Override
        public void close() {
            if (!kept) {
                vault.close();
            }
        }
    }

    /**
     * Deletes every {@code .pre-migration-v<N>} copy for versions older than the current one.
     * Best effort: a copy that cannot be inspected or deleted (for example one that is not
     * owner-only) is left for the user and does not fail the unlock.
     */
    private int removeStaleRollbackCopies() {
        int removed = 0;
        for (int version = 0; version < EnvelopeCodec.VERSION; version++) {
            if (deleteIfSafe(ROLLBACK_SUFFIX_PREFIX + version)) {
                removed++;
            }
        }
        return removed;
    }

    private boolean deleteIfSafe(String suffix) {
        try {
            return store.deleteSibling(suffix);
        } catch (StorageException e) {
            return false;
        }
    }

    /**
     * Writes a migrated vault (ADR 0015). The records are already decoded by the current codec, so
     * the migrated payload is known to be valid before anything is written. Any failure after the
     * rollback copy exists puts the original bytes back and only then deletes the copy, so the
     * original is never lost.
     */
    private void installMigrated(byte[] original, int fromVersion, Vault vault, SecretBytes vk)
            throws VaultException {
        String suffix = ROLLBACK_SUFFIX_PREFIX + fromVersion;
        keepRollbackCopy(suffix, original);
        boolean verified = false;
        boolean rolledBack = false;
        try {
            probe.at(MigrationStep.ROLLBACK_COPY_WRITTEN);
            vault.save();
            probe.at(MigrationStep.MIGRATED_WRITTEN);
            verifyOnDisk(vk);
            verified = true;
        } catch (VaultException | RuntimeException e) {
            rolledBack = true;
            rollBack(original, suffix, e);
            throw e;
        } finally {
            if (!verified && !rolledBack) {
                // An Error (for example OutOfMemoryError while verifying): still put the original back.
                rollBack(original, suffix, null);
            }
        }
        try {
            store.deleteSibling(suffix);
        } catch (StorageException e) {
            throw new VaultException(VaultException.Code.STORAGE, e);
        }
    }

    /**
     * Creates the rollback copy. A copy left by an interrupted earlier attempt is reused when it
     * holds exactly the current file; one that differs is never overwritten, because it may be the
     * only good copy, and the migration is refused with {@code STORAGE}.
     */
    private void keepRollbackCopy(String suffix, byte[] original) throws VaultException {
        try {
            if (store.siblingExists(suffix)) {
                if (!ConstantTime.equals(store.readSibling(suffix), original)) {
                    throw new VaultException(VaultException.Code.STORAGE,
                            new StorageException(StorageException.Code.IO, null));
                }
                return;
            }
            store.createSibling(suffix, original);
        } catch (StorageException e) {
            throw new VaultException(VaultException.Code.STORAGE, e);
        }
    }

    /** Re-reads the vault and opens it in full at the current version; closes what it opened. */
    private void verifyOnDisk(SecretBytes vk) throws VaultException {
        VaultReader.Envelope env = reader.parse(readFile());
        if (env.needsMigration()) {
            throw new VaultException(VaultException.Code.CORRUPT, null);
        }
        reader.records(env, vk).forEach(VaultRecord::close);
    }

    /**
     * Restores the original bytes after a failed migration, then deletes the rollback copy. If the
     * restore itself fails, the copy stays on disk and the failure is attached to {@code failure}
     * when there is one to attach it to.
     */
    private void rollBack(byte[] original, String suffix, Exception failure) {
        try {
            if (!onDiskEquals(original)) {
                store.writeAtomically(original);
            }
            store.deleteSibling(suffix);
        } catch (StorageException | RuntimeException e) {
            if (failure != null) {
                failure.addSuppressed(e);
            }
        }
    }

    private boolean onDiskEquals(byte[] expected) {
        try {
            return ConstantTime.equals(store.readAll(), expected);
        } catch (StorageException e) {
            return false;
        }
    }

    /** Saves a freshly created vault; locks it again if anything fails. */
    private CreatedVault saveNew(Vault vault, SecretBytes rk) throws VaultException {
        try {
            vault.save();
            return new CreatedVault(vault, RecoveryKey.format(rk));
        } catch (VaultException | RuntimeException e) {
            vault.close();
            throw e;
        }
    }

    private byte[] readFile() throws VaultException {
        try {
            return store.readAll();
        } catch (StorageException e) {
            throw new VaultException(VaultException.Code.STORAGE, e);
        }
    }
}
