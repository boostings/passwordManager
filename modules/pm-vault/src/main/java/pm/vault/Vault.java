package pm.vault;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.locks.ReentrantLock;
import pm.crypto.Aead;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.Hash;
import pm.crypto.Kdf;
import pm.crypto.SecretBytes;
import pm.crypto.passkey.Es256;
import pm.crypto.passkey.PasskeyKey;
import pm.crypto.passkey.storage.PasskeyStorage;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.EnvelopeHeader;
import pm.vault.envelope.SlotHeader;
import pm.vault.internal.PasskeyRecordAccess;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.RecordSearch;
import pm.vault.record.VaultRecord;

/**
 * An unlocked vault (ADR 0003, ADR 0004). It holds the vault key (VK) and the decrypted
 * records in memory until {@link #close()}.
 *
 * <p><b>Ownership.</b> The vault owns every record it holds. {@link #put} transfers
 * ownership to the vault. The record it replaces is retired and closed when the vault locks,
 * not at once: the replacement may be the same instance or may share a {@code SecretBytes}
 * with it, and closing it early would zero secrets that are still live. {@link #remove}
 * closes the removed record at once. {@link #close} closes every held and retired record.
 *
 * <p><b>Passkeys (ADR 0016 addendum, SR-085, SR-087).</b> A passkey's key and counter are vault
 * state. {@link #records()} and {@link #search} return keyless views of passkey records, so
 * closing one changes nothing in the vault. {@link #put} of a passkey whose id the vault holds
 * takes only the title and names from it; the key, identity and counter stay the vault's, so an
 * old view put back can never lower the counter. A new passkey must carry a valid key.
 *
 * <p><b>Locked state (OBJ14-J).</b> {@code close()} is the lock operation. It zeroes the VK,
 * closes every record and is idempotent. Afterwards {@link #save()} throws
 * {@link VaultException} with code {@code LOCKED}, and {@link #signWithPasskey} throws
 * {@link PasskeyException} with code {@code LOCKED}. Every other method except
 * {@link #isLocked()} and {@code close()} throws {@link IllegalStateException}, because its
 * signature has no checked failure channel.
 *
 * <p><b>Threads.</b> Every method takes a private lock (LCK00-J), so an auto-lock from
 * another thread cannot interleave with a save or edit. A save also takes a lock shared by every
 * vault over the same store, under which it checks that the file is still the one this vault last
 * read or wrote (SR-151); the store's file lock keeps other processes out for its lifetime.
 */
public final class Vault implements AutoCloseable {

    /** Data-key and vault-key length in bytes (AES-256). */
    static final int KEY_LENGTH = 32;

    private static final String DATA_KEY_INFO = "pm/data/v1";
    private static final String LOCKED_MESSAGE = "LOCKED";

    private static final int RP_ID_HASH_BYTES = 32;
    private static final int BYTE_MASK = 0xFF;
    private static final int FLAG_UP = 0x01;
    private static final int FLAG_AT = 0x40;
    private static final int FLAG_ED = 0x80;

    /**
     * One save lock per store instance, shared by every vault over it (a {@link VaultService}
     * hands out any number), so a save's check of the file and its write are one step. Weak keys:
     * a store nobody references any more frees its entry.
     */
    private static final Map<VaultFileStore, ReentrantLock> SAVE_LOCKS =
            Collections.synchronizedMap(new WeakHashMap<>());

    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantLock saveLock;
    private final VaultFileStore store;
    private final Clock clock;
    private final PayloadCodec codec;
    private final SecretBytes vaultKey;
    /** Guarded by {@link #lock}. */
    private final Map<UUID, VaultRecord> byId = new LinkedHashMap<>();
    /** Guarded by {@link #lock}. Records replaced by {@link #put}; closed on lock. */
    private final List<VaultRecord> retired = new ArrayList<>();
    /** Guarded by {@link #lock}. Replaced only after a save reaches disk (ERR03-J). */
    private EnvelopeHeader currentHeader;
    /** Guarded by {@link #lock}. */
    private boolean closed;
    /** Guarded by {@link #lock}. A put or remove since the last save: the next save rotates backups. */
    private boolean contentChanged;
    /** Guarded by {@link #lock}. A {@link #signWithPasskey} call is running on the lock's owner. */
    private boolean signing;

    /**
     * Creates an unlocked vault. Copies {@code vk}; the caller keeps ownership of its
     * argument. Takes ownership of {@code initial}, whose ids must be distinct.
     */
    Vault(VaultFileStore store, Clock clock, PayloadCodec codec, EnvelopeHeader header,
          SecretBytes vk, List<VaultRecord> initial) {
        this.store = Objects.requireNonNull(store, "store");
        this.saveLock = SAVE_LOCKS.computeIfAbsent(store, s -> new ReentrantLock());
        this.clock = Objects.requireNonNull(clock, "clock");
        this.codec = Objects.requireNonNull(codec, "codec");
        this.currentHeader = Objects.requireNonNull(header, "header");
        Objects.requireNonNull(vk, "vk");
        initial.forEach(r -> {
            if (byId.putIfAbsent(r.id(), r) != null) {
                throw new IllegalArgumentException("duplicate record id");
            }
        });
        this.vaultKey = vk.apply(Vault::copyKey);
    }

    /**
     * Returns an unmodifiable snapshot of the records in insertion order. Passkey records are
     * keyless views (see the class comment); every other record is the vault's own instance.
     */
    public List<VaultRecord> records() {
        return locked(() -> {
            ensureOpen();
            return byId.values().stream().map(Vault::shareable).toList();
        });
    }

    /**
     * Returns the records whose non-secret fields match {@code query} (see
     * {@link RecordSearch#matches}). Secret fields are never searched.
     *
     * @param query search text; empty matches everything
     */
    public List<VaultRecord> search(String query) {
        Objects.requireNonNull(query, "query");
        return locked(() -> {
            ensureOpen();
            List<VaultRecord> hits = new ArrayList<>();
            for (VaultRecord r : byId.values()) {
                if (RecordSearch.matches(r, query)) {
                    hits.add(shareable(r));
                }
            }
            return List.copyOf(hits);
        });
    }

    /**
     * Inserts {@code r}, or replaces the record with the same id. The vault takes ownership
     * of {@code r}; the replaced record is closed when the vault locks. Changes reach disk on
     * {@link #save()}. For a passkey the vault already holds, only the title, account name,
     * display name and update time are taken from {@code r}; its key and counter are ignored.
     *
     * @param r record to store
     * @throws IllegalArgumentException {@code BAD_KEY} for a new passkey record without a valid
     *     key (such as a view of a removed passkey); the vault is unchanged and the caller keeps
     *     {@code r}
     * @throws IllegalStateException {@code LOCKED} after close; {@code REENTRANT} from inside a
     *     {@link #signWithPasskey} port, where the vault is read-only
     */
    public void put(VaultRecord r) {
        Objects.requireNonNull(r, "r");
        locked(() -> {
            ensureOpen();
            ensureNotSigning();
            if (r instanceof PasskeyRecord) {
                putPasskey(PasskeyRecord.class.cast(r));
            } else {
                Optional.ofNullable(byId.put(r.id(), r)).ifPresent(retired::add);
            }
            contentChanged = true;
            return null;
        });
    }

    /** Caller holds the lock. */
    private void putPasskey(PasskeyRecord incoming) {
        PasskeyRecordAccess.Hook hook = PasskeyRecordAccess.hook();
        if (byId.get(incoming.id()) instanceof PasskeyRecord) {
            // The vault's passkey is never handed out, so nothing else holds it: close it now.
            try (PasskeyRecord live = PasskeyRecord.class.cast(byId.get(incoming.id())); incoming) {
                byId.put(incoming.id(), hook.edited(live, incoming));
            }
            return;
        }
        if (!hook.keyIsValid(incoming)) {
            throw new IllegalArgumentException(PasskeyException.Code.BAD_KEY.name());
        }
        Optional.ofNullable(byId.put(incoming.id(), incoming)).ifPresent(retired::add);
    }

    /**
     * Removes and closes the record with {@code id}.
     *
     * @param id record id
     * @return true if a record was removed
     * @throws IllegalStateException {@code LOCKED} after close; {@code REENTRANT} from inside a
     *     {@link #signWithPasskey} port
     */
    public boolean remove(UUID id) {
        Objects.requireNonNull(id, "id");
        return locked(() -> {
            ensureOpen();
            ensureNotSigning();
            VaultRecord removed = byId.remove(id);
            if (removed == null) {
                return false;
            }
            removed.close();
            contentChanged = true;
            return true;
        });
    }

    /**
     * Enrolls a new passkey (ADR 0016 M6.3 addendum, SR-115): generates a P-256 key inside
     * {@code pm-crypto} from {@code Csprng}, builds the record here with a random 32-byte credential
     * ID, counter 0 and a random record id, and writes the whole vault atomically before
     * returning. Only the public credential comes back; the private key never leaves the vault.
     * If the write fails the record is dropped from memory and nothing is returned, so a relying
     * party is never given a credential the vault does not hold. The caller has already decided
     * that {@code rpId} is valid for the requesting origin (the WebAuthn layer, SR-116).
     *
     * @param title record title (at most 256 characters)
     * @param rpId relying-party ID, as {@link PasskeyRecord} requires: a canonical lower-case
     *     host name, not an IP address
     * @param userHandle WebAuthn {@code user.id}, 1 to 64 bytes; copied
     * @param accountName WebAuthn {@code user.name}, already made display-safe, with a visible
     *     character
     * @param displayName WebAuthn {@code user.displayName}, display-safe, possibly empty
     * @return the record id, RP ID, credential ID and COSE public key of the saved passkey
     * @throws PasskeyException {@code LOCKED}, {@code REENTRANT} (called from inside an
     *     {@link AssertionPort}), {@code BAD_INPUT} (a field breaks the record's rules; nothing
     *     changed) or {@code SAVE_FAILED} (the cause attached; nothing is enrolled)
     */
    public PasskeyCreated createPasskey(String title, String rpId, byte[] userHandle, String accountName,
                                        String displayName) throws PasskeyException {
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(rpId, "rpId");
        byte[] handle = Objects.requireNonNull(userHandle, "userHandle").clone();
        Objects.requireNonNull(accountName, "accountName");
        Objects.requireNonNull(displayName, "displayName");
        return locked(() -> {
            if (closed) {
                throw new PasskeyException(PasskeyException.Code.LOCKED, null);
            }
            if (signing) {
                throw new PasskeyException(PasskeyException.Code.REENTRANT, null);
            }
            byte[] credentialId = PasskeyKey.newCredentialId();
            byte[] cose;
            PasskeyRecord created;
            try (PasskeyKey key = PasskeyKey.generate()) {
                cose = key.cosePublicKey();
                created = newPasskey(key, title, rpId, credentialId, handle, accountName, displayName);
            }
            boolean pending = contentChanged;
            byId.put(created.id(), created);
            try {
                persist(true);
            } catch (VaultException e) {
                throw dropUnsaved(created, pending, e);
            } catch (RuntimeException e) {
                throw dropUnsaved(created, pending, e);
            }
            return new PasskeyCreated(created.id(), created.rpId(), credentialId, cose);
        });
    }

    /** The record for a freshly generated key. Caller holds the lock. */
    private PasskeyRecord newPasskey(PasskeyKey key, String title, String rpId, byte[] credentialId, byte[] handle,
                                     String accountName, String displayName) throws PasskeyException {
        Instant now = clock.instant();
        SecretBytes stored = PasskeyStorage.toStorage(key);
        try {
            return PasskeyRecordAccess.hook().create(Csprng.uuid(), title, rpId, credentialId, handle, accountName,
                    displayName, stored, 0, now, now, now);
        } catch (IllegalArgumentException e) {
            stored.close();
            throw new PasskeyException(PasskeyException.Code.BAD_INPUT, e);
        }
    }

    /** Removes an enrollment whose save failed and returns the failure. Caller holds the lock. */
    private PasskeyException dropUnsaved(PasskeyRecord created, boolean pending, Exception cause) {
        byId.remove(created.id());
        created.close();
        contentChanged = pending;
        return new PasskeyException(PasskeyException.Code.SAVE_FAILED, cause);
    }

    /**
     * Changes the title, account name and display name of passkey {@code id} (ADR 0016 M6.3
     * addendum). Its RP ID, credential ID, user handle, key, counter, creation and last use stay as
     * they are. Like {@link #put}, the change reaches disk on the next {@link #save()}.
     *
     * @param id the passkey record's id
     * @param title new title
     * @param accountName new account name (visible, display-safe)
     * @param displayName new display name (display-safe, possibly empty)
     * @return false if the vault holds no passkey with that id; nothing changed
     * @throws IllegalArgumentException if a new value breaks the record's rules; nothing changed
     * @throws PasskeyException {@code REENTRANT} if called from inside an {@link AssertionPort}, as
     *     {@link #createPasskey} is; nothing changed
     */
    public boolean editPasskey(UUID id, String title, String accountName, String displayName)
            throws PasskeyException {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(accountName, "accountName");
        Objects.requireNonNull(displayName, "displayName");
        return locked(() -> {
            ensureOpen();
            refuseWhileSigning();
            if (!(byId.get(id) instanceof PasskeyRecord)) {
                return false;
            }
            PasskeyRecord live = PasskeyRecord.class.cast(byId.get(id));
            // A keyless record carrying the new names; putPasskey merges only the editable fields.
            putPasskey(PasskeyRecordAccess.hook().create(id, title, live.rpId(), live.credentialId(),
                    live.userHandle(), accountName, displayName, closedKey(), live.signCount(), live.created(),
                    clock.instant(), live.lastUsed()));
            contentChanged = true;
            return true;
        });
    }

    /**
     * Changes only the title of passkey {@code id}; see {@link #editPasskey}.
     *
     * @return false if the vault holds no passkey with that id
     * @throws IllegalArgumentException if the title breaks the record's rules
     * @throws PasskeyException {@code REENTRANT} if called from inside an {@link AssertionPort}
     */
    public boolean renamePasskey(UUID id, String title) throws PasskeyException {
        Objects.requireNonNull(id, "id");
        return locked(() -> {
            ensureOpen();
            refuseWhileSigning();
            if (!(byId.get(id) instanceof PasskeyRecord)) {
                return false;
            }
            PasskeyRecord live = PasskeyRecord.class.cast(byId.get(id));
            return editPasskey(id, title, live.accountName(), live.displayName());
        });
    }

    /** {@code REENTRANT} inside {@link #signWithPasskey}'s port. Caller holds the lock. */
    private void refuseWhileSigning() throws PasskeyException {
        if (signing) {
            throw new PasskeyException(PasskeyException.Code.REENTRANT, null);
        }
    }

    /** A closed key buffer: the record built with it has no key. */
    private static SecretBytes closedKey() {
        SecretBytes none = SecretBytes.takeOwnership(new byte[PasskeyRecord.PRIVATE_KEY_BYTES]);
        none.close();
        return none;
    }

    /**
     * Encrypts the records under a fresh data key and writes the vault. Steps: new
     * {@code dataSalt}; {@code saved = clock}; {@code save_seq + 1}; encode the header;
     * compute the AAD; derive DK = HKDF(VK, dataSalt, "pm/data/v1"); seal; then
     * {@code store.backup()} and {@code store.writeAtomically}. The in-memory header changes
     * only after the write succeeds (ERR03-J).
     *
     * @throws VaultException {@code LOCKED} after close, {@code STORAGE} if the write fails,
     *                        {@code CORRUPT} if the save counter is exhausted or sealing fails,
     *                        {@code CONFLICT} (nothing written) if the file's save_seq is not the
     *                        one this vault last read or wrote, or the file no longer parses
     *                        (SR-151); a missing file is written again
     * @throws IllegalStateException {@code REENTRANT} from inside a {@link #signWithPasskey} port
     */
    public void save() throws VaultException {
        locked(() -> {
            ensureNotSigning();
            persist(true);
            return null;
        });
    }

    /**
     * {@link #save()}, rotating the {@code .bak.N} generations only if {@code rotateBackups}. A
     * passkey counter advance alone does not rotate them, so signing in does not push the user's
     * recovery points out (ADR 0016 addendum).
     */
    private void persist(boolean rotateBackups) throws VaultException {
        persist(rotateBackups, WriteProbe.NONE);
    }

    /**
     * {@link #persist(boolean)} with a test probe at each {@link WriteStep}. The in-memory header
     * becomes the written one only after the write succeeds (ERR03-J). The file is checked and
     * written under the store's save lock.
     */
    private void persist(boolean rotateBackups, WriteProbe probe) throws VaultException {
        lockedForSave(() -> {
            if (closed) {
                throw new VaultException(VaultException.Code.LOCKED, null);
            }
            EnvelopeHeader next;
            try {
                next = currentHeader.nextSave(VaultService.epochSeconds(clock));
            } catch (ArithmeticException e) {
                throw new VaultException(VaultException.Code.CORRUPT, e);
            }
            byte[] file = sealFile(next, vaultKey, codec, List.copyOf(byId.values()));
            if (file.length > VaultFileStore.MAX_FILE_BYTES) {
                // Never write a file that unlock would refuse to read.
                throw new VaultException(VaultException.Code.STORAGE,
                        new StorageException(StorageException.Code.TOO_LARGE, null));
            }
            probe.at(WriteStep.SEALED);
            try {
                boolean exists;
                try {
                    exists = store.exists();
                } catch (IllegalStateException ex) {
                    if (ex.getCause() instanceof StorageException storageFailure) {
                        throw new VaultException(VaultException.Code.STORAGE, storageFailure);
                    }
                    throw ex;
                }
                if (exists) {
                    refuseIfChanged(store.readAll());
                }
                if (exists && rotateBackups) {
                    store.backup();
                }
                probe.at(WriteStep.BACKED_UP);
                store.writeAtomically(file);
            } catch (StorageException e) {
                throw new VaultException(VaultException.Code.STORAGE, e);
            }
            probe.at(WriteStep.WRITTEN);
            currentHeader = next;
            contentChanged = false;
            return null;
        });
    }

    /**
     * Points in the save of a passphrase change where tests inject a crash or a failure. Inside
     * {@code VaultFileStore.writeAtomically} the vault file goes from the old bytes to the new
     * ones in one rename, so a crash at any storage step leaves the file as at {@link #BACKED_UP}
     * (before the rename) or as at {@link #WRITTEN} (after it). {@link #PUT_BACK} is reached only
     * after a failure.
     */
    enum WriteStep {
        /** The new file is sealed in memory; nothing on disk has changed. */
        SEALED,
        /** {@code .bak.N} has rotated; the vault file is still the old one. */
        BACKED_UP,
        /** The new vault file is in place; the in-memory header is still the old one. */
        WRITTEN,
        /** The change failed, and the old file is about to be written back. */
        PUT_BACK
    }

    /** Test seam: called at each {@link WriteStep}; production does nothing. */
    @FunctionalInterface
    interface WriteProbe {
        /** No-op probe. */
        WriteProbe NONE = step -> { /* Production checkpoint: no action. */ };

        void at(WriteStep step) throws VaultException;
    }

    /** Builds the header a passphrase change writes, from the current header and the VK. */
    @FunctionalInterface
    interface PassphraseRewrap {
        /**
         * Returns {@code current} with a new KDF salt and passphrase slot.
         *
         * @param current the header as last written
         * @param vk      the vault key; not closed and not retained
         * @return the header to save
         * @throws VaultException if the new slot cannot be built
         */
        EnvelopeHeader rewrap(EnvelopeHeader current, SecretBytes vk) throws VaultException;
    }

    /**
     * Saves the vault under the header {@code rewrap} builds ({@link VaultService#changePassphrase}),
     * with the same {@code .bak.N} rotation and atomic write as {@link #save()}. Under the vault
     * lock and the store's save lock, and refused like {@code save()} before {@code rewrap} runs:
     * {@code LOCKED} after close, {@code REENTRANT} inside a {@link #signWithPasskey} port,
     * {@code CONFLICT} if the file is not the one this vault last read or wrote (SR-151).
     *
     * <p>If the save fails in any way, the file bytes read before it are written back unless the
     * file still holds them (a failure to do so, an Error included, is attached to the original
     * failure). The file is then read back to report what it holds (SR-152): the old passphrase
     * slot, and the original failure is rethrown with the in-memory header the old one; the new
     * slot, and {@code PASSPHRASE_CHANGED_UNCONFIRMED} is thrown with the in-memory header the
     * one on disk; anything else, or nothing readable, and {@code PASSPHRASE_CHANGE_UNKNOWN} is
     * thrown with the in-memory header the old one. The vault stays open in every case.
     *
     * @throws VaultException {@code LOCKED}, {@code CONFLICT}, {@code STORAGE} (the file cannot be
     *     read or written; not changed), whatever {@code rewrap} throws, as {@link #save()} (not
     *     changed), {@code PASSPHRASE_CHANGED_UNCONFIRMED} or {@code PASSPHRASE_CHANGE_UNKNOWN}
     * @throws IllegalStateException {@code REENTRANT} from inside a {@link #signWithPasskey} port
     */
    void changePassphraseSlot(PassphraseRewrap rewrap, WriteProbe probe) throws VaultException {
        Objects.requireNonNull(rewrap, "rewrap");
        Objects.requireNonNull(probe, "probe");
        lockedForSave(() -> {
            if (closed) {
                throw new VaultException(VaultException.Code.LOCKED, null);
            }
            ensureNotSigning();
            byte[] original;
            try {
                original = store.readAll();
            } catch (StorageException e) {
                throw new VaultException(VaultException.Code.STORAGE, e);
            }
            // Before the KDF runs; the save below checks again under the same locks.
            refuseIfChanged(original);
            EnvelopeHeader previous = currentHeader;
            EnvelopeHeader changed = rewrap.rewrap(previous, vaultKey);
            // Same save_seq as previous, so the save below writes changed's successor. Only this
            // thread can see the swap: it holds the lock until the header is final either way.
            currentHeader = changed;
            try {
                persist(true, probe);
            } catch (VaultException | RuntimeException | Error e) {
                // An Error too: an OutOfMemoryError after the rename must not leave the new file.
                currentHeader = previous;
                putBack(original, e, probe);
                settle(previous, changed, e);
                throw e;
            }
            return null;
        });
    }

    /**
     * Writes {@code original} back unless the file already holds it, so a failed passphrase change
     * leaves the file as it was. Any failure to do so is attached to {@code failure}: the catch
     * names every Throwable the block can throw (its only checked ones are StorageException and
     * VaultException), so an Error here cannot replace {@code failure}. Caller holds the locks.
     */
    private void putBack(byte[] original, Throwable failure, WriteProbe probe) {
        try {
            probe.at(WriteStep.PUT_BACK);
            if (!ConstantTime.equals(store.readAll(), original)) {
                store.writeAtomically(original);
            }
        } catch (StorageException | VaultException | RuntimeException | Error e) {
            suppress(failure, e);
        }
    }

    /**
     * After a failed passphrase change, reads the file back and reports which passphrase slot it
     * holds (SR-152). Returns normally only if it holds {@code previous}'s, so the caller's
     * failure truthfully means "not changed". Caller holds the locks.
     *
     * @throws VaultException {@code PASSPHRASE_CHANGED_UNCONFIRMED} if the file holds
     *     {@code changed}'s slot (the in-memory header becomes the file's), otherwise
     *     {@code PASSPHRASE_CHANGE_UNKNOWN}; both with {@code failure} as the cause
     */
    private void settle(EnvelopeHeader previous, EnvelopeHeader changed, Throwable failure)
            throws VaultException {
        EnvelopeHeader onDisk;
        try {
            onDisk = headerOf(store.readAll());
        } catch (StorageException | RuntimeException | Error e) {
            suppress(failure, e);
            onDisk = null;
        }
        if (onDisk != null && samePassphraseSlot(onDisk, previous)) {
            return;
        }
        if (onDisk != null && samePassphraseSlot(onDisk, changed)) {
            // The file this save sealed (only it holds the new slot), so it also holds the records.
            currentHeader = onDisk;
            contentChanged = false;
            throw new VaultException(VaultException.Code.PASSPHRASE_CHANGED_UNCONFIRMED, failure);
        }
        throw new VaultException(VaultException.Code.PASSPHRASE_CHANGE_UNKNOWN, failure);
    }

    /**
     * Refuses with {@code CONFLICT} unless {@code file}'s save_seq is the one this vault last read
     * or wrote (SR-151). Another vault over the same store saved since, and writing now would undo
     * that save without a word: a record, or a passphrase change. Caller holds the locks.
     */
    private void refuseIfChanged(byte[] file) throws VaultException {
        EnvelopeHeader onDisk = headerOf(file);
        if (onDisk == null || onDisk.saveSeq() != currentHeader.saveSeq()) {
            throw new VaultException(VaultException.Code.CONFLICT, null);
        }
    }

    /**
     * Returns {@code file}'s header, or null if it is not a vault file of a version this build
     * reads. Unauthenticated, so it is only compared, never used to open anything.
     */
    private static EnvelopeHeader headerOf(byte[] file) {
        try {
            int version = EnvelopeCodec.peekVersion(file);
            return version > EnvelopeCodec.VERSION ? null : EnvelopeCodec.decode(file, version).header();
        } catch (VaultException e) {
            return null;
        }
    }

    /** Whether two headers hold the same passphrase slot: the KDF parameters and salt, and the MASTER slot. */
    private static boolean samePassphraseSlot(EnvelopeHeader a, EnvelopeHeader b) {
        return Arrays.asList(a.kdf(), a.firstSlot(SlotHeader.MASTER))
                .equals(Arrays.asList(b.kdf(), b.firstSlot(SlotHeader.MASTER)));
    }

    /**
     * Attaches {@code extra} to {@code failure}, unless it is the same object: the JVM may throw
     * one preallocated OutOfMemoryError twice, and self-suppression throws.
     */
    private static void suppress(Throwable failure, Throwable extra) {
        // Throwable.equals is identity.
        if (!failure.equals(extra)) {
            failure.addSuppressed(extra);
        }
    }

    /**
     * Signs one WebAuthn assertion with a stored passkey, advancing its counter first (ADR 0016
     * addendum, SR-087, SR-088). Under the vault lock, so concurrent signers are serialised and
     * each gets its own counter value:
     * <ol>
     *   <li>check {@code clientDataHash} is 32 bytes and find the passkey record {@code id};
     *       refuse {@code COUNTER_EXHAUSTED} if its counter is already 2^32 - 1. Nothing changes
     *       on any of these refusals;</li>
     *   <li>replace the record in memory with a copy whose counter is one higher and whose last
     *       use is now;</li>
     *   <li>write the vault, the new counter and every pending change included, atomically; the
     *       {@code .bak.N} generations rotate only if a record was put or removed since the last
     *       save. If the write fails, {@code SAVE_FAILED}, and nothing is signed;</li>
     *   <li>only then load the key, give {@code port} a keyless view of the saved record to build
     *       the authenticator data, sign, and close the key.</li>
     * </ol>
     * The counter is on disk before any signature exists, so a crash at any point can lose a
     * signature but never lets a later signature carry a counter at or below one already
     * released. A value whose save failed stays in memory and is never handed out again. Inside
     * {@code port} the vault is read-only on the signing thread: a passkey call is refused with
     * {@code PasskeyException} {@code REENTRANT}, and {@link #put}, {@link #remove}, {@link #save()}
     * and {@link #close()} with {@code IllegalStateException} {@code REENTRANT}, so signing order is
     * always counter order and the record being signed with cannot be removed or locked away
     * mid-signature. Another thread's call just waits for the lock.
     *
     * @param id the passkey record's id
     * @param clientDataHash SHA-256 of the client data, exactly 32 bytes
     * @param port builds the authenticator data for the persisted counter
     * @return the assertion; its counter is already saved
     * @throws PasskeyException {@code LOCKED}, {@code REENTRANT}, {@code BAD_INPUT}, {@code NOT_FOUND}
     *     (no record, or not a passkey), {@code COUNTER_EXHAUSTED}, {@code SAVE_FAILED} (any failure
     *     to write, the cause attached), {@code BAD_KEY} or {@code SIGN_FAILED} (the port failed or
     *     returned authenticator data not bound to this record's RP ID, UP flag and persisted
     *     counter; see {@link AssertionPort}; the counter value stays burnt)
     */
    public PasskeyAssertion signWithPasskey(UUID id, byte[] clientDataHash, AssertionPort port)
            throws PasskeyException {
        Objects.requireNonNull(id, "id");
        byte[] hash = Objects.requireNonNull(clientDataHash, "clientDataHash").clone();
        Objects.requireNonNull(port, "port");
        return locked(() -> {
            if (closed) {
                throw new PasskeyException(PasskeyException.Code.LOCKED, null);
            }
            if (signing) {
                throw new PasskeyException(PasskeyException.Code.REENTRANT, null);
            }
            if (hash.length != Es256.CLIENT_DATA_HASH_BYTES) {
                throw new PasskeyException(PasskeyException.Code.BAD_INPUT, null);
            }
            VaultRecord found = byId.get(id);
            if (!(found instanceof PasskeyRecord)) {
                throw new PasskeyException(PasskeyException.Code.NOT_FOUND, null);
            }
            signing = true;
            try {
                PasskeyRecord persisted = advanceAndPersist(PasskeyRecord.class.cast(found));
                return signPersisted(persisted, hash, port);
            } finally {
                signing = false;
            }
        });
    }

    /**
     * Replaces {@code current} with a copy whose counter is one higher, closes {@code current}
     * (never handed out) and writes the vault. Caller holds the lock.
     */
    private PasskeyRecord advanceAndPersist(PasskeyRecord current) throws PasskeyException {
        if (current.signCount() >= PasskeyRecord.MAX_SIGN_COUNT) {
            throw new PasskeyException(PasskeyException.Code.COUNTER_EXHAUSTED, null);
        }
        PasskeyRecord next = PasskeyRecordAccess.hook().advanced(current, current.signCount() + 1, clock.instant());
        byId.put(current.id(), next);
        current.close();
        try {
            persist(contentChanged);
        } catch (VaultException e) {
            throw new PasskeyException(PasskeyException.Code.SAVE_FAILED, e);
        } catch (RuntimeException e) {
            // A failing codec or store: still a failed save, and the value stays burnt.
            throw new PasskeyException(PasskeyException.Code.SAVE_FAILED, e);
        }
        return next;
    }

    /**
     * Loads the key of the saved record, asks {@code port} for the authenticator data and signs.
     * The key is loaded first, so nothing the port does to the vault can reach it. Caller holds
     * the lock.
     */
    private static PasskeyAssertion signPersisted(PasskeyRecord persisted, byte[] clientDataHash, AssertionPort port)
            throws PasskeyException {
        try (PasskeyKey key = loadKey(persisted)) {
            byte[] authenticatorData = authenticatorData(persisted, port);
            return new PasskeyAssertion(persisted.signCount(), authenticatorData,
                    key.sign(authenticatorData, clientDataHash));
        } catch (CryptoException e) {
            throw new PasskeyException(PasskeyException.Code.SIGN_FAILED, e);
        }
    }

    private static byte[] authenticatorData(PasskeyRecord persisted, AssertionPort port) throws PasskeyException {
        byte[] built;
        try (PasskeyRecord view = PasskeyRecordAccess.hook().view(persisted)) {
            built = port.authenticatorData(view);
        } catch (RuntimeException e) {
            throw new PasskeyException(PasskeyException.Code.SIGN_FAILED, e);
        }
        if (built == null) {
            throw new PasskeyException(PasskeyException.Code.SIGN_FAILED, null);
        }
        byte[] data = built.clone();
        if (!boundTo(persisted, data)) {
            throw new PasskeyException(PasskeyException.Code.SIGN_FAILED, null);
        }
        return data;
    }

    /**
     * Whether {@code data} is authenticator data for this record's assertion (WebAuthn §6.1):
     * at least 37 bytes; {@code rpIdHash} = SHA-256 of the record's RP ID, computed here; the
     * user-present flag set; no attested credential data (not allowed in an assertion); trailing
     * bytes exactly when the extension flag is set; and the signature counter equal to the value
     * just persisted. User verification and the extension content are the caller's policy (M6.3).
     */
    private static boolean boundTo(PasskeyRecord persisted, byte[] data) {
        if (data.length < Es256.MIN_AUTHENTICATOR_DATA_BYTES) {
            return false;
        }
        byte[] expectedRp = Hash.sha256(persisted.rpId().getBytes(StandardCharsets.US_ASCII));
        if (!ConstantTime.equals(expectedRp, Arrays.copyOf(data, RP_ID_HASH_BYTES))) {
            return false;
        }
        int flags = data[RP_ID_HASH_BYTES] & BYTE_MASK;
        boolean extensions = (flags & FLAG_ED) != 0;
        if ((flags & FLAG_UP) == 0 || (flags & FLAG_AT) != 0
                || extensions != (data.length > Es256.MIN_AUTHENTICATOR_DATA_BYTES)) {
            return false;
        }
        long counter = 0;
        for (int i = RP_ID_HASH_BYTES + 1; i < Es256.MIN_AUTHENTICATOR_DATA_BYTES; i++) {
            counter = (counter << Byte.SIZE) | (data[i] & BYTE_MASK);
        }
        return counter == persisted.signCount();
    }

    private static PasskeyKey loadKey(PasskeyRecord persisted) throws PasskeyException {
        try {
            return PasskeyStorage.fromStorage(PasskeyRecordAccess.hook().privateKey(persisted));
        } catch (CryptoException e) {
            throw new PasskeyException(PasskeyException.Code.BAD_KEY, e);
        }
    }

    /**
     * The file a restore installs (ADR 0015, ADR 0016 addendum): {@code records} sealed under
     * {@code vk} as the save after {@code header}, with every passkey counter raised to
     * {@code max(backup + margin, existing + 1)}, where {@code existing} is the counter the vault being
     * replaced holds for the same record id (from {@code floors}, if any). A value that would
     * reach 2^32 - 1 becomes 2^32 - 1, which is exhausted: the credential cannot sign again rather
     * than repeat a counter. Never lowered. Takes ownership of {@code records}.
     */
    static byte[] raisedForRestore(EnvelopeHeader header, SecretBytes vk, PayloadCodec codec,
                                   List<VaultRecord> records, long margin, Map<UUID, Long> floors, long now)
            throws VaultException {
        List<VaultRecord> raised = new ArrayList<>(records.size());
        try {
            records.forEach(r -> raised.add(r instanceof PasskeyRecord
                    ? raise(PasskeyRecord.class.cast(r), margin, floors.getOrDefault(r.id(), -1L)) : r));
            EnvelopeHeader next;
            try {
                next = header.nextSave(now);
            } catch (ArithmeticException e) {
                throw new VaultException(VaultException.Code.CORRUPT, e);
            }
            return sealFile(next, vk, codec, raised);
        } finally {
            raised.forEach(VaultRecord::close);
            records.forEach(VaultRecord::close);
        }
    }

    private static VaultRecord raise(PasskeyRecord stored, long margin, long floor) {
        long wanted = Math.max(stored.signCount() + margin, floor + 1);
        long target = Math.min(wanted, PasskeyRecord.MAX_SIGN_COUNT);
        if (target <= stored.signCount()) {
            return PasskeyRecordAccess.hook().edited(stored, stored);
        }
        return PasskeyRecordAccess.hook().advanced(stored, target, stored.lastUsed());
    }

    /** A passkey leaves the vault only as a keyless view; other records as themselves. */
    private static VaultRecord shareable(VaultRecord r) {
        return r instanceof PasskeyRecord ? PasskeyRecordAccess.hook().view(PasskeyRecord.class.cast(r)) : r;
    }

    /** Returns true once {@link #close()} has run. */
    public boolean isLocked() {
        return locked(() -> closed);
    }

    /**
     * Locks the vault: zeroes the VK and closes every held and retired record. Idempotent.
     *
     * @throws IllegalStateException {@code REENTRANT} from inside a {@link #signWithPasskey} port;
     *     the vault stays open and the signature completes. Another thread waits for the lock.
     */
    @Override
    public void close() {
        locked(() -> {
            ensureNotSigning();
            if (!closed) {
                closed = true;
                try (vaultKey) {
                    byId.values().forEach(VaultRecord::close);
                    retired.forEach(VaultRecord::close);
                    byId.clear();
                    retired.clear();
                }
            }
            return null;
        });
    }

    /** Returns the header as last written; used by tests for {@code save_seq}. */
    EnvelopeHeader header() {
        return locked(() -> {
            ensureOpen();
            return currentHeader;
        });
    }

    /**
     * Runs {@code action} on the file as last saved and the VK, under the vault lock so that no
     * save can replace the file meanwhile (ADR 0015 backups). Neither argument may be retained.
     *
     * @throws VaultException {@code LOCKED} after close, {@code STORAGE} if the file cannot be
     *                        read, or whatever {@code action} throws
     */
    <T> T withSavedFile(SavedFileAction<T> action) throws VaultException {
        Objects.requireNonNull(action, "action");
        return locked(() -> {
            if (closed) {
                throw new VaultException(VaultException.Code.LOCKED, null);
            }
            byte[] file;
            try {
                file = store.readAll();
            } catch (StorageException e) {
                throw new VaultException(VaultException.Code.STORAGE, e);
            }
            return action.run(file, vaultKey);
        });
    }

    /** Body of {@link #withSavedFile}. */
    @FunctionalInterface
    interface SavedFileAction<T> {
        /**
         * Uses the saved file and the VK.
         *
         * @param file the saved file, owned by the action
         * @param vk   the vault key; not closed and not retained
         * @return the result
         * @throws VaultException on failure
         */
        T run(byte[] file, SecretBytes vk) throws VaultException;
    }

    /**
     * Derives the per-save data key DK = HKDF-SHA256(VK, dataSalt, "pm/data/v1", 32)
     * (ADR 0004). The caller closes the result.
     */
    static SecretBytes dataKey(SecretBytes vk, byte[] dataSalt) throws CryptoException {
        return Kdf.hkdfSha256(vk, dataSalt, DATA_KEY_INFO.getBytes(StandardCharsets.UTF_8), KEY_LENGTH);
    }

    /**
     * Seals {@code records} as the vault file for header {@code next}: a fresh {@code dataSalt},
     * the AAD, DK = HKDF(VK, dataSalt, "pm/data/v1") and {@code aad ‖ AES-GCM(DK, payload, aad)}.
     */
    private static byte[] sealFile(EnvelopeHeader next, SecretBytes vk, PayloadCodec codec, List<VaultRecord> records)
            throws VaultException {
        byte[] dataSalt = Csprng.bytes(EnvelopeCodec.SALT_LENGTH);
        byte[] aad = EnvelopeCodec.aadOf(EnvelopeCodec.encodeHeader(next), dataSalt);
        byte[] ciphertext;
        try (SecretBytes dk = dataKey(vk, dataSalt);
             SecretBytes plaintext = codec.encode(records)) {
            ciphertext = Aead.sealWithFreshKey(dk, plaintext, aad);
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
        byte[] file = Arrays.copyOf(aad, Math.addExact(aad.length, ciphertext.length));
        System.arraycopy(ciphertext, 0, file, aad.length, ciphertext.length);
        return file;
    }

    /** Runs {@code action} under {@link #lock}; the only place the lock is taken (LCK08-J). */
    private <T, E extends Exception> T locked(LockedAction<T, E> action) throws E {
        lock.lock();
        try {
            return action.run();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Runs {@code action} under {@link #lock}, then {@link #saveLock}, always in that order; the
     * only place the save lock is taken (LCK08-J).
     */
    private <T, E extends Exception> T lockedForSave(LockedAction<T, E> action) throws E {
        return locked(() -> {
            saveLock.lock();
            try {
                return action.run();
            } finally {
                saveLock.unlock();
            }
        });
    }

    /** Body of a locked section; may throw one checked exception type. */
    @FunctionalInterface
    private interface LockedAction<T, E extends Exception> {
        T run() throws E;
    }

    /** Defensive copy of the caller's VK; used inside {@code apply}, so the array is not retained. */
    private static SecretBytes copyKey(byte[] vk) {
        return SecretBytes.copyOf(vk);
    }

    /** Caller holds the lock. */
    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException(LOCKED_MESSAGE);
        }
    }

    /**
     * Caller holds the lock. Inside a {@link #signWithPasskey} port the vault is read-only: the
     * lock is reentrant, so only the signing thread itself can get here while {@code signing}.
     */
    private void ensureNotSigning() {
        if (signing) {
            throw new IllegalStateException(PasskeyException.Code.REENTRANT.name());
        }
    }
}
