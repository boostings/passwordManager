package pm.vault;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
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
 * another thread cannot interleave with a save or edit.
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

    private final ReentrantLock lock = new ReentrantLock();
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
     */
    public void put(VaultRecord r) {
        Objects.requireNonNull(r, "r");
        locked(() -> {
            ensureOpen();
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
     */
    public boolean remove(UUID id) {
        Objects.requireNonNull(id, "id");
        return locked(() -> {
            ensureOpen();
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
     * Encrypts the records under a fresh data key and writes the vault. Steps: new
     * {@code dataSalt}; {@code saved = clock}; {@code save_seq + 1}; encode the header;
     * compute the AAD; derive DK = HKDF(VK, dataSalt, "pm/data/v1"); seal; then
     * {@code store.backup()} and {@code store.writeAtomically}. The in-memory header changes
     * only after the write succeeds (ERR03-J).
     *
     * @throws VaultException {@code LOCKED} after close, {@code STORAGE} if the write fails,
     *                        {@code CORRUPT} if the save counter is exhausted or sealing fails
     */
    public void save() throws VaultException {
        persist(true);
    }

    /**
     * {@link #save()}, rotating the {@code .bak.N} generations only if {@code rotateBackups}. A
     * passkey counter advance alone does not rotate them, so signing in does not push the user's
     * recovery points out (ADR 0016 addendum).
     */
    private void persist(boolean rotateBackups) throws VaultException {
        locked(() -> {
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
                if (exists && rotateBackups) {
                    store.backup();
                }
                store.writeAtomically(file);
            } catch (StorageException e) {
                throw new VaultException(VaultException.Code.STORAGE, e);
            }
            currentHeader = next;
            contentChanged = false;
            return null;
        });
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
     * released. A value whose save failed stays in memory and is never handed out again. A call
     * from inside {@code port} on the same thread is refused with {@code REENTRANT}, so signing
     * order is always counter order.
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

    /** Locks the vault: zeroes the VK and closes every held and retired record. Idempotent. */
    @Override
    public void close() {
        locked(() -> {
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
}
