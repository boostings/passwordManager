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
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.Kdf;
import pm.crypto.SecretBytes;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.EnvelopeHeader;
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
 * <p><b>Locked state (OBJ14-J).</b> {@code close()} is the lock operation. It zeroes the VK,
 * closes every record and is idempotent. Afterwards {@link #save()} throws
 * {@link VaultException} with code {@code LOCKED}. Every other method except
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

    /** Returns an unmodifiable snapshot of the records in insertion order. */
    public List<VaultRecord> records() {
        return locked(() -> {
            ensureOpen();
            return List.copyOf(byId.values());
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
                    hits.add(r);
                }
            }
            return List.copyOf(hits);
        });
    }

    /**
     * Inserts {@code r}, or replaces the record with the same id. The vault takes ownership
     * of {@code r}; the replaced record is closed when the vault locks. Changes reach disk on
     * {@link #save()}.
     *
     * @param r record to store
     */
    public void put(VaultRecord r) {
        Objects.requireNonNull(r, "r");
        locked(() -> {
            ensureOpen();
            Optional.ofNullable(byId.put(r.id(), r)).ifPresent(retired::add);
            return null;
        });
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
            byte[] dataSalt = Csprng.bytes(EnvelopeCodec.SALT_LENGTH);
            byte[] aad = EnvelopeCodec.aadOf(EnvelopeCodec.encodeHeader(next), dataSalt);
            byte[] file = seal(aad, dataSalt);
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
                if (exists) {
                    store.backup();
                }
                store.writeAtomically(file);
            } catch (StorageException e) {
                throw new VaultException(VaultException.Code.STORAGE, e);
            }
            currentHeader = next;
            return null;
        });
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
     * Derives the per-save data key DK = HKDF-SHA256(VK, dataSalt, "pm/data/v1", 32)
     * (ADR 0004). The caller closes the result.
     */
    static SecretBytes dataKey(SecretBytes vk, byte[] dataSalt) throws CryptoException {
        return Kdf.hkdfSha256(vk, dataSalt, DATA_KEY_INFO.getBytes(StandardCharsets.UTF_8), KEY_LENGTH);
    }

    /** Returns {@code aad ‖ AES-GCM(DK, payload, aad)}, which is the complete file. Caller holds the lock. */
    private byte[] seal(byte[] aad, byte[] dataSalt) throws VaultException {
        byte[] ciphertext;
        try (SecretBytes dk = dataKey(vaultKey, dataSalt);
             SecretBytes plaintext = codec.encode(List.copyOf(byId.values()))) {
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
