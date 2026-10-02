package pm.cli;

import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.Argon2Params;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.tui.CreatedSession;
import pm.tui.Session;
import pm.tui.VaultPort;
import pm.tui.VaultServiceAdapter;
import pm.vault.VaultException;
import pm.vault.VaultService;
import pm.vault.record.VaultRecord;

/**
 * Production {@link VaultPort} for one vault path: each create/unlock opens a
 * {@link VaultFileStore} (taking its exclusive lock, ADR 0003), delegates to
 * {@link VaultServiceAdapter}, and releases the store when the session closes. Storage failures
 * surface as {@link VaultException} codes only (SR-501). Confined to one thread.
 */
final class FileVaultPort implements VaultPort {
    private final Path vaultFile;
    private final Clock clock;
    private final Argon2Params kdf;

    FileVaultPort(Path vaultFile, Clock clock, Argon2Params kdf) {
        this.vaultFile = Objects.requireNonNull(vaultFile, "vaultFile");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.kdf = Objects.requireNonNull(kdf, "kdf");
    }

    @Override
    public CreatedSession create(SecretChars passphrase) throws VaultException {
        VaultFileStore store = openStore();
        try {
            CreatedSession created = adapter(store).create(passphrase);
            return new CreatedSession(new StoreSession(created.session(), store), created.recoveryKey());
        } catch (VaultException | RuntimeException e) {
            store.close();
            throw e;
        }
    }

    @Override
    public Session unlockWithPassphrase(SecretChars passphrase) throws VaultException {
        VaultFileStore store = openStore();
        try {
            return new StoreSession(adapter(store).unlockWithPassphrase(passphrase), store);
        } catch (VaultException | RuntimeException e) {
            store.close();
            throw e;
        }
    }

    @Override
    public Session unlockWithRecoveryKey(SecretChars recoveryKey) throws VaultException {
        VaultFileStore store = openStore();
        try {
            return new StoreSession(adapter(store).unlockWithRecoveryKey(recoveryKey), store);
        } catch (VaultException | RuntimeException e) {
            store.close();
            throw e;
        }
    }

    private VaultServiceAdapter adapter(VaultFileStore store) {
        return new VaultServiceAdapter(new VaultService(store, clock, kdf));
    }

    private VaultFileStore openStore() throws VaultException {
        try {
            return VaultFileStore.open(vaultFile);
        } catch (StorageException e) {
            throw new VaultException(vaultCode(e.code()), e);
        }
    }

    /** Lock contention keeps its own code; every other storage failure is {@code STORAGE}. */
    static VaultException.Code vaultCode(StorageException.Code code) {
        return switch (code) {
            case LOCKED_BY_OTHER -> VaultException.Code.LOCKED;
            case NOT_FOUND, TOO_LARGE, SYMLINK_REFUSED, PERMISSIONS, IO -> VaultException.Code.STORAGE;
        };
    }

    /** Session that also releases the file store, and with it the vault lock, on close. */
    private static final class StoreSession implements Session {
        private final Session delegate;
        private final VaultFileStore store;

        StoreSession(Session delegate, VaultFileStore store) {
            this.delegate = Objects.requireNonNull(delegate, "delegate");
            this.store = Objects.requireNonNull(store, "store");
        }

        @Override
        public List<VaultRecord> records() {
            return delegate.records();
        }

        @Override
        public List<VaultRecord> search(String query) {
            return delegate.search(query);
        }

        @Override
        public void put(VaultRecord r) {
            delegate.put(r);
        }

        @Override
        public boolean remove(UUID id) {
            return delegate.remove(id);
        }

        @Override
        public void save() throws VaultException {
            delegate.save();
        }

        @Override
        public boolean isLocked() {
            return delegate.isLocked();
        }

        @Override
        public void close() {
            try (store) {
                delegate.close();
            }
        }
    }
}
