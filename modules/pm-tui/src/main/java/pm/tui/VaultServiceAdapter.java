package pm.tui;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretChars;
import pm.vault.CreatedVault;
import pm.vault.Vault;
import pm.vault.VaultException;
import pm.vault.VaultService;
import pm.vault.record.VaultRecord;

/**
 * Production {@link VaultPort}: thin delegation to {@link VaultService} and {@link Vault}
 * (ADR 0003, ADR 0004). Holds no secrets of its own.
 */
public final class VaultServiceAdapter implements VaultPort {
    private final VaultService service;

    /** Wraps {@code service}. */
    public VaultServiceAdapter(VaultService service) {
        this.service = Objects.requireNonNull(service, "service");
    }

    @Override
    public CreatedSession create(SecretChars passphrase) throws VaultException {
        CreatedVault created = service.create(passphrase);
        return new CreatedSession(new VaultSession(service, created.vault()), created.recoveryKey());
    }

    @Override
    public Session unlockWithPassphrase(SecretChars passphrase) throws VaultException {
        return new VaultSession(service, service.unlockWithPassphrase(passphrase));
    }

    @Override
    public Session unlockWithRecoveryKey(SecretChars recoveryKey) throws VaultException {
        return new VaultSession(service, service.unlockWithRecoveryKey(recoveryKey));
    }

    /** {@link Session} backed by a real {@link Vault}. */
    private static final class VaultSession implements Session {
        private final VaultService service;
        private final Vault vault;

        VaultSession(VaultService service, Vault vault) {
            this.service = service;
            this.vault = Objects.requireNonNull(vault, "vault");
        }

        @Override
        public List<VaultRecord> records() {
            return vault.records();
        }

        @Override
        public List<VaultRecord> search(String query) {
            return vault.search(query);
        }

        @Override
        public void put(VaultRecord r) {
            vault.put(r);
        }

        @Override
        public boolean remove(UUID id) {
            return vault.remove(id);
        }

        @Override
        public void save() throws VaultException {
            vault.save();
        }

        /**
         * Opens the file once more with {@code current} to check it, the cheap recovery-key parse
         * first, then the passphrase (one Argon2id run), and closes that copy at once.
         */
        @Override
        public void changePassphrase(SecretChars current, SecretChars fresh) throws VaultException {
            try {
                service.unlockWithRecoveryKey(current).close();
            } catch (VaultException notTheRecoveryKey) {
                if (notTheRecoveryKey.code() != VaultException.Code.WRONG_CREDENTIAL) {
                    throw notTheRecoveryKey;
                }
                service.unlockWithPassphrase(current).close();
            }
            service.changePassphrase(vault, fresh);
        }

        @Override
        public boolean isLocked() {
            return vault.isLocked();
        }

        @Override
        public void close() {
            vault.close();
        }
    }
}
