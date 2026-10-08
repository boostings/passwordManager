package pm.cli;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.tui.CreatedSession;
import pm.tui.Session;
import pm.tui.VaultPort;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;

/** In-memory {@link VaultPort}: one vault, passphrase kept as {@link SecretBytes}. */
final class FakeVaultPort implements VaultPort {
    static final String RECOVERY_KEY = "RK-AAAA-BBBB-CCCC-DDDD";

    final List<VaultRecord> stored = new ArrayList<>();
    private SecretBytes passphraseUtf8;
    private VaultException.Code failure;
    private boolean bug;
    private boolean refusePut;
    final List<VaultRecord> refused = new ArrayList<>();
    int saves;
    int creates;
    private FakeSession lastSession;
    private SecretChars lastRecoveryKey;

    /** Pre-creates a vault with {@code passphrase}. */
    FakeVaultPort withVault(String passphrase) {
        passphraseUtf8 = SecretBytes.copyOf(passphrase.getBytes(StandardCharsets.UTF_8));
        return this;
    }

    /** Every create/unlock fails with {@code code}. */
    FakeVaultPort failing(VaultException.Code code) {
        failure = code;
        return this;
    }

    /** Every create/unlock throws an unexpected {@link IllegalStateException}, as a bug would. */
    FakeVaultPort buggy() {
        bug = true;
        return this;
    }

    /** {@link Session#put} throws {@link IllegalStateException}; the offered record is kept in {@link #refused}. */
    FakeVaultPort refusingPut() {
        refusePut = true;
        return this;
    }

    FakeSession session() {
        return Objects.requireNonNull(lastSession, "no session opened");
    }

    SecretChars recoveryKey() {
        return Objects.requireNonNull(lastRecoveryKey, "no vault created");
    }

    boolean exists() {
        return passphraseUtf8 != null;
    }

    @Override
    public CreatedSession create(SecretChars passphrase) throws VaultException {
        failIfConfigured();
        if (exists()) {
            throw new VaultException(VaultException.Code.ALREADY_EXISTS, null);
        }
        creates++;
        passphraseUtf8 = passphrase.toUtf8();
        lastSession = new FakeSession();
        lastRecoveryKey = SecretChars.takeOwnership(RECOVERY_KEY.toCharArray());
        return new CreatedSession(lastSession, lastRecoveryKey);
    }

    @Override
    public Session unlockWithPassphrase(SecretChars passphrase) throws VaultException {
        failIfConfigured();
        if (!exists()) {
            throw new VaultException(VaultException.Code.STORAGE, null);
        }
        try (SecretBytes typed = passphrase.toUtf8()) {
            if (!typed.equals(passphraseUtf8)) {
                throw new VaultException(VaultException.Code.WRONG_CREDENTIAL, null);
            }
        }
        lastSession = new FakeSession();
        return lastSession;
    }

    @Override
    public Session unlockWithRecoveryKey(SecretChars recoveryKey) throws VaultException {
        throw new VaultException(VaultException.Code.WRONG_CREDENTIAL, null);
    }

    private void failIfConfigured() throws VaultException {
        if (bug) {
            throw new IllegalStateException("internal detail " + MainArgsTest.CANARY);
        }
        if (failure != null) {
            throw new VaultException(failure, null);
        }
    }

    /** Session over {@link #stored}. */
    final class FakeSession implements Session {
        private boolean locked;

        @Override
        public List<VaultRecord> records() {
            return List.copyOf(stored);
        }

        @Override
        public List<VaultRecord> search(String query) {
            String q = query.toLowerCase(Locale.ROOT);
            return stored.stream().filter(r -> r.title().toLowerCase(Locale.ROOT).contains(q)).toList();
        }

        @Override
        public void put(VaultRecord r) {
            if (refusePut) {
                refused.add(r);
                throw new IllegalStateException("vault is locked");
            }
            stored.removeIf(old -> old.id().equals(r.id()));
            stored.add(r);
        }

        @Override
        public boolean remove(UUID id) {
            return stored.removeIf(r -> r.id().equals(id));
        }

        @Override
        public void save() {
            saves++;
        }

        @Override
        public void changePassphrase(SecretChars current, SecretChars fresh) {
            throw new UnsupportedOperationException("the CLI changes passphrases through VaultService");
        }

        @Override
        public boolean isLocked() {
            return locked;
        }

        @Override
        public void close() {
            locked = true;
        }
    }

    /** A stored login for list/search tests. */
    static LoginRecord login(String title, String secretValue, java.time.Instant at) {
        return new LoginRecord(UUID.randomUUID(), title, "alice",
                SecretBytes.copyOf(secretValue.getBytes(StandardCharsets.UTF_8)), List.of(), "", List.of(), at, at, at);
    }
}
