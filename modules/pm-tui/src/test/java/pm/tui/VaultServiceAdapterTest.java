package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.VaultException;
import pm.vault.VaultService;

/** The production session's passphrase change (M7.8) against a real vault file. */
class VaultServiceAdapterTest {
    private static final String FIRST = "first passphrase 0123";
    private static final String SECOND = "second passphrase 4567";

    @TempDir
    Path dir;

    private static SecretChars chars(String s) {
        return SecretChars.takeOwnership(s.toCharArray());
    }

    @Test
    void theChangeNeedsTheCurrentPassphraseOrTheRecoveryKey() throws IOException, VaultException, StorageException {
        try (VaultFileStore store = VaultFileStore.open(dir.resolve("vault.pmv"))) {
            VaultServiceAdapter port = new VaultServiceAdapter(new VaultService(store, Clock.systemUTC(),
                    Argon2Params.FLOOR));
            CreatedSession created;
            try (SecretChars pw = chars(FIRST)) {
                created = port.create(pw);
            }
            String[] recovery = new String[1];
            try (Session session = created.session(); SecretChars rk = created.recoveryKey();
                    SecretChars wrong = chars("not the passphrase"); SecretChars fresh = chars(SECOND)) {
                rk.withChars(c -> recovery[0] = String.valueOf(c));
                VaultException refused = assertThrows(VaultException.class,
                        () -> session.changePassphrase(wrong, fresh));
                assertEquals(VaultException.Code.WRONG_CREDENTIAL, refused.code());
                try (SecretChars current = chars(FIRST)) {
                    session.changePassphrase(current, fresh);
                }
                try (SecretChars byRecovery = chars(recovery[0]); SecretChars back = chars(FIRST)) {
                    session.changePassphrase(byRecovery, back);
                }
            }
            try (SecretChars pw = chars(FIRST); Session reopened = port.unlockWithPassphrase(pw)) {
                assertEquals(0, reopened.records().size());
            }
            try (SecretChars old = chars(SECOND)) {
                assertEquals(VaultException.Code.WRONG_CREDENTIAL,
                        assertThrows(VaultException.class, () -> port.unlockWithPassphrase(old)).code());
            }
        }
    }
}
