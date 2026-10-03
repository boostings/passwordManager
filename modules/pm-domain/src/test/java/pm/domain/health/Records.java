package pm.domain.health;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import pm.crypto.SecretBytes;
import pm.vault.record.LoginRecord;
import pm.vault.record.WifiRecord;

/** Test record factories. Passwords are obviously fake sample data (SR-800). */
final class Records {
    private Records() {
    }

    static UUID id(int n) {
        return new UUID(0x5EED, n);
    }

    static SecretBytes secret(String s) {
        return SecretBytes.copyOf(s.getBytes(StandardCharsets.UTF_8));
    }

    static LoginRecord login(int n, String password, Instant updated) {
        return new LoginRecord(id(n), "site " + n, "user", secret(password), List.of(), "", List.of(),
                updated, updated, updated);
    }

    static WifiRecord wifi(int n, String security, String password, Instant updated) {
        return new WifiRecord(id(n), "net " + n, "ssid", security, secret(password), false, "", updated, updated);
    }
}
