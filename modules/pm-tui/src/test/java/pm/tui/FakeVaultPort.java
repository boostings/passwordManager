package pm.tui;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/** In-memory {@link VaultPort} for headless TUI tests (Lane C is scaffolding in M1). */
final class FakeVaultPort implements VaultPort {
    static final Instant T0 = Instant.parse("2026-10-01T12:00:00Z");
    /** A record secret that must never reach the screen (SR-503). */
    static final String LOGIN_SECRET = "hunter2-LOGIN-SECRET";
    static final String WIFI_SECRET = "wifi-SECRET-psk";

    private final char[] expectedPassphrase;
    private final char[] expectedRecovery;
    private final List<FakeSession> opened = new ArrayList<>();
    private int attempts;

    FakeVaultPort(String expectedPassphrase, String expectedRecovery) {
        this.expectedPassphrase = expectedPassphrase.toCharArray();
        this.expectedRecovery = expectedRecovery.toCharArray();
    }

    @Override
    public CreatedSession create(SecretChars passphrase) throws VaultException {
        throw new VaultException(VaultException.Code.ALREADY_EXISTS, null);
    }

    @Override
    public Session unlockWithPassphrase(SecretChars passphrase) throws VaultException {
        return open(passphrase, expectedPassphrase);
    }

    @Override
    public Session unlockWithRecoveryKey(SecretChars recoveryKey) throws VaultException {
        return open(recoveryKey, expectedRecovery);
    }

    private Session open(SecretChars given, char[] expected) throws VaultException {
        attempts++;
        boolean[] match = new boolean[1];
        given.withChars(chars -> match[0] = sameChars(chars, expected));
        if (!match[0]) {
            throw new VaultException(VaultException.Code.WRONG_CREDENTIAL, null);
        }
        FakeSession s = new FakeSession();
        opened.add(s);
        return s;
    }

    /** Length-independent comparison, in the spirit of SR-016 even in a fake. */
    private static boolean sameChars(char[] given, char[] expected) {
        int diff = given.length ^ expected.length;
        for (int i = 0; i < Math.min(given.length, expected.length); i++) {
            diff |= given[i] ^ expected[i];
        }
        return diff == 0;
    }

    /** Number of unlock attempts, successful or not. */
    int attemptCount() {
        return attempts;
    }

    /** Sessions opened so far, oldest first. */
    List<FakeSession> openedSessions() {
        return opened;
    }

    /** The most recently opened session. */
    FakeSession last() {
        return opened.get(opened.size() - 1);
    }

    /** In-memory session pre-loaded with one login, one Wi-Fi and one SSH record. */
    static final class FakeSession implements Session {
        private final Map<UUID, VaultRecord> byId = new LinkedHashMap<>();
        private final List<String> queries = new ArrayList<>();
        private int saves;
        private boolean locked;
        private VaultException.Code failSaveWith;

        FakeSession() {
            add(new LoginRecord(UUID.randomUUID(), "GitHub", "octocat", secret(LOGIN_SECRET),
                    List.of("https://github.com"), "", List.of("dev"), T0, T0, T0));
            add(new WifiRecord(UUID.randomUUID(), "Home WiFi", "HomeNet", "WPA3",
                    secret(WIFI_SECRET), false, "", T0, T0));
            add(new SshKeyRecord(UUID.randomUUID(), "Deploy key", "ed25519", secret("ssh-SECRET"),
                    "ssh-ed25519 AAAA", "SHA256:abc", "", List.of("example.org"), T0, T0));
        }

        private void add(VaultRecord r) {
            byId.put(r.id(), r);
        }

        private static SecretBytes secret(String value) {
            return SecretBytes.copyOf(value.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public List<VaultRecord> records() {
            return List.copyOf(byId.values());
        }

        @Override
        public List<VaultRecord> search(String query) {
            queries.add(query);
            String q = query.toLowerCase(Locale.ROOT);
            return byId.values().stream().filter(r -> matches(r, q)).toList();
        }

        private static boolean matches(VaultRecord r, String q) {
            List<String> fields = new ArrayList<>(DashboardWindow.row(r));
            return fields.stream().anyMatch(f -> f.toLowerCase(Locale.ROOT).contains(q));
        }

        @Override
        public void put(VaultRecord r) {
            add(r);
        }

        @Override
        public boolean remove(UUID id) {
            return byId.remove(id) != null;
        }

        @Override
        public void save() throws VaultException {
            saves++;
            if (failSaveWith != null) {
                throw new VaultException(failSaveWith, null);
            }
        }

        @Override
        public boolean isLocked() {
            return locked;
        }

        @Override
        public void close() {
            locked = true;
        }

        /** Makes every later {@link #save()} fail with {@code code}. */
        void failSaves(VaultException.Code code) {
            failSaveWith = code;
        }

        int saveCount() {
            return saves;
        }

        List<String> searchQueries() {
            return queries;
        }
    }
}
