package pm.vault.record;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import pm.crypto.SecretBytes;
import pm.crypto.passkey.PasskeyKey;
import pm.crypto.passkey.storage.PasskeyStorage;

/** Passkey records for the record and vault tests. Every factory returns a record the caller owns. */
public final class PasskeyFixtures {
    /** Creation time of every fixture record. */
    public static final Instant T0 = Instant.parse("2026-10-02T12:00:00Z");
    private static final byte[] CREDENTIAL_ID = filled(32, 0x5a);
    private static final byte[] USER_HANDLE = filled(8, 0x33);

    private PasskeyFixtures() {
    }

    /** A copy of the fixture credential ID (32 bytes). */
    public static byte[] credentialId() {
        return CREDENTIAL_ID.clone();
    }

    /** A copy of the fixture user handle (8 bytes). */
    public static byte[] userHandle() {
        return USER_HANDLE.clone();
    }

    /** A record for {@code key} with counter {@code signCount}. */
    public static PasskeyRecord passkey(UUID id, PasskeyKey key, long signCount) {
        return new PasskeyRecord(id, "Example", "example.com", CREDENTIAL_ID, USER_HANDLE, "alice@example.com",
                "Alice", PasskeyStorage.toStorage(key), signCount, T0, T0, T0);
    }

    /** A record for a freshly generated key, with counter 0. */
    public static PasskeyRecord passkey(String id) {
        try (PasskeyKey key = PasskeyKey.generate()) {
            return passkey(UUID.fromString(id), key, 0);
        }
    }

    /** A record whose stored key is 98 bytes but not a valid storage form. */
    public static PasskeyRecord withBrokenKey(UUID id) {
        return new PasskeyRecord(id, "Broken", "example.com", CREDENTIAL_ID, USER_HANDLE, "bob", "Bob",
                SecretBytes.takeOwnership(new byte[PasskeyRecord.PRIVATE_KEY_BYTES]), 0, T0, T0, T0);
    }

    /** A copy of the record's storage form, for tests that check zero-filling. */
    static byte[] storedKey(PasskeyRecord record) {
        return record.privateKey().apply(bytes -> Arrays.copyOf(bytes, bytes.length));
    }

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }
}
