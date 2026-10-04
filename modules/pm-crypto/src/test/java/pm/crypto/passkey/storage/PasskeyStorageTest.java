package pm.crypto.passkey.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.crypto.passkey.PasskeyKey;

/** The vault-only storage form API (ADR 0016, SR-080, SR-081). */
class PasskeyStorageTest {
    private static final byte[] AUTH_DATA = new byte[37];
    private static final byte[] CLIENT_DATA_HASH = new byte[32];

    @Test
    void roundTripsThroughThePublicApi() throws CryptoException {
        try (PasskeyKey key = PasskeyKey.generate(); SecretBytes stored = PasskeyStorage.toStorage(key);
                PasskeyKey back = PasskeyStorage.fromStorage(stored)) {
            assertEquals(PasskeyStorage.STORAGE_BYTES, stored.length());
            assertArrayEquals(key.publicPoint(), back.publicPoint());
            assertArrayEquals(key.sign(AUTH_DATA, CLIENT_DATA_HASH), back.sign(AUTH_DATA, CLIENT_DATA_HASH));
            assertFalse(stored.isClosed());
        }
    }

    @Test
    void invalidFormsAndClosedKeysAreRefused() {
        try (SecretBytes zeros = SecretBytes.copyOf(new byte[PasskeyStorage.STORAGE_BYTES])) {
            CryptoException e = assertThrows(CryptoException.class, () -> PasskeyStorage.fromStorage(zeros));
            assertEquals(CryptoException.Code.BAD_INPUT, e.code());
        }
        PasskeyKey[] held = new PasskeyKey[1];
        try (PasskeyKey key = PasskeyKey.generate()) {
            held[0] = key;
        }
        assertThrows(IllegalStateException.class, () -> PasskeyStorage.toStorage(held[0]));
        assertThrows(NullPointerException.class, () -> PasskeyStorage.toStorage(null));
        assertThrows(NullPointerException.class, () -> PasskeyStorage.fromStorage(null));
    }
}
