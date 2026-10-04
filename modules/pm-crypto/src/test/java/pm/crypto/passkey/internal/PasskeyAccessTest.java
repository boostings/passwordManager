package pm.crypto.passkey.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.crypto.passkey.PasskeyKey;

/** The storage hook is installed once, by PasskeyKey, and cannot be replaced (ADR 0016). */
class PasskeyAccessTest {
    @Test
    void theCodecIsInstalledByPasskeyKeyAndCannotBeReplaced() {
        PasskeyAccess.Storage codec = PasskeyAccess.storage();
        assertNotNull(codec);
        PasskeyAccess.Storage rogue = new PasskeyAccess.Storage() {
            @Override
            public SecretBytes toStorage(PasskeyKey key) {
                return SecretBytes.copyOf(new byte[1]);
            }

            @Override
            public PasskeyKey fromStorage(SecretBytes stored) throws CryptoException {
                throw new CryptoException(CryptoException.Code.INTERNAL);
            }
        };
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> PasskeyAccess.install(rogue));
        assertEquals("ALREADY_INSTALLED", e.getMessage());
        assertSame(codec, PasskeyAccess.storage());
    }
}
