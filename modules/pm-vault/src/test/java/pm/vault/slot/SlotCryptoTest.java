package pm.vault.slot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.KdfHeader;

/** ADR 0004 slot KEK derivation. */
final class SlotCryptoTest {

    private static final UUID SLOT_A = new UUID(1L, 1L);
    private static final UUID SLOT_B = new UUID(2L, 2L);

    @Test
    void passphraseKekIsDeterministicFor32Bytes() throws CryptoException {
        try (SecretChars pw = chars("correct horse battery staple");
             SecretBytes k1 = SlotCrypto.kekFromPassphrase(pw, kdf(), SLOT_A);
             SecretBytes k2 = SlotCrypto.kekFromPassphrase(pw, kdf(), SLOT_A)) {
            assertEquals(SlotCrypto.KEK_LENGTH, k1.length());
            assertEquals(k1, k2);
            assertEquals(28, pw.length(), "caller keeps ownership of pw");
        }
    }

    @Test
    void slotUuidSeparatesKeksFromTheSameInput() throws CryptoException {
        try (SecretChars pw = chars("same input");
             SecretBytes a = SlotCrypto.kekFromPassphrase(pw, kdf(), SLOT_A);
             SecretBytes b = SlotCrypto.kekFromPassphrase(pw, kdf(), SLOT_B)) {
            assertNotEquals(a, b);
        }
        try (SecretBytes rk = SecretBytes.copyOf(new byte[32]);
             SecretBytes a = SlotCrypto.kekFromRecovery(rk, SLOT_A);
             SecretBytes b = SlotCrypto.kekFromRecovery(rk, SLOT_B)) {
            assertNotEquals(a, b);
        }
    }

    @Test
    void differentPassphrasesGiveDifferentKeks() throws CryptoException {
        try (SecretChars pw1 = chars("first");
             SecretChars pw2 = chars("second");
             SecretBytes a = SlotCrypto.kekFromPassphrase(pw1, kdf(), SLOT_A);
             SecretBytes b = SlotCrypto.kekFromPassphrase(pw2, kdf(), SLOT_A)) {
            assertNotEquals(a, b);
        }
    }

    @Test
    void kdfSaltChangesTheKek() throws CryptoException {
        byte[] otherSalt = new byte[EnvelopeCodec.SALT_LENGTH];
        Arrays.fill(otherSalt, (byte) 0x77);
        Argon2Params f = Argon2Params.FLOOR;
        KdfHeader other = new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB(), f.iterations(), f.parallelism(), otherSalt);
        try (SecretChars pw = chars("pw");
             SecretBytes a = SlotCrypto.kekFromPassphrase(pw, kdf(), SLOT_A);
             SecretBytes b = SlotCrypto.kekFromPassphrase(pw, other, SLOT_A)) {
            assertNotEquals(a, b);
        }
    }

    @Test
    void recoveryKekIs32BytesAndLeavesInputOpen() throws CryptoException {
        try (SecretBytes rk = SecretBytes.copyOf(new byte[32]);
             SecretBytes kek = SlotCrypto.kekFromRecovery(rk, SLOT_A)) {
            assertEquals(SlotCrypto.KEK_LENGTH, kek.length());
            assertFalse(rk.isClosed());
        }
    }

    @Test
    void outOfRangeHeaderParamsAreBadParams() {
        KdfHeader belowFloor = new KdfHeader(EnvelopeCodec.KDF_ALG, 8, 1, 1, new byte[EnvelopeCodec.SALT_LENGTH]);
        try (SecretChars pw = chars("pw")) {
            CryptoException e = assertThrows(CryptoException.class, () -> kek(pw, belowFloor));
            assertEquals(CryptoException.Code.BAD_PARAMS, e.code());
            assertEquals("BAD_PARAMS", e.getMessage());
        }
    }

    private static SecretBytes kek(SecretChars pw, KdfHeader k) throws CryptoException {
        return SlotCrypto.kekFromPassphrase(pw, k, SLOT_A);
    }

    private static KdfHeader kdf() {
        Argon2Params f = Argon2Params.FLOOR;
        return new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB(), f.iterations(), f.parallelism(),
                new byte[EnvelopeCodec.SALT_LENGTH]);
    }

    private static SecretChars chars(String s) {
        return SecretChars.takeOwnership(s.toCharArray());
    }
}
