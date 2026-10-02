package pm.vault.slot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.Kdf;
import pm.crypto.KeyWrap;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.KdfHeader;

/**
 * A3b / SR-051: a wrong passphrase pays the full Argon2id cost of the header, exactly like the
 * right one, and only then fails at AES-KWP unwrap with the same code a tampered wrapped key gives.
 *
 * <p>Slot-level proof. {@code VaultService.unlockWithPassphrase} maps that unwrap
 * {@code AUTH_FAILED} to {@code WRONG_CREDENTIAL} for both cases; it needs Lane B/D storage and
 * codec to run end to end, so this test stops at the KWP boundary.
 */
final class SlotCryptoWorkFactorTest {

    private static final UUID SLOT = new UUID(3L, 3L);
    private static final String RIGHT = "correct horse battery staple";
    private static final List<String> WRONG = List.of("x", "correct horse battery stapl", "Z".repeat(200));
    private static final int VK_LENGTH = 32;
    private static final int TIMING_RUNS = 3;
    private static final double MIN_TIME_RATIO = 0.5;

    /** One observed Argon2id call; recorded only after the real KDF returned. */
    private record Call(int memoryKiB, int iterations, int parallelism, List<Byte> salt) {
    }

    /** Delegates to the real {@link Kdf#argon2id} and records each completed call. */
    private static final class Recorder implements SlotCrypto.Stretcher {
        private final List<Call> calls = new ArrayList<>();
        private int started;

        @Override
        public SecretBytes argon2id(SecretBytes password, byte[] salt32, Argon2Params params) throws CryptoException {
            started++;
            SecretBytes out = Kdf.argon2id(password, salt32, params);
            calls.add(new Call(params.memoryKiB(), params.iterations(), params.parallelism(), boxed(salt32)));
            return out;
        }
    }

    @Test
    void wrongPassphraseRunsArgon2idOnceWithTheHeaderParamsLikeTheRightOne() throws CryptoException {
        KdfHeader header = nonDefaultHeader();
        Call expected = new Call(header.m(), header.t(), header.p(), boxed(header.salt()));

        Recorder right = new Recorder();
        try (SecretChars pw = chars(RIGHT);
             SecretBytes kek = SlotCrypto.kekFromPassphrase(pw, header, SLOT, right)) {
            assertEquals(SlotCrypto.KEK_LENGTH, kek.length());
        }
        assertEquals(List.of(expected), right.calls, "right passphrase: one full Argon2id with header params");
        assertEquals(1, right.started);

        for (String wrong : WRONG) {
            Recorder rec = new Recorder();
            try (SecretChars pw = chars(wrong);
                 SecretBytes kek = SlotCrypto.kekFromPassphrase(pw, header, SLOT, rec)) {
                assertEquals(SlotCrypto.KEK_LENGTH, kek.length(), "slot layer cannot tell wrong from right");
            }
            assertEquals(1, rec.started, "wrong passphrase: Argon2id entered exactly once");
            assertEquals(right.calls, rec.calls, "wrong passphrase: same completed work as the right one");
        }
    }

    @Test
    void seamIsThePublicPath() throws CryptoException {
        KdfHeader header = floorHeader();
        try (SecretChars pw = chars(RIGHT);
             SecretBytes viaPublic = SlotCrypto.kekFromPassphrase(pw, header, SLOT);
             SecretBytes viaSeam = SlotCrypto.kekFromPassphrase(pw, header, SLOT, new Recorder())) {
            assertEquals(viaPublic, viaSeam, "public method must route through the same Argon2id step");
        }
    }

    @Test
    void wrongPassphraseFailsOnlyAtUnwrapWithTheTamperedWrapCode() throws CryptoException {
        KdfHeader header = floorHeader();
        byte[] wrapped;
        try (SecretChars pw = chars(RIGHT);
             SecretBytes kek = SlotCrypto.kekFromPassphrase(pw, header, SLOT);
             SecretBytes vk = SecretBytes.copyOf(pattern(VK_LENGTH, 0x5A))) {
            wrapped = KeyWrap.wrap(kek, vk);
            try (SecretBytes back = KeyWrap.unwrap(kek, wrapped)) {
                assertEquals(vk, back, "right passphrase unwraps the VK");
            }
            byte[] tampered = wrapped.clone();
            tampered[tampered.length - 1] ^= 0x01;
            CryptoException tamper = assertThrows(CryptoException.class, () -> unwrapClosing(kek, tampered));
            assertEquals(CryptoException.Code.AUTH_FAILED, tamper.code());
        }

        Recorder rec = new Recorder();
        try (SecretChars pw = chars(WRONG.get(1));
             SecretBytes kek = SlotCrypto.kekFromPassphrase(pw, header, SLOT, rec)) {
            assertEquals(1, rec.calls.size(), "Argon2id completed before any unwrap is attempted");
            CryptoException wrong = assertThrows(CryptoException.class, () -> unwrapClosing(kek, wrapped));
            assertEquals(CryptoException.Code.AUTH_FAILED, wrong.code(),
                    "same code as a tampered wrap; VaultService maps both to WRONG_CREDENTIAL");
            assertEquals("AUTH_FAILED", wrong.getMessage());
        }
    }

    /**
     * Timing sanity, not a side-channel proof: both paths do identical Argon2id work, so the
     * best-of-3 wrong time must not be far below the best-of-3 right time.
     */
    @Test
    void wrongPassphraseIsNotMeasurablyFasterThanTheRightOne() throws CryptoException {
        KdfHeader header = floorHeader();
        long right = bestOf(RIGHT, header);
        long wrong = bestOf(WRONG.get(1), header);
        assertTrue(wrong >= MIN_TIME_RATIO * right,
                () -> "wrong " + wrong + " ns vs right " + right + " ns");
    }

    @Test
    void outOfRangeHeaderNeverReachesArgon2id() {
        KdfHeader belowFloor = new KdfHeader(EnvelopeCodec.KDF_ALG, 8, 1, 1, new byte[EnvelopeCodec.SALT_LENGTH]);
        Recorder rec = new Recorder();
        try (SecretChars pw = chars(RIGHT)) {
            CryptoException e = assertThrows(CryptoException.class,
                    () -> SlotCrypto.kekFromPassphrase(pw, belowFloor, SLOT, rec).close());
            assertEquals(CryptoException.Code.BAD_PARAMS, e.code());
        }
        assertEquals(0, rec.started, "header validation is credential-independent and precedes the KDF");
    }

    @Test
    void differentHeaderSaltsAreHonoured() throws CryptoException {
        Recorder rec = new Recorder();
        KdfHeader a = floorHeader();
        KdfHeader b = nonDefaultHeader();
        try (SecretChars pw = chars(RIGHT);
             SecretBytes ka = SlotCrypto.kekFromPassphrase(pw, a, SLOT, rec);
             SecretBytes kb = SlotCrypto.kekFromPassphrase(pw, b, SLOT, rec)) {
            assertNotEquals(ka, kb);
        }
        assertEquals(2, rec.calls.size());
        assertArrayEquals(unboxed(rec.calls.get(0).salt()), a.salt());
        assertArrayEquals(unboxed(rec.calls.get(1).salt()), b.salt());
    }

    private static long bestOf(String pass, KdfHeader header) throws CryptoException {
        long best = Long.MAX_VALUE;
        for (int i = 0; i < TIMING_RUNS; i++) {
            try (SecretChars pw = chars(pass)) {
                long start = System.nanoTime();
                SlotCrypto.kekFromPassphrase(pw, header, SLOT).close();
                best = Math.min(best, System.nanoTime() - start);
            }
        }
        return best;
    }

    private static void unwrapClosing(SecretBytes kek, byte[] wrapped) throws CryptoException {
        KeyWrap.unwrap(kek, wrapped).close();
    }

    /** FLOOR memory and parallelism, one extra iteration, non-zero salt: params cannot be defaults. */
    private static KdfHeader nonDefaultHeader() {
        Argon2Params f = Argon2Params.FLOOR;
        return new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB(), f.iterations() + 1, f.parallelism(),
                pattern(EnvelopeCodec.SALT_LENGTH, 0x3C));
    }

    private static KdfHeader floorHeader() {
        Argon2Params f = Argon2Params.FLOOR;
        return new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB(), f.iterations(), f.parallelism(),
                pattern(EnvelopeCodec.SALT_LENGTH, 0x11));
    }

    private static byte[] pattern(int n, int start) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (start + i);
        }
        return b;
    }

    private static List<Byte> boxed(byte[] b) {
        List<Byte> out = new ArrayList<>(b.length);
        for (byte x : b) {
            out.add(x);
        }
        return List.copyOf(out);
    }

    private static byte[] unboxed(List<Byte> l) {
        byte[] out = new byte[l.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = l.get(i);
        }
        return out;
    }

    private static SecretChars chars(String s) {
        return SecretChars.takeOwnership(s.toCharArray());
    }
}
