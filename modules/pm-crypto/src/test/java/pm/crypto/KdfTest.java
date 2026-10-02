package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.jupiter.api.Test;

/** Argon2id (RFC 9106) and HKDF-SHA256 (RFC 5869) known answers and contract checks. */
class KdfTest {
    private static final HexFormat HEX = HexFormat.of();

    // RFC 9106 §5.3 Argon2id test vector: m=32 KiB, t=3, p=4, tag 32 bytes, version 0x13.
    private static final int RFC9106_M = 32;
    private static final int RFC9106_T = 3;
    private static final int RFC9106_P = 4;
    private static final String RFC9106_PWD_HEX = "01".repeat(32);
    private static final String RFC9106_SALT_HEX = "02".repeat(16);
    private static final String RFC9106_K_HEX = "03".repeat(8);
    private static final String RFC9106_X_HEX = "04".repeat(12);
    private static final String RFC9106_TAG_HEX = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";

    // Independent oracle (argon2-cffi 25.1.0), salt 00..1f, t=3, m=65536 KiB, version 0x13, 32-byte tag.
    // p=1, password "correct horse":
    private static final String ORACLE_FLOOR_P1_HEX = "5ae5814e91d65faf404b210f2e803dfb6dc636ba6bd666d9d2012acee1bc54b9";
    // p=4, empty password:
    private static final String ORACLE_P4_EMPTY_HEX = "7d8aeb76f74eaba0f5b1708d66319b2bc5c12bc262df52536dd0ce62f93bc7b6";

    // RFC 5869 Appendix A, test cases 1-3 (SHA-256).
    private static final String TC1_IKM = "0b".repeat(22);
    private static final String TC1_SALT = "000102030405060708090a0b0c";
    private static final String TC1_INFO = "f0f1f2f3f4f5f6f7f8f9";
    private static final String TC1_OKM =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    private static final String TC2_IKM = range(0x00, 0x50);
    private static final String TC2_SALT = range(0x60, 0xb0);
    private static final String TC2_INFO = range(0xb0, 0x100);
    private static final String TC2_OKM = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            + "cc30c58179ec3e87c14c01d5c1f3434f1d87";
    private static final String TC3_IKM = "0b".repeat(22);
    private static final String TC3_OKM =
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";

    private static String range(int fromInclusive, int toExclusive) {
        StringBuilder sb = new StringBuilder();
        for (int i = fromInclusive; i < toExclusive; i++) {
            sb.append(HEX.toHexDigits((byte) i));
        }
        return sb.toString();
    }

    private static SecretBytes sb(byte[] b) {
        return SecretBytes.copyOf(b);
    }

    private static byte[] raw(SecretBytes s) {
        return TestBytes.copyOut(s);
    }

    private static byte[] bcArgon2id(byte[] pw, byte[] salt, Argon2Params p) {
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(p.memoryKiB())
                .withIterations(p.iterations())
                .withParallelism(p.parallelism())
                .build());
        byte[] out = new byte[Kdf.ARGON2_OUT_LEN];
        gen.generateBytes(pw, out);
        return out;
    }

    // ---- Argon2id -------------------------------------------------------------------------

    /** Validates the BC wiring (type id, version 0x13) at the RFC's small parameters, below our floor. */
    @Test
    void argon2idRfc9106Vector() {
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(HEX.parseHex(RFC9106_SALT_HEX))
                .withSecret(HEX.parseHex(RFC9106_K_HEX))
                .withAdditional(HEX.parseHex(RFC9106_X_HEX))
                .withMemoryAsKB(RFC9106_M)
                .withIterations(RFC9106_T)
                .withParallelism(RFC9106_P)
                .build());
        byte[] tag = new byte[Kdf.ARGON2_OUT_LEN];
        gen.generateBytes(HEX.parseHex(RFC9106_PWD_HEX), tag);
        assertArrayEquals(HEX.parseHex(RFC9106_TAG_HEX), tag);
    }

    @Test
    void argon2idAtFloorIsDeterministicAndMatchesBouncyCastle() throws CryptoException {
        byte[] pw = "correct horse".getBytes(StandardCharsets.UTF_8);
        byte[] salt = new byte[Kdf.SALT_LEN];
        try (SecretBytes a = Kdf.argon2id(sb(pw), salt, Argon2Params.FLOOR);
             SecretBytes b = Kdf.argon2id(sb(pw), salt, Argon2Params.FLOOR)) {
            assertEquals(Kdf.ARGON2_OUT_LEN, a.length());
            assertEquals(a, b);
            assertArrayEquals(bcArgon2id(pw, salt, Argon2Params.FLOOR), raw(a));
        }
    }

    /**
     * F10: the RFC 9106 vector cannot run through {@link Kdf#argon2id}: it needs m = 32 KiB (below
     * the 64 MiB floor), a secret K and associated data X, none of which the public API accepts.
     * Instead these vectors come from an independent implementation, recorded so they can be
     * regenerated: argon2-cffi 25.1.0, {@code argon2.low_level.hash_secret_raw(pw, salt, t, m, p,
     * 32, Type.ID, 0x13)} with salt = bytes(range(32)).
     */
    @Test
    void argon2idMatchesIndependentOracleAtFloor() throws CryptoException {
        byte[] salt = HEX.parseHex(range(0x00, 0x20));
        try (SecretBytes out = Kdf.argon2id(sb("correct horse".getBytes(StandardCharsets.UTF_8)), salt,
                Argon2Params.FLOOR)) {
            assertArrayEquals(HEX.parseHex(ORACLE_FLOOR_P1_HEX), raw(out));
        }
    }

    /** Same oracle, four lanes and an empty password: checks the parallelism wiring. */
    @Test
    void argon2idMatchesIndependentOracleWithFourLanes() throws CryptoException {
        byte[] salt = HEX.parseHex(range(0x00, 0x20));
        Argon2Params fourLanes = new Argon2Params(Argon2Params.FLOOR.memoryKiB(), Argon2Params.FLOOR.iterations(), 4);
        try (SecretBytes out = Kdf.argon2id(sb(new byte[0]), salt, fourLanes)) {
            assertArrayEquals(HEX.parseHex(ORACLE_P4_EMPTY_HEX), raw(out));
        }
    }

    @Property(tries = 5)
    void argon2idSaltSeparatesOutputs(@ForAll @Size(min = 1, max = 32) byte[] pw,
                                      @ForAll @Size(32) byte[] salt) throws CryptoException {
        byte[] otherSalt = salt.clone();
        otherSalt[0] ^= 1;
        try (SecretBytes a = Kdf.argon2id(sb(pw), salt, Argon2Params.FLOOR);
             SecretBytes b = Kdf.argon2id(sb(pw), otherSalt, Argon2Params.FLOOR)) {
            assertNotEquals(a, b);
        }
    }

    @Test
    void argon2idRejectsSaltNot32Bytes() {
        for (int len : new int[] {0, 16, 31, 33}) {
            CryptoException e = assertThrows(CryptoException.class,
                    () -> Kdf.argon2id(sb(new byte[1]), new byte[len], Argon2Params.FLOOR));
            assertEquals(CryptoException.Code.BAD_INPUT, e.code());
        }
    }

    @Test
    void tuneWithTinyTargetReturnsFloorAfterOneMeasurement() {
        assertEquals(Argon2Params.FLOOR, Kdf.tune(Duration.ofMillis(1)));
    }

    // ---- tune with a fake timer: exercises both loops without running Argon2 -----------------

    private static final Duration TARGET = Duration.ofSeconds(1);
    private static final long TARGET_NANOS = TARGET.toNanos();
    private static final int MID_MEMORY_KIB = 262_144;
    private static final int MID_ITERATIONS = 5;
    private static final long MIB = 1024L * 1024L;
    private static final long UNLIMITED_BUDGET = Long.MAX_VALUE;

    @Test
    void tuneReachingTargetImmediatelyMeasuresOnceAndReturnsFloor() {
        AtomicInteger calls = new AtomicInteger();
        Argon2Params tuned = Kdf.tune(TARGET, p -> {
            calls.incrementAndGet();
            return TARGET_NANOS;
        }, UNLIMITED_BUDGET);
        assertEquals(Argon2Params.FLOOR, tuned);
        assertEquals(1, calls.get());
    }

    @Test
    void tuneNeverReachingTargetClimbsToMaxMemoryThenMaxIterations() {
        Argon2Params tuned = Kdf.tune(TARGET, p -> 0L, UNLIMITED_BUDGET);
        assertEquals(new Argon2Params(Argon2Params.MAX_MEMORY_KIB, Argon2Params.MAX_ITERATIONS,
                Argon2Params.FLOOR.parallelism()), tuned);
    }

    @Test
    void tuneReachingTargetMidMemoryStopsBeforeIterations() {
        Argon2Params tuned = Kdf.tune(TARGET, p -> p.memoryKiB() >= MID_MEMORY_KIB ? TARGET_NANOS : 0L,
                UNLIMITED_BUDGET);
        assertEquals(new Argon2Params(MID_MEMORY_KIB, Argon2Params.FLOOR.iterations(),
                Argon2Params.FLOOR.parallelism()), tuned);
    }

    @Test
    void tuneReachingTargetMidIterationsStopsThere() {
        Argon2Params tuned = Kdf.tune(TARGET, p -> p.iterations() >= MID_ITERATIONS ? TARGET_NANOS : 0L,
                UNLIMITED_BUDGET);
        assertEquals(new Argon2Params(Argon2Params.MAX_MEMORY_KIB, MID_ITERATIONS,
                Argon2Params.FLOOR.parallelism()), tuned);
    }

    /** F6: with a 300 MiB budget memory stops at 256 MiB (largest power of two within budget). */
    @Test
    void tuneCapsMemoryAtHeapBudgetRoundedDownToPowerOfTwo() {
        Argon2Params tuned = Kdf.tune(TARGET, p -> 0L, 300L * MIB);
        assertEquals(new Argon2Params(MID_MEMORY_KIB, Argon2Params.MAX_ITERATIONS,
                Argon2Params.FLOOR.parallelism()), tuned);
    }

    /** F6: a budget below the floor still yields the floor (never weaker than ADR 0007). */
    @Test
    void tuneNeverGoesBelowFloorMemoryOnATinyHeap() {
        Argon2Params tuned = Kdf.tune(TARGET, p -> 0L, MIB);
        assertEquals(new Argon2Params(Argon2Params.FLOOR.memoryKiB(), Argon2Params.MAX_ITERATIONS,
                Argon2Params.FLOOR.parallelism()), tuned);
    }

    @Test
    void memoryCapIsMinOfOneGibAndBudgetAsPowerOfTwo() {
        assertEquals(Argon2Params.MAX_MEMORY_KIB, Kdf.memoryCapKiB(UNLIMITED_BUDGET));
        assertEquals(Argon2Params.MAX_MEMORY_KIB, Kdf.memoryCapKiB(1024L * MIB));
        assertEquals(MID_MEMORY_KIB * 2, Kdf.memoryCapKiB(1023L * MIB));
        assertEquals(Argon2Params.FLOOR.memoryKiB(), Kdf.memoryCapKiB(0L));
        assertEquals(256L * MIB, Kdf.heapBudgetBytes(512L * MIB));
        assertEquals(UNLIMITED_BUDGET, Kdf.heapBudgetBytes(-1L));
        assertTrue(Kdf.heapBudgetBytes() > 0);
    }

    /** F6: parameters from a hostile header that exceed the heap budget fail before allocation. */
    @Test
    void argon2idRejectsMemoryAboveHeapBudget() {
        long budget = Argon2Params.FLOOR.memoryKiB() * 1024L - 1;
        CryptoException e = assertThrows(CryptoException.class,
                () -> Kdf.argon2id(sb(new byte[1]), new byte[Kdf.SALT_LEN], Argon2Params.FLOOR, budget));
        assertEquals(CryptoException.Code.BAD_PARAMS, e.code());
    }

    // ---- HKDF-SHA256 ----------------------------------------------------------------------

    /** RFC 5869 vectors 1 and 3 use a 22-byte IKM, below the public 32-byte floor, so they go through the core. */
    private static void assertHkdf(String ikm, byte[] salt, String info, String okm) throws CryptoException {
        byte[] expected = HEX.parseHex(okm);
        try (SecretBytes out = Kdf.hkdfSha256AnyIkm(sb(HEX.parseHex(ikm)), salt, HEX.parseHex(info), expected.length)) {
            assertArrayEquals(expected, raw(out));
        }
    }

    @Test
    void hkdfRfc5869TestCase1() throws CryptoException {
        assertHkdf(TC1_IKM, HEX.parseHex(TC1_SALT), TC1_INFO, TC1_OKM);
    }

    /** Test case 2 has an 80-byte IKM, so it runs through the public method. */
    @Test
    void hkdfRfc5869TestCase2() throws CryptoException {
        byte[] expected = HEX.parseHex(TC2_OKM);
        try (SecretBytes out = Kdf.hkdfSha256(sb(HEX.parseHex(TC2_IKM)), HEX.parseHex(TC2_SALT),
                HEX.parseHex(TC2_INFO), expected.length)) {
            assertArrayEquals(expected, raw(out));
        }
    }

    /** F9b: IKM shorter than 32 bytes is a caller bug (BAD_INPUT), whatever the other arguments. */
    @Test
    void hkdfRejectsIkmShorterThan32Bytes() {
        for (int len : new int[] {0, 1, 22, Kdf.HKDF_MIN_IKM - 1}) {
            CryptoException e = assertThrows(CryptoException.class,
                    () -> Kdf.hkdfSha256(sb(new byte[len]), null, new byte[0], Kdf.SALT_LEN));
            assertEquals(CryptoException.Code.BAD_INPUT, e.code());
        }
    }

    @Test
    void hkdfRfc5869TestCase3EmptySaltAndInfo() throws CryptoException {
        assertHkdf(TC3_IKM, new byte[0], "", TC3_OKM);
    }

    @Test
    void hkdfNullSaltEqualsEmptySalt() throws CryptoException {
        assertHkdf(TC3_IKM, null, "", TC3_OKM);
    }

    @Test
    void hkdfOutputLengthBounds() throws CryptoException {
        try (SecretBytes one = Kdf.hkdfSha256(sb(new byte[Kdf.SALT_LEN]), null, new byte[0], 1);
             SecretBytes max = Kdf.hkdfSha256(sb(new byte[Kdf.SALT_LEN]), null, new byte[0], Kdf.HKDF_MAX_OUT)) {
            assertEquals(1, one.length());
            assertEquals(Kdf.HKDF_MAX_OUT, max.length());
        }
        for (int len : new int[] {0, -1, Kdf.HKDF_MAX_OUT + 1}) {
            CryptoException e = assertThrows(CryptoException.class,
                    () -> Kdf.hkdfSha256(sb(new byte[Kdf.SALT_LEN]), null, new byte[0], len));
            assertEquals(CryptoException.Code.BAD_PARAMS, e.code());
        }
    }

    @Property(tries = 200)
    void hkdfInfoSeparatesKeys(@ForAll @Size(32) byte[] ikm, @ForAll @Size(max = 16) byte[] info)
            throws CryptoException {
        byte[] otherInfo = Arrays.copyOf(info, info.length + 1);
        try (SecretBytes a = Kdf.hkdfSha256(sb(ikm), null, info, Kdf.SALT_LEN);
             SecretBytes b = Kdf.hkdfSha256(sb(ikm), null, otherInfo, Kdf.SALT_LEN)) {
            assertNotEquals(a, b);
        }
    }
}
