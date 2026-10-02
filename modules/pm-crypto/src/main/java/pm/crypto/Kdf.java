package pm.crypto;

import java.lang.management.ManagementFactory;
import java.time.Duration;
import java.util.Objects;
import java.util.function.ToLongFunction;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * Key derivation: Argon2id for passphrases (ADR 0007), HKDF-SHA256 for high-entropy inputs (ADR 0004).
 *
 * <p>Copies outside our control (ADR 0008 residual risk): Bouncy Castle's {@code HKDFParameters}
 * clones the IKM and {@code HKDFBytesGenerator} keeps the PRK; {@code Argon2BytesGenerator} keeps
 * its memory blocks, which are derived from the password. None of these can be zeroed from here.
 * They become garbage when the generator goes out of scope but stay in the heap until reused.
 */
public final class Kdf {
    /** ADR 0007: salt is exactly 32 bytes. */
    static final int SALT_LEN = 32;
    /** ADR 0007: Argon2id output is exactly 32 bytes. */
    static final int ARGON2_OUT_LEN = 32;
    /** RFC 5869: HKDF-SHA256 output is at most 255 * HashLen. */
    static final int HKDF_MAX_OUT = 255 * 32;
    /** HKDF input must carry at least 256 bits; shorter IKM means a caller passed the wrong thing. */
    static final int HKDF_MIN_IKM = 32;
    private static final int HKDF_MIN_OUT = 1;
    private static final int TUNE_MEMORY_FACTOR = 2;
    private static final long BYTES_PER_KIB = 1024L;
    private static final long HEAP_BUDGET_DIVISOR = 2L;

    private Kdf() {
    }

    /**
     * Argon2id (RFC 9106) with a 32-byte salt and 32-byte output.
     *
     * @throws CryptoException {@code BAD_INPUT} if the salt is not 32 bytes; {@code BAD_PARAMS} if
     *     {@code params} need more than half the maximum heap, checked before anything is allocated
     *     so a hostile vault header cannot exhaust the heap
     */
    public static SecretBytes argon2id(SecretBytes password, byte[] salt32, Argon2Params params) throws CryptoException {
        return argon2id(password, salt32, params, heapBudgetBytes());
    }

    /** {@link #argon2id(SecretBytes, byte[], Argon2Params)} with an injectable memory budget in bytes. */
    static SecretBytes argon2id(SecretBytes password, byte[] salt32, Argon2Params params, long budgetBytes)
            throws CryptoException {
        Objects.requireNonNull(salt32, "salt32");
        Objects.requireNonNull(params, "params");
        if (salt32.length != SALT_LEN) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        if (params.memoryKiB() * BYTES_PER_KIB > budgetBytes) {
            throw new CryptoException(CryptoException.Code.BAD_PARAMS);
        }
        Argon2BytesGenerator gen = argon2Generator(salt32, params);
        byte[] out = new byte[ARGON2_OUT_LEN];
        password.withBytes(pw -> gen.generateBytes(pw, out));
        return SecretBytes.takeOwnership(out);
    }

    /**
     * Benchmarks this machine and returns parameters near {@code target}, never below the floor
     * (ADR 0007): double memory first, then raise iterations up to 10. Memory stops at the lower of
     * 1 GiB and half the maximum heap, rounded down to a power of two and never below the floor.
     */
    public static Argon2Params tune(Duration target) {
        return tune(target, Kdf::timeOnce, heapBudgetBytes());
    }

    /**
     * {@link #tune(Duration)} with an injectable timer (nanoseconds per run) and memory budget
     * (bytes), so tests need not run Argon2.
     */
    static Argon2Params tune(Duration target, ToLongFunction<Argon2Params> timer, long budgetBytes) {
        long targetNanos = target.toNanos();
        int maxMemoryKiB = memoryCapKiB(budgetBytes);
        Argon2Params p = Argon2Params.FLOOR;
        long elapsed = timer.applyAsLong(p);
        while (elapsed < targetNanos && p.memoryKiB() < maxMemoryKiB) {
            int memory = Math.min(p.memoryKiB() * TUNE_MEMORY_FACTOR, maxMemoryKiB);
            p = new Argon2Params(memory, p.iterations(), p.parallelism());
            elapsed = timer.applyAsLong(p);
        }
        while (elapsed < targetNanos && p.iterations() < Argon2Params.MAX_ITERATIONS) {
            p = new Argon2Params(p.memoryKiB(), p.iterations() + 1, p.parallelism());
            elapsed = timer.applyAsLong(p);
        }
        return p;
    }

    /**
     * HKDF-SHA256 (RFC 5869); {@code salt} may be null; {@code outLen} in 1..8160.
     *
     * @throws CryptoException {@code BAD_INPUT} if {@code ikm} is shorter than 32 bytes;
     *     {@code BAD_PARAMS} if {@code outLen} is out of range
     */
    public static SecretBytes hkdfSha256(SecretBytes ikm, byte[] salt, byte[] info, int outLen) throws CryptoException {
        if (ikm.length() < HKDF_MIN_IKM) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        return hkdfSha256AnyIkm(ikm, salt, info, outLen);
    }

    /** HKDF without the IKM length floor; package-private so tests can run the RFC 5869 vectors (22-byte IKM). */
    static SecretBytes hkdfSha256AnyIkm(SecretBytes ikm, byte[] salt, byte[] info, int outLen) throws CryptoException {
        if (outLen < HKDF_MIN_OUT || outLen > HKDF_MAX_OUT) {
            throw new CryptoException(CryptoException.Code.BAD_PARAMS);
        }
        HKDFBytesGenerator gen = new HKDFBytesGenerator(new SHA256Digest());
        // HKDFParameters clones the IKM and gen keeps the PRK; neither can be zeroed (see class javadoc).
        ikm.withBytes(in -> gen.init(new HKDFParameters(in, salt, info)));
        byte[] out = new byte[outLen];
        // Bouncy Castle's HKDFBytesGenerator.generateBytes returns exactly outLen or throws
        // DataLengthException past 255 * HashLen; outLen is bounded above, so no length check is needed.
        gen.generateBytes(out, 0, outLen);
        return SecretBytes.takeOwnership(out);
    }

    /**
     * Half the maximum heap: Argon2 must leave room for the rest of the process. Read through the
     * MemoryMXBean because the ArchUnit process rule bans {@code java.lang.Runtime} outside
     * pm.approval and pm.platform.
     */
    static long heapBudgetBytes() {
        return heapBudgetBytes(ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getMax());
    }

    /** {@code maxHeapBytes} is -1 when the JVM defines no maximum; then only the 1 GiB parameter cap applies. */
    static long heapBudgetBytes(long maxHeapBytes) {
        if (maxHeapBytes < 0) {
            return Long.MAX_VALUE;
        }
        return maxHeapBytes / HEAP_BUDGET_DIVISOR;
    }

    /** min(1 GiB, budget) in KiB, rounded down to a power of two, never below the floor. */
    static int memoryCapKiB(long budgetBytes) {
        int capped = (int) Math.min(Argon2Params.MAX_MEMORY_KIB, budgetBytes / BYTES_PER_KIB);
        return Math.max(Argon2Params.FLOOR.memoryKiB(), Integer.highestOneBit(capped));
    }

    private static Argon2BytesGenerator argon2Generator(byte[] salt, Argon2Params params) {
        Argon2Parameters bcParams = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(params.memoryKiB())
                .withIterations(params.iterations())
                .withParallelism(params.parallelism())
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(bcParams);
        return gen;
    }

    /** One Argon2id run over a fixed all-zero dummy input; returns elapsed nanoseconds. */
    private static long timeOnce(Argon2Params params) {
        byte[] dummyInput = new byte[ARGON2_OUT_LEN];
        byte[] out = new byte[ARGON2_OUT_LEN];
        long start = System.nanoTime();
        Argon2BytesGenerator gen = argon2Generator(new byte[SALT_LEN], params);
        gen.generateBytes(dummyInput, out);
        return System.nanoTime() - start;
    }
}
