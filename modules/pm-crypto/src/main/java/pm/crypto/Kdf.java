package pm.crypto;

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
    /**
     * Argon2 needs about 1.03 x m of heap (the m-KiB block matrix plus generator state); refuse
     * unless 1.1 x m fits in the heap still free, so a hostile header fails before allocating.
     */
    private static final long HEADROOM_NUM = 11L;
    private static final long HEADROOM_DEN = 10L;
    /** Free heap assumed when the JVM defines no maximum: exactly enough for the 1 GiB parameter cap. */
    static final long UNBOUNDED_HEAP_AVAILABLE =
            Argon2Params.MAX_MEMORY_KIB * BYTES_PER_KIB * HEADROOM_NUM / HEADROOM_DEN;

    private Kdf() {
    }

    /**
     * Argon2id (RFC 9106) with a 32-byte salt and 32-byte output.
     *
     * @throws CryptoException {@code BAD_INPUT} if the salt is not 32 bytes; {@code BAD_PARAMS} if
     *     {@code memoryKiB * 1024 * 11/10} exceeds the heap still available (maximum heap minus heap
     *     in use now), checked before anything is allocated so a hostile vault header cannot exhaust
     *     the heap. With no defined maximum heap only the 1 GiB {@link Argon2Params} cap applies.
     */
    public static SecretBytes argon2id(SecretBytes password, byte[] salt32, Argon2Params params) throws CryptoException {
        Objects.requireNonNull(params, "params");
        return argon2id(password, salt32, params, availableHeapFor(requiredHeapBytes(params)));
    }

    /**
     * {@link #argon2id(SecretBytes, byte[], Argon2Params)} with an injectable available-heap figure
     * in bytes.
     */
    static SecretBytes argon2id(SecretBytes password, byte[] salt32, Argon2Params params, long availableBytes)
            throws CryptoException {
        Objects.requireNonNull(salt32, "salt32");
        Objects.requireNonNull(params, "params");
        if (salt32.length != SALT_LEN) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        if (requiredHeapBytes(params) > availableBytes) {
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
     *
     * <p>If the free heap cannot hold even one run at the floor, nothing is timed and the floor is
     * returned: timing it would end in {@link OutOfMemoryError}. {@link #argon2id} then refuses
     * those parameters on this JVM with {@code BAD_PARAMS}, the clean failure ADR 0007 asks for.
     */
    public static Argon2Params tune(Duration target) {
        return tune(target, Kdf::timeOnce, heapBudgetBytes(),
                availableHeapFor(requiredHeapBytes(Argon2Params.FLOOR)));
    }

    /**
     * {@link #tune(Duration)} with an injectable timer, memory budget and available-heap figure
     * (bytes). The timer is never called when the floor needs more than {@code availableBytes}.
     */
    static Argon2Params tune(Duration target, ToLongFunction<Argon2Params> timer, long budgetBytes,
                             long availableBytes) {
        if (requiredHeapBytes(Argon2Params.FLOOR) > availableBytes) {
            return Argon2Params.FLOOR;
        }
        return tune(target, timer, budgetBytes);
    }

    /**
     * The timing loop of {@link #tune(Duration)} with an injectable timer (nanoseconds per run) and
     * memory budget (bytes), so tests need not run Argon2.
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

    /** Heap Argon2 must find free before running: {@code memoryKiB * 1024 * 11/10}. */
    static long requiredHeapBytes(Argon2Params params) {
        return params.memoryKiB() * BYTES_PER_KIB * HEADROOM_NUM / HEADROOM_DEN;
    }

    /**
     * {@link #availableHeapBytes()}, measured again after one collection if the first figure is
     * short of {@code requiredBytes}. "In use" counts unreachable garbage, such as the blocks of the
     * Argon2 runs {@link #tune} just timed, which would otherwise refuse a run that fits.
     */
    static long availableHeapFor(long requiredBytes) {
        long available = availableHeapBytes();
        if (requiredBytes > available) {
            collectGarbage();
            available = availableHeapBytes();
        }
        return available;
    }

    /** CE-005: deliberate collection so the heap figure excludes garbage; runs only before refusing. */
    private static void collectGarbage() {
        System.gc();
    }

    /** Maximum heap minus heap in use now, or {@link #UNBOUNDED_HEAP_AVAILABLE} with no defined maximum. */
    static long availableHeapBytes() {
        Runtime rt = Runtime.getRuntime();
        return availableHeapBytes(rt.maxMemory(), rt.totalMemory() - rt.freeMemory());
    }

    /**
     * {@code maxHeapBytes} is {@link Long#MAX_VALUE} (or negative) when the JVM defines no maximum;
     * then the figure is just enough for the 1 GiB parameter cap, never unbounded.
     */
    static long availableHeapBytes(long maxHeapBytes, long usedHeapBytes) {
        if (undefinedMax(maxHeapBytes)) {
            return UNBOUNDED_HEAP_AVAILABLE;
        }
        return maxHeapBytes - usedHeapBytes;
    }

    /** Half the maximum heap: what {@link #tune} may use, leaving headroom for the rest of the process. */
    static long heapBudgetBytes() {
        return heapBudgetBytes(Runtime.getRuntime().maxMemory());
    }

    /** With no defined maximum heap only the 1 GiB parameter cap applies (see {@link #memoryCapKiB}). */
    static long heapBudgetBytes(long maxHeapBytes) {
        if (undefinedMax(maxHeapBytes)) {
            return Long.MAX_VALUE;
        }
        return maxHeapBytes / HEAP_BUDGET_DIVISOR;
    }

    private static boolean undefinedMax(long maxHeapBytes) {
        return maxHeapBytes < 0 || maxHeapBytes == Long.MAX_VALUE;
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
