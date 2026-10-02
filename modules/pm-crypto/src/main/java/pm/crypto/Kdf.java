package pm.crypto;

import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.HKDFParameters;

/** Key derivation: Argon2id for passphrases (ADR 0007), HKDF-SHA256 for high-entropy inputs (ADR 0004). */
public final class Kdf {
    /** ADR 0007: salt is exactly 32 bytes. */
    static final int SALT_LEN = 32;
    /** ADR 0007: Argon2id output is exactly 32 bytes. */
    static final int ARGON2_OUT_LEN = 32;
    /** RFC 5869: HKDF-SHA256 output is at most 255 * HashLen. */
    static final int HKDF_MAX_OUT = 255 * 32;
    private static final int HKDF_MIN_OUT = 1;
    private static final int TUNE_MEMORY_FACTOR = 2;

    private Kdf() {
    }

    /** Argon2id (RFC 9106) with a 32-byte salt and 32-byte output. */
    public static SecretBytes argon2id(SecretBytes password, byte[] salt32, Argon2Params params) throws CryptoException {
        Objects.requireNonNull(salt32, "salt32");
        Objects.requireNonNull(params, "params");
        if (salt32.length != SALT_LEN) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        Argon2BytesGenerator gen = argon2Generator(salt32, params);
        byte[] out = new byte[ARGON2_OUT_LEN];
        password.withBytes(pw -> gen.generateBytes(pw, out));
        return SecretBytes.takeOwnership(out);
    }

    /**
     * Benchmarks this machine and returns parameters near {@code target}, never below the floor
     * (ADR 0007): double memory up to 1 GiB first, then raise iterations up to 10.
     */
    public static Argon2Params tune(Duration target) {
        long targetNanos = target.toNanos();
        Argon2Params p = Argon2Params.FLOOR;
        long elapsed = timeOnce(p);
        while (elapsed < targetNanos && p.memoryKiB() < Argon2Params.MAX_MEMORY_KIB) {
            int memory = Math.min(p.memoryKiB() * TUNE_MEMORY_FACTOR, Argon2Params.MAX_MEMORY_KIB);
            p = new Argon2Params(memory, p.iterations(), p.parallelism());
            elapsed = timeOnce(p);
        }
        while (elapsed < targetNanos && p.iterations() < Argon2Params.MAX_ITERATIONS) {
            p = new Argon2Params(p.memoryKiB(), p.iterations() + 1, p.parallelism());
            elapsed = timeOnce(p);
        }
        return p;
    }

    /** HKDF-SHA256 (RFC 5869); {@code salt} may be null; {@code outLen} in 1..8160. */
    public static SecretBytes hkdfSha256(SecretBytes ikm, byte[] salt, byte[] info, int outLen) throws CryptoException {
        if (outLen < HKDF_MIN_OUT || outLen > HKDF_MAX_OUT) {
            throw new CryptoException(CryptoException.Code.BAD_PARAMS);
        }
        HKDFBytesGenerator gen = new HKDFBytesGenerator(new SHA256Digest());
        // HKDFParameters keeps its own copy of the IKM; that copy is unreachable once gen goes out of scope.
        ikm.withBytes(in -> gen.init(new HKDFParameters(in, salt, info)));
        byte[] out = new byte[outLen];
        int written = gen.generateBytes(out, 0, outLen);
        if (written != outLen) {
            Arrays.fill(out, (byte) 0);
            throw new CryptoException(CryptoException.Code.INTERNAL);
        }
        return SecretBytes.takeOwnership(out);
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
