package pm.vault.envelope;

import java.util.Arrays;
import java.util.Objects;

/**
 * The {@code kdf} map of the vault header (ADR 0003, ADR 0007). Public metadata: it is
 * authenticated by the AAD but not secret. The salt is copied on the way in and out
 * (OBJ06-J, OBJ05-J).
 *
 * <p>Contract note: §2 of the M1 sprint plan declares this as a record. Error Prone's
 * {@code ArrayRecordComponent} rejects array record components under {@code -Werror}, so it
 * is a final class with the same constructor and accessor names.
 */
public final class KdfHeader {
    private final String algorithm;
    private final int memoryKiB;
    private final int iterations;
    private final int parallelism;
    private final byte[] saltBytes;

    /**
     * Creates a KDF header.
     *
     * @param alg  KDF algorithm name; only {@code "argon2id"} is accepted on read
     * @param m    Argon2 memory in KiB
     * @param t    Argon2 iterations
     * @param p    Argon2 lanes
     * @param salt 32-byte random salt; copied
     */
    public KdfHeader(String alg, int m, int t, int p, byte[] salt) {
        this.algorithm = Objects.requireNonNull(alg, "alg");
        this.memoryKiB = m;
        this.iterations = t;
        this.parallelism = p;
        this.saltBytes = Objects.requireNonNull(salt, "salt").clone();
    }

    /** Returns the algorithm name. */
    public String alg() {
        return algorithm;
    }

    /** Returns the Argon2 memory in KiB. */
    public int m() {
        return memoryKiB;
    }

    /** Returns the Argon2 iterations. */
    public int t() {
        return iterations;
    }

    /** Returns the Argon2 lanes. */
    public int p() {
        return parallelism;
    }

    /** Returns a copy of the salt. */
    public byte[] salt() {
        return saltBytes.clone();
    }

    /** Compares salt contents, not references (EXP02-J), in constant time (SR-016). */
    @Override
    public boolean equals(Object o) {
        return o instanceof KdfHeader k
                && algorithm.equals(k.algorithm) && memoryKiB == k.memoryKiB
                && iterations == k.iterations && parallelism == k.parallelism
                && Bytes.sameContents(saltBytes, k.saltBytes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, memoryKiB, iterations, parallelism, Arrays.hashCode(saltBytes));
    }

    @Override
    public String toString() {
        return "KdfHeader[alg=" + algorithm + ", m=" + memoryKiB + ", t=" + iterations
                + ", p=" + parallelism + "]";
    }
}
