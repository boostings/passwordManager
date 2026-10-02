package pm.crypto;

/**
 * Argon2id cost parameters with the ADR 0007 floors and caps enforced at construction.
 *
 * @param memoryKiB memory cost in KiB, 64 MiB..1 GiB
 * @param iterations time cost, 3..10
 * @param parallelism lanes, 1..16
 */
public record Argon2Params(int memoryKiB, int iterations, int parallelism) {
    private static final int MIN_MEMORY_KIB = 65_536;
    private static final int MAX_MEMORY_KIB = 1_048_576;
    private static final int MIN_ITERATIONS = 3;
    private static final int MAX_ITERATIONS = 10;
    private static final int MIN_PARALLELISM = 1;
    private static final int MAX_PARALLELISM = 16;

    /** The ADR 0007 floor: m = 64 MiB, t = 3, p = 1. Never go lower. */
    public static final Argon2Params FLOOR = new Argon2Params(MIN_MEMORY_KIB, MIN_ITERATIONS, MIN_PARALLELISM);

    /** Validates bounds. */
    public Argon2Params {
        if (memoryKiB < MIN_MEMORY_KIB || memoryKiB > MAX_MEMORY_KIB
                || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                || parallelism < MIN_PARALLELISM || parallelism > MAX_PARALLELISM) {
            throw new IllegalArgumentException("ARGON2_PARAMS_OUT_OF_RANGE");
        }
    }
}
