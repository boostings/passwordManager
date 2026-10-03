package pm.vault;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import pm.vault.envelope.EnvelopeCodec;

/**
 * The ordered list of format migrations this build ships (ADR 0015). The steps form one
 * contiguous chain that ends at {@link EnvelopeCodec#VERSION}, so every version the registry
 * names can be brought to the current one, and no version can be skipped.
 *
 * <p>Format 1 is the first format ever written, so the production registry is empty. Tests
 * inject a registry with a synthetic step to prove the framework end to end.
 */
final class MigrationRegistry {

    /** The registry this build ships: no format predates version 1. */
    static final MigrationRegistry PRODUCTION = new MigrationRegistry(List.of());

    /** Sorted by {@link Migration#fromVersion()}, contiguous, ending at the current version. */
    private final List<Migration> steps;

    /**
     * Creates a registry.
     *
     * @param migrations the steps, in any order
     * @throws IllegalArgumentException if the steps do not form one contiguous chain ending at
     *                                  {@link EnvelopeCodec#VERSION}
     */
    MigrationRegistry(List<Migration> migrations) {
        List<Migration> sorted = new ArrayList<>(Objects.requireNonNull(migrations, "migrations"));
        sorted.forEach(m -> Objects.requireNonNull(m, "migration"));
        sorted.sort(Comparator.comparingInt(Migration::fromVersion));
        int expected = EnvelopeCodec.VERSION - sorted.size();
        if (expected < 0) {
            throw new IllegalArgumentException("chain");
        }
        for (Migration m : sorted) {
            if (m.fromVersion() != expected) {
                throw new IllegalArgumentException("chain");
            }
            expected++;
        }
        this.steps = List.copyOf(sorted);
    }

    /** Returns the oldest format version this build can read. */
    int oldestReadable() {
        return EnvelopeCodec.VERSION - steps.size();
    }

    /**
     * Returns whether {@code version} can be read: the current version, or an older one with a
     * chain of steps to it.
     *
     * @param version format version from a file prefix
     */
    boolean canRead(int version) {
        return version >= oldestReadable() && version <= EnvelopeCodec.VERSION;
    }

    /**
     * Returns the steps that bring {@code version} to the current version, oldest first; empty for
     * the current version.
     *
     * @param version a version for which {@link #canRead(int)} is true
     * @throws IllegalArgumentException otherwise
     */
    List<Migration> chainFrom(int version) {
        if (!canRead(version)) {
            throw new IllegalArgumentException("version");
        }
        return steps.subList(version - oldestReadable(), steps.size());
    }
}
