package pm.domain.health;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Records that share one password.
 *
 * @param ids the records' ids, at least two
 */
public record ReuseGroup(List<UUID> ids) {
    private static final int MIN_IDS = 2;

    /**
     * Checks the group and takes an unmodifiable copy.
     *
     * @throws NullPointerException if {@code ids} or an element is null
     * @throws IllegalArgumentException if fewer than two ids are given
     */
    public ReuseGroup {
        ids = List.copyOf(Objects.requireNonNull(ids, "ids"));
        if (ids.size() < MIN_IDS) {
            throw new IllegalArgumentException("a reuse group has at least two records");
        }
    }
}
