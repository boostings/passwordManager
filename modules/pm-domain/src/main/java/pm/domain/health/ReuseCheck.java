package pm.domain.health;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.Hmac;
import pm.crypto.SecretBytes;

/**
 * Finds passwords used by more than one record without keeping a map from password to record
 * (ADR 0012 §6).
 *
 * <p>Each run draws a fresh 256-bit key from {@code Csprng} and computes HMAC-SHA256 of every
 * password under it. Only those tags are compared, never the passwords. Tags are bucketed by their
 * first four bytes (a keyed, per-run value that tells nothing about the password once the key is
 * gone) and compared within a bucket with {@link ConstantTime#equals}. The key and every tag are
 * zero-filled before {@link #find} returns, so nothing that outlives the call can link two records.
 */
public final class ReuseCheck {
    private static final int KEY_BYTES = 32;
    private static final int BUCKET_BYTES = 4;
    private static final int MIN_GROUP = 2;

    private ReuseCheck() {
    }

    /** One password to compare. The caller keeps ownership of {@code password}. */
    public record Entry(UUID id, SecretBytes password) {
        /**
         * Checks the components.
         *
         * @throws NullPointerException if a component is null
         */
        public Entry {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(password, "password");
        }
    }

    /**
     * Returns the groups of two or more entries whose passwords are identical, largest group first;
     * ids within a group keep input order. Empty passwords are ignored.
     */
    public static List<ReuseGroup> find(List<Entry> entries) {
        Objects.requireNonNull(entries, "entries");
        List<Entry> nonEmpty = entries.stream().filter(e -> e.password().length() > 0).toList();
        byte[][] tags = new byte[nonEmpty.size()][];
        try (SecretBytes key = Csprng.secretBytes(KEY_BYTES)) {
            for (int i = 0; i < tags.length; i++) {
                tags[i] = nonEmpty.get(i).password().apply(p -> tag(key, p));
            }
            return group(nonEmpty, tags);
        } finally {
            for (byte[] t : tags) {
                if (t != null) {
                    Arrays.fill(t, (byte) 0);
                }
            }
        }
    }

    private static byte[] tag(SecretBytes key, byte[] password) {
        try {
            return Hmac.sha256(key, password);
        } catch (CryptoException e) {
            // A 32-byte key is always accepted; only a JCA failure lands here, and it carries a code only.
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    private static List<ReuseGroup> group(List<Entry> entries, byte[][] tags) {
        Map<Integer, List<Integer>> buckets = new HashMap<>();
        for (int i = 0; i < tags.length; i++) {
            buckets.computeIfAbsent(bucket(tags[i]), b -> new ArrayList<>()).add(i);
        }
        int[] parent = new int[tags.length];
        for (int i = 0; i < parent.length; i++) {
            parent[i] = i;
        }
        for (List<Integer> members : buckets.values()) {
            for (int a = 0; a < members.size(); a++) {
                for (int b = a + 1; b < members.size(); b++) {
                    int x = members.get(a);
                    int y = members.get(b);
                    if (ConstantTime.equals(tags[x], tags[y])) {
                        parent[root(parent, y)] = root(parent, x);
                    }
                }
            }
        }
        Map<Integer, List<UUID>> byRoot = new HashMap<>();
        List<List<UUID>> ordered = new ArrayList<>();
        for (int i = 0; i < tags.length; i++) {
            List<UUID> ids = byRoot.computeIfAbsent(root(parent, i), r -> {
                List<UUID> fresh = new ArrayList<>();
                ordered.add(fresh);
                return fresh;
            });
            ids.add(entries.get(i).id());
        }
        return ordered.stream()
                .filter(ids -> ids.size() >= MIN_GROUP)
                .sorted(Comparator.comparingInt((List<UUID> ids) -> ids.size()).reversed())
                .map(ReuseGroup::new)
                .toList();
    }

    private static int root(int[] parent, int i) {
        int r = i;
        while (parent[r] != r) {
            r = parent[r];
        }
        return r;
    }

    private static int bucket(byte[] t) {
        int b = 0;
        for (int i = 0; i < BUCKET_BYTES; i++) {
            b = (b << Byte.SIZE) | (t[i] & 0xff);
        }
        return b;
    }
}
