package pm.domain.env;

import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import pm.crypto.SecretBytes;
import pm.vault.record.ProjectRecord;
import pm.vault.record.VaultRecord;

/**
 * Environment profiles stored in a {@link ProjectRecord} (plan.md §13 M2, ADR 0011). A project
 * keeps every variable of every profile in its one {@code variables} map, keyed
 * {@code <profile>/<NAME>}; a key without {@code /} belongs to {@link #DEFAULT_PROFILE}. This keeps
 * the M1 vault format unchanged.
 *
 * <p>Maps returned here share their {@link SecretBytes} with the record, which still owns them:
 * callers must not close them.
 */
public final class ProjectEnv {
    /** Profile used when none is named. */
    public static final String DEFAULT_PROFILE = "default";
    /** Separator between profile and variable name in a stored key. */
    static final char SEPARATOR = '/';

    private static final Pattern PROFILE = Pattern.compile("[a-z0-9][a-z0-9_-]{0,31}");

    private ProjectEnv() {
    }

    /** True if {@code profile} is a valid profile name: lower-case letters, digits, - and _, 1–32 chars. */
    public static boolean isValidProfile(String profile) {
        return PROFILE.matcher(Objects.requireNonNull(profile, "profile")).matches();
    }

    /** The stored key for {@code name} in {@code profile}. */
    static String key(String profile, String name) {
        return profile + SEPARATOR + name;
    }

    /** Every profile with at least one variable, sorted. */
    public static SortedSet<String> profiles(ProjectRecord project) {
        SortedSet<String> names = new TreeSet<>();
        for (String key : project.variables().keySet()) {
            int slash = key.indexOf(SEPARATOR);
            names.add(slash < 0 ? DEFAULT_PROFILE : key.substring(0, slash));
        }
        return names;
    }

    /**
     * The variables of {@code profile}, sorted by name. The values stay owned by {@code project}.
     *
     * @throws IllegalArgumentException {@code BAD_PROFILE} for an invalid profile name
     */
    public static SortedMap<String, SecretBytes> variables(ProjectRecord project, String profile) {
        checkProfile(profile);
        SortedMap<String, SecretBytes> out = new TreeMap<>();
        project.variables().forEach((key, value) -> {
            int slash = key.indexOf(SEPARATOR);
            String owner = slash < 0 ? DEFAULT_PROFILE : key.substring(0, slash);
            if (owner.equals(profile)) {
                out.put(key.substring(slash + 1), value);
            }
        });
        return out;
    }

    /**
     * Returns a copy of {@code project} whose {@code profile} holds exactly {@code entries}. The new
     * record takes ownership of the entries' values; values of other profiles are shared with
     * {@code project} (the vault retires the old record on {@code put} and closes it on lock).
     *
     * @throws IllegalArgumentException {@code BAD_PROFILE}, {@code DUPLICATE_NAME}, or a record
     *     limit if the project would exceed one
     */
    public static ProjectRecord withProfile(ProjectRecord project, String profile,
            Collection<EnvEntry> entries, Instant now) {
        checkProfile(profile);
        Map<String, SecretBytes> merged = new HashMap<>();
        project.variables().forEach((key, value) -> {
            int slash = key.indexOf(SEPARATOR);
            String owner = slash < 0 ? DEFAULT_PROFILE : key.substring(0, slash);
            if (!owner.equals(profile)) {
                merged.put(key, value);
            }
        });
        entries.forEach(e -> {
            if (merged.put(key(profile, e.name()), e.value()) != null) {
                throw new IllegalArgumentException("DUPLICATE_NAME");
            }
        });
        return new ProjectRecord(project.id(), project.title(), project.canonicalPath(), project.gitRemote(),
                merged, project.config(), project.created(), now.truncatedTo(ChronoUnit.SECONDS));
    }

    /** A new, empty project for {@code directory}, which must be absolute and already canonical. */
    public static ProjectRecord newProject(UUID id, String title, Path directory, String gitRemote, Instant now) {
        if (!directory.isAbsolute()) {
            throw new IllegalArgumentException("NOT_ABSOLUTE");
        }
        Instant at = now.truncatedTo(ChronoUnit.SECONDS);
        return new ProjectRecord(id, title, directory.toString(), gitRemote, Map.of(), Map.of(), at, at);
    }

    /**
     * The project registered for {@code directory}: the one whose path is {@code directory} or its
     * nearest ancestor. {@code directory} must already be canonical (real path).
     */
    public static Optional<ProjectRecord> forDirectory(List<VaultRecord> records, Path directory) {
        return projects(records)
                .filter(p -> {
                    Path root = Path.of(p.canonicalPath());
                    return root.isAbsolute() && directory.startsWith(root);
                })
                .max(Comparator.comparingInt(p -> Path.of(p.canonicalPath()).getNameCount()));
    }

    /** Finds a project by exact title. */
    public static Optional<ProjectRecord> byTitle(List<VaultRecord> records, String title) {
        return projects(records).filter(p -> p.title().equals(title)).findFirst();
    }

    /** The project records among {@code records}. */
    public static Stream<ProjectRecord> projects(List<VaultRecord> records) {
        return records.stream().filter(ProjectRecord.class::isInstance).map(ProjectRecord.class::cast);
    }

    private static void checkProfile(String profile) {
        if (!isValidProfile(profile)) {
            throw new IllegalArgumentException("BAD_PROFILE");
        }
    }
}
