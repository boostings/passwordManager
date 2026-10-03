package pm.domain.env;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.record.ProjectRecord;
import pm.vault.record.VaultRecord;

class ProjectEnvTest {
    private static final Instant T0 = Instant.parse("2026-10-01T12:00:00Z");
    private static final Path ROOT = java.util.Objects.requireNonNull(Path.of("").toAbsolutePath().getRoot()).resolve("work").resolve("app");

    static EnvEntry entry(String name, String value) {
        return new EnvEntry(name, SecretBytes.copyOf(value.getBytes(StandardCharsets.UTF_8)));
    }

    static String text(SecretBytes s) {
        return s.apply(b -> new String(b, StandardCharsets.UTF_8));
    }

    static ProjectRecord empty(String title, Path dir) {
        return ProjectEnv.newProject(UUID.randomUUID(), title, dir, "", T0);
    }

    @Test
    void profilesAreSeparateNamespaces() {
        try (ProjectRecord p0 = empty("app", ROOT);
             ProjectRecord p1 = ProjectEnv.withProfile(p0, "dev", List.of(entry("DB", "dev-db"), entry("KEY", "k1")), T0);
             ProjectRecord p = ProjectEnv.withProfile(p1, "prod", List.of(entry("DB", "prod-db")), T0.plusSeconds(5));
             ProjectRecord replaced = ProjectEnv.withProfile(p, "dev", List.of(entry("ONLY", "1")), T0)) {
            assertEquals(Set.of("dev", "prod"), ProjectEnv.profiles(p));
            assertEquals(List.of("DB", "KEY"), List.copyOf(ProjectEnv.variables(p, "dev").keySet()));
            assertEquals("prod-db", text(ProjectEnv.variables(p, "prod").get("DB")));
            assertEquals(T0.plusSeconds(5), p.updated());

            assertEquals(Set.of("ONLY"), ProjectEnv.variables(replaced, "dev").keySet(), "replace, not merge");
            assertSame(ProjectEnv.variables(p, "prod").get("DB"), ProjectEnv.variables(replaced, "prod").get("DB"));
        }
    }

    @Test
    void unprefixedKeysBelongToDefault() {
        try (ProjectRecord p = new ProjectRecord(UUID.randomUUID(), "legacy", ROOT.toString(), "",
                Map.of("TOKEN_A", SecretBytes.copyOf(new byte[] {1})), Map.of(), T0, T0)) {
            assertEquals(Set.of(ProjectEnv.DEFAULT_PROFILE), ProjectEnv.profiles(p));
            assertTrue(ProjectEnv.variables(p, "default").containsKey("TOKEN_A"));
        }
    }

    @Test
    void validatesProfilesAndDuplicates() {
        try (ProjectRecord p = empty("app", ROOT)) {
            for (String bad : List.of("", "Dev", "a/b", "-x", "x".repeat(33))) {
                assertFalse(ProjectEnv.isValidProfile(bad), bad);
                assertThrows(IllegalArgumentException.class, () -> ProjectEnv.variables(p, bad));
            }
            assertThrows(IllegalArgumentException.class,
                    () -> ProjectEnv.withProfile(p, "dev", List.of(entry("A", "1"), entry("A", "2")), T0));
        }
        assertThrows(IllegalArgumentException.class, () -> empty("x", Path.of("rel")));
    }

    @Test
    void findsTheNearestRegisteredDirectory() {
        try (ProjectRecord outer = empty("outer", ROOT);
             ProjectRecord inner = empty("inner", ROOT.resolve("svc"))) {
            List<VaultRecord> all = List.of(outer, inner);
            assertEquals(Optional.of(inner), ProjectEnv.forDirectory(all, ROOT.resolve("svc").resolve("src")));
            assertEquals(Optional.of(outer), ProjectEnv.forDirectory(all, ROOT.resolve("web")));
            assertEquals(Optional.empty(), ProjectEnv.forDirectory(all, ROOT.getParent()));
            assertEquals(Optional.empty(), ProjectEnv.forDirectory(all, ROOT.resolveSibling("app2")),
                    "path prefix is by component, not by string");
            assertEquals(Optional.of(inner), ProjectEnv.byTitle(all, "inner"));
        }
    }
}
