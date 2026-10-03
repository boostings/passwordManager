package pm.approval.run;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.ApprovalRequest;
import pm.crypto.SecretBytes;

/** approval-model §6 and SR-102: the argv shown is the argv executed, with no shell in between. */
class EnvRunnerTest {
    private static final Path SH = Path.of("/bin/sh");

    @TempDir
    Path tmp;

    private static ApprovalRequest inject(List<String> argv, Optional<java.util.SortedSet<String>> vars) {
        return new ApprovalRequest(UUID.randomUUID(), new ApprovalRequest.Requester(ApprovalRequest.Kind.CLI, "pm env run"),
                ApprovalRequest.Operation.ENV_INJECT, new ApprovalRequest.Scope("app", "dev", vars, List.of()),
                Duration.ZERO, new ApprovalRequest.Display(argv, Optional.empty(), ApprovalRequest.Effect.INJECT),
                Instant.now());
    }

    private static SortedMap<String, SecretBytes> vars(String name, String value) {
        SortedMap<String, SecretBytes> m = new TreeMap<>();
        m.put(name, SecretBytes.copyOf(value.getBytes(StandardCharsets.UTF_8)));
        return m;
    }

    private static int waitFor(Process p) throws InterruptedException {
        return p.waitFor();
    }

    @Test
    void argvShownIsArgvExecutedWithoutShellExpansion() throws IOException, InterruptedException {
        assumeTrue(Files.isExecutable(SH), "needs /bin/sh as the test's child program");
        Path out = tmp.resolve("args");
        // The child script prints its arguments one per line; pm itself never invokes a shell.
        List<String> argv = List.of(SH.toString(), "-c", "printf '%s\\n' \"$@\" > \"$0\"", out.toString(),
                "a b", "$(touch " + tmp.resolve("pwned") + ")", ";", "*", "`id`");
        ApprovalRequest q = inject(argv, Optional.empty());
        assertEquals(0, waitFor(EnvRunner.start(q, new TreeMap<>(), Set.of(), tmp, ProcessBuilder.Redirect.DISCARD)));
        assertEquals(q.display().argv().subList(4, argv.size()),
                Files.readAllLines(out, StandardCharsets.UTF_8), "each element arrives intact and unexpanded");
        assertFalse(Files.exists(tmp.resolve("pwned")));
    }

    @Test
    void approvedVariablesReachTheChildAndScrubbedOnesDoNot() throws IOException, InterruptedException {
        assumeTrue(Files.isExecutable(SH), "needs /bin/sh as the test's child program");
        Path out = tmp.resolve("env");
        ApprovalRequest q = inject(List.of(SH.toString(), "-c", "printf '%s|%s' \"$DB\" \"${HOME:-unset}\" > \"$0\"",
                out.toString()), Optional.of(new TreeSet<>(Set.of("DB"))));
        SortedMap<String, SecretBytes> v = vars("DB", "pa$$ word\n2");
        try {
            assertEquals(0, waitFor(EnvRunner.start(q, v, Set.of("HOME"), tmp, ProcessBuilder.Redirect.DISCARD)));
        } finally {
            v.values().forEach(SecretBytes::close);
        }
        assertEquals("pa$$ word\n2|unset", Files.readString(out, StandardCharsets.UTF_8));
    }

    @Test
    void exitCodeIsPassedThroughAndMissingProgramIs127() {
        assumeTrue(Files.isExecutable(SH), "needs /bin/sh as the test's child program");
        assertEquals(7, EnvRunner.run(inject(List.of(SH.toString(), "-c", "exit 7"), Optional.empty()),
                new TreeMap<>(), Set.of(), tmp));
        assertEquals(EnvRunner.NOT_STARTED, EnvRunner.run(inject(List.of(tmp.resolve("absent").toString()),
                Optional.empty()), new TreeMap<>(), Set.of(), tmp));
    }

    @Test
    void variablesOutsideTheApprovedScopeAreRefused() {
        ApprovalRequest q = inject(List.of("/bin/true"), Optional.of(new TreeSet<>(Set.of("DB"))));
        SortedMap<String, SecretBytes> v = vars("OTHER", "x");
        try {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> EnvRunner.start(q, v, Set.of(), tmp, ProcessBuilder.Redirect.DISCARD));
            assertEquals("NOT_APPROVED", e.getMessage());
        } finally {
            v.values().forEach(SecretBytes::close);
        }
    }

    @Test
    void releaseCopiesOnlyTheScopedVariables() {
        SortedMap<String, SecretBytes> profile = new TreeMap<>(vars("A", "1"));
        profile.putAll(vars("B", "2"));
        try {
            SortedMap<String, SecretBytes> some = EnvRelease.copy(profile,
                    new ApprovalRequest.Scope("app", "dev", Optional.of(new TreeSet<>(Set.of("B"))), List.of()));
            assertEquals(Set.of("B"), some.keySet());
            some.values().forEach(SecretBytes::close);
            assertFalse(profile.get("B").isClosed(), "closing the copy leaves the vault's value alone");
            SortedMap<String, SecretBytes> all = EnvRelease.copy(profile, ApprovalRequest.Scope.profile("app", "dev"));
            assertEquals(Set.of("A", "B"), all.keySet());
            all.values().forEach(SecretBytes::close);
            assertThrows(IllegalArgumentException.class, () -> EnvRelease.copy(profile,
                    new ApprovalRequest.Scope("app", "dev", Optional.of(new TreeSet<>(Set.of("C"))), List.of())));
            assertTrue(profile.values().stream().noneMatch(SecretBytes::isClosed));
        } finally {
            profile.values().forEach(SecretBytes::close);
        }
    }
}
