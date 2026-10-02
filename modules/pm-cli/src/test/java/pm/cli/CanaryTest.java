package pm.cli;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pm.vault.VaultException;

/** SR-500: the canary passphrase never reaches stdout or stderr, on success or failure paths. */
class CanaryTest {
    private static final String CANARY = MainArgsTest.CANARY;
    private static final Instant NOW = Instant.parse("2026-10-02T12:00:00Z");

    /** One scripted invocation: port factory, console script, args. */
    private record Scenario(Supplier<FakeVaultPort> port, Supplier<FakeConsoleIo> io, List<String> args) {
    }

    private static Arguments scenario(String name, Supplier<FakeVaultPort> port, Supplier<FakeConsoleIo> io,
            String... args) {
        return Arguments.of(Named.of(name, new Scenario(port, io, List.of(args))));
    }

    private static FakeVaultPort populated() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        port.stored.add(FakeVaultPort.login("GitHub", CANARY, NOW));
        return port;
    }

    static Stream<Arguments> scenarios() {
        return Stream.of(
                scenario("init", FakeVaultPort::new, () -> new FakeConsoleIo().secret(CANARY).secret(CANARY), "init"),
                scenario("init mismatch", FakeVaultPort::new,
                        () -> new FakeConsoleIo().secret(CANARY).secret(CANARY + "!"), "init"),
                scenario("init exists", CanaryTest::populated,
                        () -> new FakeConsoleIo().secret(CANARY).secret(CANARY), "init"),
                scenario("add-login", CanaryTest::populated, () -> new FakeConsoleIo().secret(CANARY)
                        .line("Site").line("bob").secret(CANARY).line("https://x").line("t"), "add-login"),
                scenario("list", CanaryTest::populated, () -> new FakeConsoleIo().secret(CANARY), "list"),
                scenario("search", CanaryTest::populated, () -> new FakeConsoleIo().secret(CANARY), "search", "git"),
                scenario("wrong passphrase", () -> new FakeVaultPort().withVault("other"),
                        () -> new FakeConsoleIo().secret(CANARY), "list"),
                scenario("corrupt", () -> populated().failing(VaultException.Code.CORRUPT),
                        () -> new FakeConsoleIo().secret(CANARY), "list"),
                scenario("passphrase as argument", CanaryTest::populated, FakeConsoleIo::new, "list", CANARY),
                scenario("tui", CanaryTest::populated, FakeConsoleIo::new, "tui"));
    }

    @ParameterizedTest
    @MethodSource("scenarios")
    void canaryNeverReachesOutput(Scenario s) {
        FakeVaultPort port = s.port().get();
        FakeConsoleIo io = s.io().get();
        Cli cli = new Cli(Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, "/home/alice")::get,
                Clock.fixed(NOW, ZoneOffset.UTC), p -> { });

        cli.run(s.args().toArray(String[]::new), io, path -> port);

        assertFalse(io.outText().contains(CANARY), "stdout leaked the canary");
        assertFalse(io.errText().contains(CANARY), "stderr leaked the canary");
        assertTrue(io.allSecretsZeroed(), "every readPassword buffer zeroed");
    }
}
