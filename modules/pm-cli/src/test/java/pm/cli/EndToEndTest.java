package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.crypto.Csprng;

/**
 * M1.3 end-to-end test (SR-500): drives {@link Cli} over the real {@link FileVaultPort},
 * {@code VaultService} and {@code VaultFileStore} stack against a vault file on disk. No fake
 * vault port is involved; only the terminal is scripted ({@link FakeConsoleIo}).
 *
 * <p>Flow: {@code init} with the canary passphrase, {@code add-login}, {@code list}, then a
 * <em>new</em> {@link Cli} and port reopen and unlock the same file and {@code list} shows the
 * record, and finally a wrong passphrase exits with {@link ExitCodes#WRONG_CREDENTIAL}. After every
 * step the canary must be absent from captured stdout and stderr. The Gradle test task sets
 * {@code pm.canary.secret}, and the CI canary grep then checks every report and log under
 * {@code modules/*}{@code /build} for it as well.
 *
 * <p>The vault lives in {@code <tempdir>/v/vault.pmv}. {@code VaultFileStore} refuses a vault
 * whose existing parent directory is group- or other-accessible, and JUnit's {@code @TempDir} is
 * created with the process umask (typically {@code 755}). So the test leaves {@code v} absent and
 * lets the store create it owner-only ({@code rwx------}), exactly as it does for a first-run
 * default path.
 *
 * <p>Speed: {@link Cli#kdfFor} is the seam the production opener uses to pick Argon2id parameters;
 * here its tuner returns {@link Argon2Params#FLOOR} instead of benchmarking, so each init or unlock
 * costs one floor-cost hash and nothing loops Argon2.
 */
class EndToEndTest {
    private static final String CANARY_PROPERTY = "pm.canary.secret";
    private static final int FALLBACK_CANARY_BYTES = 16;
    private static final String CANARY = canaryFromBuild();
    private static final String LOGIN_SECRET = "e2e-login-secret-5b1d";
    private static final String WRONG_PASSPHRASE = "definitely-not-the-passphrase";
    private static final String TITLE = "GitHub";
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");

    @TempDir
    Path tempDir;

    /**
     * The canary from the Gradle test task; when run outside Gradle (an IDE) a random one, so the
     * leak assertions still mean something.
     */
    private static String canaryFromBuild() {
        return Optional.ofNullable(System.getProperty(CANARY_PROPERTY))
                .filter(s -> !s.isEmpty())
                .orElseGet(() -> "CANARY-" + HexFormat.of().formatHex(Csprng.bytes(FALLBACK_CANARY_BYTES)));
    }

    @Test
    void initAddListReopenAndRejectWrongPassphrase() throws IOException {
        Path vault = tempDir.resolve("v").resolve("vault.pmv");

        FakeConsoleIo init = new FakeConsoleIo().secret(CANARY).secret(CANARY);
        assertEquals(ExitCodes.OK, run(vault, init, "init"), init::errText);
        assertTrue(init.outText().contains(Messages.VAULT_CREATED.text()));
        assertTrue(Files.isRegularFile(vault), "init wrote the vault file");
        assertNoLeak(init);

        FakeConsoleIo add = new FakeConsoleIo().secret(CANARY)
                .line(TITLE).line("alice").secret(LOGIN_SECRET).line("https://github.com").line("dev");
        assertEquals(ExitCodes.OK, run(vault, add, "add-login"), add::errText);
        assertTrue(add.outText().contains(Messages.LOGIN_ADDED.text()));
        assertNoLeak(add);

        FakeConsoleIo list = new FakeConsoleIo().secret(CANARY);
        assertEquals(ExitCodes.OK, run(vault, list, "list"), list::errText);
        assertTrue(list.outText().contains(TITLE), "list shows the new login");
        assertNoLeak(list);

        // run() builds a fresh Cli and FileVaultPort, so this reopens the file from disk and takes
        // the store lock again: it would fail with LOCKED if an earlier command leaked its store.
        FakeConsoleIo reopened = new FakeConsoleIo().secret(CANARY);
        assertEquals(ExitCodes.OK, run(vault, reopened, "list"), reopened::errText);
        assertTrue(reopened.outText().contains(TITLE), "the reopened vault still holds the login");
        assertNoLeak(reopened);

        FakeConsoleIo wrong = new FakeConsoleIo().secret(WRONG_PASSPHRASE);
        assertEquals(ExitCodes.WRONG_CREDENTIAL, run(vault, wrong, "list"));
        assertTrue(wrong.errText().contains(Messages.ERR_WRONG_CREDENTIAL.text()));
        assertFalse(wrong.outText().contains(TITLE), "nothing is listed without the passphrase");
        assertNoLeak(wrong);

        String onDisk = new String(Files.readAllBytes(vault), StandardCharsets.ISO_8859_1);
        assertFalse(onDisk.contains(CANARY), "the passphrase is not stored in the vault file");
        assertFalse(onDisk.contains(LOGIN_SECRET), "the login password is encrypted at rest");
    }

    /** One invocation through a new {@link Cli} and a new real port, as a separate process would. */
    private static int run(Path vault, FakeConsoleIo io, String command) {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        Cli cli = new Cli(Map.<String, String>of()::get, clock,
                port -> fail("the end-to-end flow never launches the TUI"));
        String[] args = {"--vault", vault.toString(), command};
        return cli.run(args, io,
                (path, creating) -> new FileVaultPort(path, clock, Cli.kdfFor(creating, () -> Argon2Params.FLOOR)));
    }

    /** SR-500: neither secret reaches stdout or stderr, and every passphrase buffer was zeroed. */
    private static void assertNoLeak(FakeConsoleIo io) {
        assertFalse(io.outText().contains(CANARY), "stdout leaked the canary passphrase");
        assertFalse(io.errText().contains(CANARY), "stderr leaked the canary passphrase");
        assertFalse(io.outText().contains(LOGIN_SECRET), "stdout leaked the login password");
        assertFalse(io.errText().contains(LOGIN_SECRET), "stderr leaked the login password");
        assertTrue(io.allSecretsZeroed(), "every readPassword buffer zeroed");
    }
}
