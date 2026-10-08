package pm.cli;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.function.UnaryOperator;
import pm.browser.host.ExtensionAllowlist;
import pm.browser.host.NativeHost;
import pm.tui.BrowserRelay;

/**
 * {@code pm} started by the browser as its native messaging host (ADR 0014 §8). Chrome cannot
 * pass options: it runs the manifest's {@code path} with the caller's origin
 * {@code chrome-extension://<id>/} as the first argument, so that argument is what selects this
 * mode. stdout then carries only native-messaging frames; nothing else is ever printed there.
 *
 * <p>The extension must be in the allowlist next to the default vault (the file
 * {@code pm browser install} writes), checked before a byte of stdin is read. Every request is
 * then relayed to the TUI ({@link BrowserRelay}); with no TUI open the reply is
 * {@code DENIED_LOCKED}. This process never opens the vault and never approves anything itself.
 */
final class BrowserHost {
    /** Prefix of the caller argument Chrome passes. */
    static final String CALLER_PREFIX = "chrome-extension://";

    private BrowserHost() {
    }

    /** Whether {@code args} is a browser starting the native host. */
    static boolean isHostInvocation(String[] args) {
        return args.length > 0 && args[0].startsWith(CALLER_PREFIX);
    }

    /**
     * Serves the browser on {@code in}/{@code out} until it closes the connection.
     *
     * @return {@link NativeHost#EXIT_OK}, {@link NativeHost#EXIT_PROTOCOL}, or
     *     {@link NativeHost#EXIT_REFUSED} when the caller is not allowed or no allowlist can be
     *     read (nothing is read from {@code in} then)
     */
    static int serve(String[] args, InputStream in, OutputStream out, UnaryOperator<String> properties) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");
        Path vaultFile;
        ExtensionAllowlist allowed;
        try {
            vaultFile = VaultPaths.defaultPath(properties);
            Path vaultDir = vaultFile.getParent();
            if (vaultDir == null) {
                return NativeHost.EXIT_REFUSED;
            }
            allowed = ExtensionAllowlist.read(vaultDir.resolve(ExtensionAllowlist.FILE_NAME));
        } catch (UsageException | IOException | IllegalArgumentException e) {
            return NativeHost.EXIT_REFUSED; // no home, no allowlist or a damaged one: nobody is allowed
        }
        // The relay socket's place depends on the default vault path only: the browser starts this
        // process with its own environment, which need not match the TUI's. No passkeys are served
        // through the browser in this version: those requests get an unknown type's reply.
        try {
            return NativeHost.runWithoutPasskeys(List.of(args), allowed, in, out,
                    extensionId -> request -> BrowserRelay.ask(vaultFile, extensionId, request));
        } catch (IOException e) {
            return NativeHost.EXIT_PROTOCOL; // the browser's end of stdout is gone
        }
    }
}
