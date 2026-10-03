package pm.sharing.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.CryptoException;

/**
 * Runs the page's real inline script under Node's WebCrypto with a stubbed DOM, to prove that the
 * browser side decrypts what {@link WebShare} seals (same key, zero nonce, id as associated data)
 * and removes the fragment. Skipped when {@code node} is not on the PATH.
 */
class NodePageTest {
    private static final String HARNESS = """
            const fs = require("fs");
            const vm = require("vm");
            const [script, path, hash, ctHex] = process.argv.slice(2);
            const els = {};
            for (const n of ["v", "s", "c"]) {
              els[n] = {textContent: "", disabled: true, addEventListener() {}};
            }
            const loc = {pathname: path, hash: hash};
            const fetched = [];
            Object.assign(globalThis, {
              document: {getElementById: (n) => els[n]},
              location: loc,
              history: {replaceState(a, b, p) { loc.hash = ""; loc.replaced = p; }},
              addEventListener() {},
              setInterval() { return 0; },
              clearInterval() {},
              fetch: async (p, o) => {
                fetched.push(p + " " + o.cache + " " + o.credentials);
                return {ok: ctHex !== "", arrayBuffer: async () => Uint8Array.from(Buffer.from(ctHex, "hex")).buffer};
              },
            });
            vm.runInThisContext(fs.readFileSync(script, "utf8"));
            setTimeout(() => {
              console.log(JSON.stringify([els.v.textContent, els.c.disabled, loc.hash, loc.replaced, fetched]));
            }, 500);
            """;

    @TempDir
    Path dir;

    @Test
    void thePageDecryptsWhatTheSenderSealedAndWipesTheFragment() throws IOException, InterruptedException,
            CryptoException {
        try (WebShare share = WebServerTest.share(Duration.ofMinutes(5))) {
            String url = share.url(InetAddress.getLoopbackAddress(), 1);
            String path = "/s/" + share.id();
            String fragment = url.substring(url.indexOf('#'));
            String ct = HexFormat.of().formatHex(share.ciphertext());
            assertEquals("[\"DB_PASSWORD=correct horse\",false,\"\",\"" + path + "\",[\"/d/" + share.id()
                    + " no-store omit\"]]", node(path, fragment, ct));
            String wrong = fragment.substring(0, 5) + (fragment.charAt(5) == 'A' ? 'B' : 'A') + fragment.substring(6);
            assertEquals("[\"\",true,\"\",\"" + path + "\",[\"/d/" + share.id() + " no-store omit\"]]",
                    node(path, wrong, ct), "a wrong key shows nothing");
            assertEquals("[\"\",true,\"\",\"" + path + "\",[]]", node(path, "#short", ct), "a damaged link fetches nothing");
            assertEquals("[\"\",true,\"\",\"" + path + "\",[\"/d/" + share.id() + " no-store omit\"]]",
                    node(path, fragment, ""), "a refused fetch shows nothing");
        }
    }

    private String node(String path, String fragment, String ciphertextHex) throws IOException, InterruptedException {
        String nodeBinary = findNode();
        assumeTrue(nodeBinary != null, "node is not installed");
        Path script = Files.writeString(dir.resolve("page.js"), WebPage.SCRIPT);
        Path harness = Files.writeString(dir.resolve("harness.js"), HARNESS);
        Process p = new ProcessBuilder(List.of(nodeBinary, harness.toString(), script.toString(), path, fragment,
                ciphertextHex)).redirectErrorStream(true).start();
        assumeTrue(p.waitFor(30, TimeUnit.SECONDS), "node timed out");
        return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
    }

    private static String findNode() {
        for (String d : System.getenv().getOrDefault("PATH", "").split(java.io.File.pathSeparator, -1)) {
            Path candidate = Path.of(d, "node");
            if (Files.isExecutable(candidate)) {
                return candidate.toString();
            }
        }
        return null;
    }
}
