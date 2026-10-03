package pm.sharing.web;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import pm.crypto.Hash;

/**
 * The one page a browser recipient loads (lan-share.md §7 step 4). Its only script is inline and
 * allowed by hash; it reads {@code k_web} from the fragment, removes the fragment from the address
 * bar and the session history entry (the browser's history database still records the full URL;
 * ADR 0010 Amendment 2), fetches the ciphertext once, decrypts with WebCrypto, shows the text with
 * {@code textContent}, and clears it after a countdown or when the page is left ({@code pagehide}). It uses no
 * storage API, no cookies and no service worker.
 */
final class WebPage {
    /** Seconds the decrypted text stays on screen. */
    static final int SHOW_SECONDS = 120;

    static final String SCRIPT = """
            "use strict";
            (async function () {
              const box = document.getElementById("v");
              const status = document.getElementById("s");
              const copy = document.getElementById("c");
              let text = "";
              function wipe(reason) {
                text = "";
                box.textContent = "";
                copy.disabled = true;
                status.textContent = reason;
              }
              copy.addEventListener("click", function () {
                if (text) {
                  navigator.clipboard.writeText(text);
                }
              });
              addEventListener("pagehide", function () { wipe("Cleared."); });
              const fragment = location.hash.slice(1);
              history.replaceState(null, "", location.pathname);
              const id = location.pathname.split("/").pop();
              try {
                if (!/^[0-9a-f]{32}$/.test(id) || !/^[A-Za-z0-9_-]{43}$/.test(fragment)) {
                  throw new Error("link");
                }
                const raw = Uint8Array.from(atob(fragment.replace(/-/g, "+").replace(/_/g, "/") + "="),
                    function (c) { return c.charCodeAt(0); });
                const aad = Uint8Array.from(id.match(/../g), function (h) { return parseInt(h, 16); });
                const res = await fetch("/d/" + id, {cache: "no-store", credentials: "omit"});
                if (!res.ok) {
                  throw new Error("gone");
                }
                const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
                raw.fill(0);
                const plain = await crypto.subtle.decrypt(
                    {name: "AES-GCM", iv: new Uint8Array(12), additionalData: aad, tagLength: 128},
                    key, await res.arrayBuffer());
                text = new TextDecoder("utf-8", {fatal: true}).decode(plain);
                box.textContent = text;
                copy.disabled = false;
                let left = SHOW_SECONDS;
                status.textContent = "Clears in " + left + " s";
                const timer = setInterval(function () {
                  left -= 1;
                  if (left <= 0) {
                    clearInterval(timer);
                    wipe("Cleared. Close this tab.");
                  } else {
                    status.textContent = "Clears in " + left + " s";
                  }
                }, 1000);
              } catch (e) {
                wipe("This link cannot be opened. It was already used, it has expired, or it is damaged.");
              }
            })();
            """.replace("SHOW_SECONDS", Integer.toString(SHOW_SECONDS));

    static final String HTML = """
            <!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="referrer" content="no-referrer">
            <title>Shared secret</title>
            <style>
            body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 2rem auto; padding: 0 1rem;
                   color: #1b1b1f; background: #fafafa; }
            pre { white-space: pre-wrap; word-break: break-all; background: #fff; border: 1px solid #ccc;
                  padding: 1rem; min-height: 3rem; }
            button { font: inherit; padding: .4rem 1rem; }
            p.note { color: #555; font-size: .9rem; }
            @media (prefers-color-scheme: dark) {
              body { color: #e6e6e9; background: #17171a; }
              pre { background: #222226; border-color: #444; }
              p.note { color: #aaa; }
            }
            </style>
            </head>
            <body>
            <h1>Shared secret</h1>
            <p id="s">Decrypting&hellip;</p>
            <pre id="v"></pre>
            <p><button id="c" type="button" disabled>Copy</button></p>
            <p class="note">This page can be opened once. The text is decrypted in this browser with a key
            that was never sent over the network, and it is cleared from the page after SHOW_SECONDS seconds or when
            you leave. Your browser warned about the certificate because the sender's computer made it for
            this one share; compare its fingerprint with the one the sender sees.</p>
            <script>SCRIPT</script>
            </body>
            </html>
            """.replace("SHOW_SECONDS", Integer.toString(SHOW_SECONDS))
            .replace("<script>SCRIPT</script>", "<script>" + SCRIPT + "</script>");

    private WebPage() {
    }

    /** The CSP source for the inline script: {@code 'sha256-<base64>'}. */
    static String scriptSource() {
        return "'sha256-" + Base64.getEncoder().encodeToString(Hash.sha256(SCRIPT.getBytes(StandardCharsets.UTF_8)))
                + "'";
    }

    /** The Content-Security-Policy sent with every response. */
    static String contentSecurityPolicy() {
        return "default-src 'none'; script-src " + scriptSource() + "; style-src 'unsafe-inline'; connect-src 'self'; "
                + "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
    }
}
