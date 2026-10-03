package pm.sharing.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;

/** SR-210: the page's CSP admits exactly its own inline script, and the page stores nothing. */
class WebPageTest {
    @Test
    void cspAllowsOnlyTheInlineScriptByItsHash() throws NoSuchAlgorithmException {
        String html = WebPage.HTML;
        int open = html.indexOf("<script>") + "<script>".length();
        String inline = html.substring(open, html.indexOf("</script>"));
        assertEquals(WebPage.SCRIPT, inline);
        assertEquals(html.indexOf("<script"), html.lastIndexOf("<script"), "exactly one script");
        String hash = Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(inline.getBytes(StandardCharsets.UTF_8)));
        assertEquals("default-src 'none'; script-src 'sha256-" + hash + "'; style-src 'unsafe-inline'; "
                + "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
                WebPage.contentSecurityPolicy());
    }

    @Test
    void pageUsesNoStorageNoRemoteResourcesAndNoMarkupSinks() {
        String page = WebPage.HTML.toLowerCase(Locale.ROOT);
        for (String banned : List.of("localstorage", "sessionstorage", "indexeddb", "document.cookie", "caches",
                "serviceworker", "innerhtml", "outerhtml", "document.write", "eval(", "new function", "src=",
                "href=", "http:", "onclick", "onload", "<form", "<iframe", "postmessage")) {
            assertFalse(page.contains(banned), banned);
        }
        assertTrue(page.contains("history.replacestate(null, \"\", location.pathname)"), "fragment wiped");
        assertTrue(page.contains("textcontent = text"));
        assertTrue(page.contains("\"pagehide\""));
    }
}
