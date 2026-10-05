package pm.browser.webauthn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Objects;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.Hash;

/**
 * The vendored Public Suffix List snapshot and the list algorithm (SR-116), and the RFC 3492
 * Punycode encoder that turns its Unicode rules into A-labels.
 */
@Tag("T-PK-01")
final class PublicSuffixListTest {

    private static PublicSuffixList custom(String text) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return PublicSuffixList.verified(data, HexFormat.of().formatHex(Hash.sha256(data))).orElseThrow();
    }

    /** The vendored snapshot, read through the production source. */
    static PublicSuffixList vendored() {
        return PublicSuffixList.pinned(PublicSuffixList.VENDORED).orElseThrow();
    }

    @Test
    void theVendoredSnapshotIsThePinnedFile() throws IOException {
        try (InputStream in = Objects.requireNonNull(
                PublicSuffixList.class.getResourceAsStream("public_suffix_list.dat"))) {
            byte[] data = in.readAllBytes();
            assertEquals(PublicSuffixList.SHA256, HexFormat.of().formatHex(Hash.sha256(data)));
            String text = new String(data, StandardCharsets.UTF_8);
            assertTrue(text.contains("// VERSION: " + PublicSuffixList.VERSION));
            assertTrue(text.startsWith("// This Source Code Form is subject to the terms of the Mozilla Public\n"
                    + "// License, v. 2.0."));
        }
        assertTrue(PublicSuffixList.pinned(PublicSuffixList.VENDORED).isPresent());
    }

    /** A damaged snapshot is an empty answer, never an exception or an error (fix round, item 3). */
    @Test
    void aMissingOrTamperedSnapshotIsEmptyNotAnError() throws IOException {
        byte[] good = PublicSuffixList.VENDORED.read();
        byte[] tampered = good.clone();
        tampered[tampered.length - 2] ^= 1;
        assertTrue(PublicSuffixList.pinned(() -> tampered).isEmpty());
        assertTrue(PublicSuffixList.pinned(() -> "com\n".getBytes(StandardCharsets.UTF_8)).isEmpty());
        assertTrue(PublicSuffixList.pinned(() -> new byte[0]).isEmpty());
        assertTrue(PublicSuffixList.pinned(() -> {
            throw new IOException("gone");
        }).isEmpty());
        assertTrue(PublicSuffixList.pinned(PublicSuffixList.fromResource("no_such_list.dat")).isEmpty());
        assertThrows(IOException.class, () -> PublicSuffixList.fromResource("no_such_list.dat").read());
        assertThrows(NullPointerException.class, () -> PublicSuffixList.pinned(null));
        assertThrows(NullPointerException.class, () -> PublicSuffixList.fromResource(null));
    }

    @Test
    void theSnapshotFollowsTheListAlgorithm() {
        PublicSuffixList psl = vendored();
        assertEquals("com", psl.publicSuffixOf("www.example.com"));
        assertEquals("co.uk", psl.publicSuffixOf("www.example.co.uk"));
        assertEquals("github.io", psl.publicSuffixOf("alice.github.io"));
        assertEquals("example.compute.amazonaws.com", psl.publicSuffixOf("www.example.compute.amazonaws.com"));
        assertEquals("ck", psl.publicSuffixOf("www.ck"));
        assertEquals("b.ck", psl.publicSuffixOf("a.b.ck"));
        assertEquals("xn--55qx5d.cn", psl.publicSuffixOf("shop.xn--55qx5d.cn"));
        // No rule: the last label (the list's implicit "*").
        assertEquals("example", psl.publicSuffixOf("example"));
        assertEquals("zzzunlisted", psl.publicSuffixOf("www.example.zzzunlisted"));
        assertTrue(psl.isPublicSuffix("com"));
        assertTrue(psl.isPublicSuffix("github.io"));
        assertFalse(psl.isPublicSuffix("example.com"));
    }

    @Test
    void parsingSkipsCommentsAndBlanksAndTakesTheFirstWord() {
        PublicSuffixList psl = custom("""
                // x.y

                  test  trailing words\r
                *.wild
                !keep.wild
                bücher.test
                a.b.test
                """);
        assertEquals("test", psl.publicSuffixOf("x.test"));
        assertEquals("x.wild", psl.publicSuffixOf("y.x.wild"));
        assertEquals("wild", psl.publicSuffixOf("keep.wild"));
        assertEquals("xn--bcher-kva.test", psl.publicSuffixOf("shop.xn--bcher-kva.test"));
        assertEquals("a.b.test", psl.publicSuffixOf("z.a.b.test"));
        assertEquals("trailing", psl.publicSuffixOf("trailing"));
        // A commented-out rule is not a rule.
        assertEquals("y", psl.publicSuffixOf("a.x.y"));
        assertFalse(psl.isPublicSuffix("keep.wild"));
        assertTrue(psl.isPublicSuffix("wild"));
    }

    /** RFC 3492 §7.1 sample strings, plus labels from the list. */
    @Test
    void punycodeMatchesRfc3492() {
        assertEquals("bcher-kva", Punycode.encode("bücher"));
        assertEquals("55qx5d", Punycode.encode("公司"));
        assertEquals("9tfky", Punycode.encode("ᬩᬮᬶ"));
        assertEquals("ihqwcrb4cv8a8dqg056pqjye", Punycode.encode("他们为什么不说中文"));
        assertEquals("egbpdaj6bu4bxfgehfvwxn", Punycode.encode("ليهمابتكلموشعربي؟"));
        assertEquals("3B-ww4c5e180e575a65lsy2b", Punycode.encode("3年B組金八先生"));
        assertEquals("-> $1.00 <--", Punycode.encode("-> $1.00 <-"));
        assertEquals("", Punycode.encode(""));
    }
}
