package pm.domain.generate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The bundled passphrase wordlist: {@value #SIZE} distinct lowercase words of four or five letters,
 * so each uniformly drawn word carries exactly 13 bits.
 *
 * <p>Derived deterministically from {@code /usr/share/dict/web2} (Webster's Second International,
 * public domain); the exact pipeline and checksums are in ADR 0012. The list is checked on load:
 * size, alphabet, word length, strict sort order and uniqueness, so a corrupted resource fails
 * loudly instead of silently lowering entropy.
 */
public final class Wordlist {
    /** Number of words. */
    public static final int SIZE = 8192;
    /** Entropy of one uniformly drawn word, in bits. */
    public static final double BITS_PER_WORD = 13.0;
    private static final String RESOURCE = "wordlist.txt";
    private static final Pattern WORD_SHAPE = Pattern.compile("[a-z]{4,5}");
    private static final List<String> LIST = load();

    private Wordlist() {
    }

    /** Returns the word at {@code index}, {@code 0 <= index < SIZE}. */
    public static String word(int index) {
        return LIST.get(index);
    }

    /** Returns the whole list, unmodifiable, in sorted order. */
    public static List<String> words() {
        return List.copyOf(LIST); // the same immutable instance; the call keeps the field private
    }

    private static List<String> load() {
        try (InputStream in = Objects.requireNonNull(Wordlist.class.getResourceAsStream(RESOURCE), "wordlist");
                BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            List<String> words = new ArrayList<>(SIZE);
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                words.add(line);
            }
            return validate(words);
        } catch (IOException e) {
            throw new UncheckedIOException("wordlist resource unreadable", e);
        }
    }

    /** Checks the list's invariants and returns an unmodifiable copy. */
    static List<String> validate(List<String> words) {
        if (words.size() != SIZE) {
            throw new IllegalStateException("wordlist has the wrong size");
        }
        Set<String> seen = new HashSet<>();
        String previous = "";
        for (String w : words) {
            if (!WORD_SHAPE.matcher(w).matches() || w.compareTo(previous) <= 0 || !seen.add(w)) {
                throw new IllegalStateException("wordlist entry is malformed, unsorted or repeated");
            }
            previous = w;
        }
        return List.copyOf(words);
    }
}
