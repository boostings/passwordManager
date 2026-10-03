package pm.fuzz;

import java.io.IOException;
import java.io.InputStream;

/**
 * Reads files of a fuzz test's seed corpus. Jazzer looks for the corpus of test class {@code X} in
 * the resource directory {@code XInputs} next to the class.
 */
final class Seeds {
    private Seeds() {
    }

    /** Returns the bytes of seed {@code name} of {@code fuzzTest}. */
    static byte[] read(Class<?> fuzzTest, String name) throws IOException {
        String resource = fuzzTest.getSimpleName() + "Inputs/" + name;
        try (InputStream in = fuzzTest.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("missing seed " + resource);
            }
            return in.readAllBytes();
        }
    }
}
