package pm.domain.env;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

class DotEnvProperties {

    /** Arbitrary bytes either parse or fail with DotEnvException: never another exception or a hang. */
    @Property(tries = 2000)
    void arbitraryInputNeverEscapes(@ForAll byte[] input) {
        try {
            DotEnv.parse(input).forEach(EnvEntry::close);
        } catch (DotEnvException expected) {
            // rejected cleanly
        }
    }

    /** Anything written in double-quoted form with escapes reads back byte for byte. */
    @Property(tries = 500)
    void doubleQuotedRoundTrip(@ForAll("vars") Map<String, String> vars) throws DotEnvException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        vars.forEach((name, value) -> {
            String escaped = value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r");
            out.writeBytes((name + "=\"" + escaped + "\"\n").getBytes(StandardCharsets.UTF_8));
        });
        List<EnvEntry> entries = DotEnv.parse(out.toByteArray());
        assertEquals(vars.size(), entries.size());
        entries.forEach(e -> {
            byte[] expected = vars.get(e.name()).getBytes(StandardCharsets.UTF_8);
            e.value().withBytes(actual -> assertArrayEquals(expected, actual));
            e.close();
        });
    }

    @Provide
    Arbitrary<Map<String, String>> vars() {
        Arbitrary<String> names = Arbitraries.strings().withCharRange('A', 'Z').withChars('_').ofMinLength(1).ofMaxLength(12);
        Arbitrary<String> values = Arbitraries.strings()
                .withCharRange(' ', '~').withChars('\n', '\t', 'é', '✓').ofMaxLength(80);
        return Arbitraries.maps(names, values).ofMaxSize(20);
    }
}
