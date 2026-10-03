package pm.domain.env;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import pm.domain.env.DotEnvException.Code;

class DotEnvTest {

    static Map<String, String> parse(String text) throws DotEnvException {
        List<EnvEntry> entries = DotEnv.parse(text.getBytes(StandardCharsets.UTF_8));
        Map<String, String> out = new LinkedHashMap<>();
        entries.forEach(e -> {
            out.put(e.name(), e.value().apply(b -> new String(b, StandardCharsets.UTF_8)));
            e.close();
        });
        return out;
    }

    static Code reject(String text) {
        return assertThrows(DotEnvException.class,
                () -> DotEnv.parse(text.getBytes(StandardCharsets.UTF_8))).code();
    }

    @Test
    void readsTheCommonForms() throws DotEnvException {
        Map<String, String> vars = parse("""
                # database
                DB_HOST=localhost
                export DB_PORT = 5432
                  DB_USER=app   # trailing comment
                DB_PASS='p#ss "x" \\n'
                MULTI="line1
                line2\\tend"
                EMPTY=
                URL=http://x/#anchor
                ESC="a\\"b\\\\c\\$d"
                UNICODE=héllo✓
                """);
        assertEquals(Map.of("DB_HOST", "localhost", "DB_PORT", "5432", "DB_USER", "app",
                "DB_PASS", "p#ss \"x\" \\n", "MULTI", "line1\nline2\tend", "EMPTY", "",
                "URL", "http://x/#anchor", "ESC", "a\"b\\c$d", "UNICODE", "héllo✓"), vars);
        assertEquals(List.of("DB_HOST", "DB_PORT", "DB_USER", "DB_PASS", "MULTI", "EMPTY", "URL", "ESC", "UNICODE"),
                List.copyOf(vars.keySet()), "file order kept");
    }

    @Test
    void handlesCrlfBomAndNoTrailingNewline() throws DotEnvException {
        assertEquals(Map.of("A", "1", "B", "x\ny"), parse("﻿A=1\r\nB=\"x\r\ny\""));
        assertEquals(Map.of(), parse(""));
        assertEquals(Map.of(), parse("\n\n   \n# only comments\n"));
        assertEquals(Map.of("exported", "1"), parse("exported=1"), "export prefix needs a blank after it");
        assertEquals(Map.of("export", "1"), parse("export=1"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "1A=x|BAD_NAME",
        "A-B=x|BAD_NAME",
        "=x|BAD_NAME",
        "JUSTANAME|MISSING_EQUALS",
        "A='open|UNTERMINATED_QUOTE",
        "A=\"open|UNTERMINATED_QUOTE",
        "A=\"bad\\q\"|BAD_ESCAPE",
        "A='x' y|TRAILING_TEXT",
        "A=\"x\"y|TRAILING_TEXT",
    })
    void rejectsMalformedLines(String text, Code code) {
        assertEquals(code, reject(text));
    }

    @Test
    void rejectsControlCharactersEncodingAndDuplicates() {
        assertEquals(Code.CONTROL_CHARACTER, reject("A=x\u0000y"));
        assertEquals(Code.CONTROL_CHARACTER, reject("A=x\ry"), "a lone CR is not a line end");
        assertEquals(Code.CONTROL_CHARACTER, reject("A=x\u007f"));
        assertEquals(Code.DUPLICATE_NAME, reject("A=1\nA=2"));
        assertEquals(Code.BAD_ENCODING, assertThrows(DotEnvException.class,
                () -> DotEnv.parse(new byte[] {'A', '=', (byte) 0xC0, (byte) 0x80})).code(), "overlong");
        assertEquals(Code.BAD_ENCODING, assertThrows(DotEnvException.class,
                () -> DotEnv.parse(new byte[] {'A', '=', (byte) 0xED, (byte) 0xA0, (byte) 0x80})).code(), "surrogate");
        assertEquals(Code.BAD_ENCODING, assertThrows(DotEnvException.class,
                () -> DotEnv.parse(new byte[] {'A', '=', (byte) 0xE2, (byte) 0x9C})).code(), "truncated");
    }

    @Test
    void enforcesSizeLimits() {
        assertEquals(Code.TOO_LARGE, assertThrows(DotEnvException.class,
                () -> DotEnv.parse(new byte[DotEnv.MAX_INPUT_BYTES + 1])).code());
        byte[] big = new byte[DotEnv.MAX_VALUE_BYTES + 3];
        Arrays.fill(big, (byte) 'x');
        big[0] = 'A';
        big[1] = '=';
        assertEquals(Code.VALUE_TOO_LARGE, assertThrows(DotEnvException.class, () -> DotEnv.parse(big)).code());
        StringBuilder many = new StringBuilder();
        for (int i = 0; i <= DotEnv.MAX_ENTRIES; i++) {
            many.append('V').append(i).append("=1\n");
        }
        assertEquals(Code.TOO_MANY_ENTRIES, reject(many.toString()));
        assertEquals(Code.BAD_NAME, reject("A".repeat(DotEnv.MAX_NAME_CHARS + 1) + "=1"));
    }

    @Test
    void errorsCarryTheLineButNoContent() {
        DotEnvException e = assertThrows(DotEnvException.class,
                () -> DotEnv.parse("OK=1\n\nSECRETVALUE='hunter2".getBytes(StandardCharsets.UTF_8)));
        assertEquals(3, e.line());
        assertFalse(e.getMessage().contains("hunter2"));
        assertFalse(e.getMessage().contains("SECRETVALUE"));
    }

    @Test
    void nameRules() {
        assertTrue(DotEnv.isValidName("_A1"));
        assertFalse(DotEnv.isValidName(""));
        assertFalse(DotEnv.isValidName("9A"));
        assertFalse(DotEnv.isValidName("A.B"));
        assertThrows(IllegalArgumentException.class,
                () -> new EnvEntry("bad name", pm.crypto.SecretBytes.copyOf(new byte[0])));
    }
}
