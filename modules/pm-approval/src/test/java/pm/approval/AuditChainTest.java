package pm.approval;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Hash;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/** Every way a log line or its head can fail the chain check (approval-model §7). */
class AuditChainTest {
    private static final Instant T0 = Instant.parse("2026-10-03T12:00:00Z");
    private static final byte[] ZERO = new byte[Hash.SHA256_BYTES];

    @TempDir
    Path dir;

    private Path log() {
        return dir.resolve(AuditLog.FILE_NAME);
    }

    private static byte[] entry(CborValue seq, CborValue prev, CborValue kind) {
        Map<String, CborValue> m = new LinkedHashMap<>();
        m.put("seq", seq);
        m.put("prev", prev);
        m.put("kind", kind);
        return CborWriter.encode(new CborValue.MapV(m));
    }

    private static String line(byte[] entry) {
        return Base64.getEncoder().encodeToString(entry);
    }

    private void writeLog(String... lines) throws IOException {
        Files.writeString(log(), String.join("\n", lines) + "\n", StandardCharsets.US_ASCII);
        Files.setPosixFilePermissions(log(), PosixFilePermissions.fromString("rw-------"));
    }

    private void writeHead(String text) throws IOException {
        Files.writeString(AuditLog.headOf(log()), text, StandardCharsets.US_ASCII);
    }

    private AuditException failure() {
        return assertThrows(AuditException.class, () -> AuditLog.check(log()));
    }

    private void assertTampered(long entry, String why) {
        AuditException e = failure();
        assertEquals(AuditException.Code.TAMPERED, e.code(), why);
        assertEquals(entry, e.entry(), why);
    }

    @Test
    void everyBadFirstEntryIsTamperedAtZero() throws IOException {
        CborValue one = new CborValue.UInt(1);
        CborValue zero = new CborValue.Bytes(ZERO);
        CborValue unlock = new CborValue.Text("unlock");
        for (byte[] bad : List.of(
                entry(new CborValue.Text("1"), zero, unlock),
                entry(new CborValue.UInt(2), zero, unlock),
                entry(one, new CborValue.Text("prev"), unlock),
                entry(one, new CborValue.Bytes(new byte[] {1}), unlock),
                entry(one, zero, new CborValue.UInt(1)),
                entry(one, zero, new CborValue.Text("format-disk")),
                CborWriter.encode(new CborValue.Array(List.of())))) {
            writeLog(line(bad));
            assertTampered(0, line(bad));
        }
    }

    @Test
    void anOverlongLineIsACutLog() throws IOException {
        writeLog("A".repeat(8 * 1024 + 1));
        AuditException e = failure();
        assertEquals(AuditException.Code.TRUNCATED, e.code());
        assertEquals(0, e.entry());
    }

    @Test
    void theHeadMustNameTheLastEntryOrTheOneBeforeIt() throws IOException, AuditException {
        AuditLog.append(log(), new TestClock(T0), AuditEvent.of("unlock"));
        AuditLog.append(log(), new TestClock(T0), AuditEvent.of("lock"));
        AuditLog.append(log(), new TestClock(T0), AuditEvent.of("unlock"));
        String head = Files.readString(AuditLog.headOf(log()), StandardCharsets.US_ASCII).strip();
        String hash = head.substring(head.indexOf(' ') + 1);

        writeHead("1 " + hash);
        assertTampered(1, "two behind");
        writeHead("0 " + hash);
        assertTampered(0, "no entry zero");
        writeHead("3 " + HexFormat.of().formatHex(ZERO));
        assertTampered(3, "the right number with the wrong hash");

        Files.delete(AuditLog.headOf(log()));
        assertTampered(3, "head removed");
        Files.createSymbolicLink(AuditLog.headOf(log()), dir.resolve("elsewhere"));
        AuditException linked = failure();
        assertEquals(AuditException.Code.UNSAFE_FILE, linked.code());
    }

    @Test
    void aHeadNamingEntryZeroIsTamperedEvenForAOneEntryLog() throws IOException, AuditException {
        AuditLog.append(log(), new TestClock(T0), AuditEvent.of("unlock"));
        String head = Files.readString(AuditLog.headOf(log()), StandardCharsets.US_ASCII).strip();
        writeHead("0 " + head.substring(head.indexOf(' ') + 1));
        assertTampered(0, "one behind is allowed, but there is no entry zero");
    }

    @Test
    void anEmptyLogNeedsNoHead() throws IOException, AuditException {
        Files.createFile(log(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        assertEquals(0, AuditLog.check(log()));
    }
}
