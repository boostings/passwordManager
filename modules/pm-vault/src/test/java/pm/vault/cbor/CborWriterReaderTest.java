package pm.vault.cbor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class CborWriterReaderTest {
    @Test
    void roundTripsSimpleValues() throws CborException {
        CborValue value = new CborValue.MapV(java.util.Map.of(
            "a", new CborValue.UInt(10L),
            "b", new CborValue.Array(java.util.List.of(new CborValue.Text("x"), new CborValue.Bool(true)))
        ));

        byte[] encoded = CborWriter.encode(value);
        CborValue decoded = CborReader.decode(encoded, CborLimits.HEADER);

        assertEquals(value, decoded);
    }

    @Test
    void rejectsIndefiniteLength() {
        byte[] input = new byte[] {0x5f};
        assertThrows(CborException.class, () -> CborReader.decode(input, CborLimits.HEADER));
    }
}
