package pm.vault.cbor;

import java.util.List;
import java.util.Map;

public sealed interface CborValue permits CborValue.UInt, CborValue.Bytes, CborValue.Text,
        CborValue.Array, CborValue.MapV, CborValue.Bool {
    record UInt(long value) implements CborValue {}

    @SuppressWarnings("ArrayRecordComponent")
    record Bytes(byte[] value) implements CborValue {}

    record Text(String value) implements CborValue {}

    record Array(List<CborValue> items) implements CborValue {}

    record MapV(Map<String, CborValue> entries) implements CborValue {}

    record Bool(boolean value) implements CborValue {}
}
