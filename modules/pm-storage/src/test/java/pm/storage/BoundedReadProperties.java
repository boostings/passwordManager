package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/** Bounded fuzz properties for the storage input boundary (SR-021, FIO08/10-J). */
final class BoundedReadProperties {
    @Provide
    Arbitrary<byte[]> payloads() {
        return Arbitraries.bytes().array(byte[].class).ofMinSize(0).ofMaxSize(20_000);
    }

    @Property(tries = 100)
    void everyByteIsPreservedAtTheLimit(@ForAll("payloads") byte[] data)
            throws IOException, StorageException {
        ByteArrayInputStream input = new ByteArrayInputStream(data);
        assertArrayEquals(data, VaultFileStore.readBounded(input, data.length));
    }

    @Property(tries = 100)
    void exceedingALimitNeverReturnsPartialData(@ForAll("payloads") byte[] data) {
        net.jqwik.api.Assume.that(data.length > 0);
        ByteArrayInputStream input = new ByteArrayInputStream(data);
        StorageException error = assertThrows(StorageException.class,
                () -> VaultFileStore.readBounded(input, data.length - 1L));
        assertEquals(StorageException.Code.TOO_LARGE, error.code());
    }
}
