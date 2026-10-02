package pm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** SR-501 / ERR01-J: filesystem details cannot escape through exception chains. */
final class StorageExceptionTest {
    @ParameterizedTest
    @EnumSource(StorageException.Code.class)
    void exposesOnlyTheErrorCode(StorageException.Code code) {
        IOException cause = new IOException("PRIVATE_PATH_SENTINEL");
        StorageException error = new StorageException(code, cause);
        error.addSuppressed(cause);
        StringWriter output = new StringWriter();
        error.printStackTrace(new PrintWriter(output));
        assertEquals(code, error.code());
        assertEquals(code.name(), error.getMessage());
        assertNull(error.getCause());
        assertEquals(0, error.getSuppressed().length);
        assertFalse(output.toString().contains("PRIVATE_PATH_SENTINEL"));
    }
}
