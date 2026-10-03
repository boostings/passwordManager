package pm.approval.ipc;

import java.util.SortedMap;
import pm.approval.Grant;
import pm.crypto.SecretBytes;

/**
 * Turns an approval into the secrets it covers. Implemented by the application, which holds the
 * unlocked vault; it must {@link Grant#consume() consume} the grant. The server owns and closes the
 * returned values once they are sent. Any exception denies the request.
 */
@FunctionalInterface
public interface Releaser {
    /** The variables, by name, that {@code grant} releases; empty for operations that release none. */
    SortedMap<String, SecretBytes> release(Grant grant);
}
