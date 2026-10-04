package pm.tui.lan;

import java.util.Objects;
import pm.crypto.DeviceIdentity;

/**
 * This install, as it shows itself on the LAN: its identity and the name its HELLO carries.
 *
 * @param identity the Ed25519 identity, owned by this value and closed by {@link #close()}
 * @param name the device name, 1 to 32 characters
 */
public record Local(DeviceIdentity identity, String name) implements AutoCloseable {
    /** Checks the fields. */
    public Local {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(name, "name");
    }

    /** This device's fingerprint, for the user to compare with a peer's screen. */
    public String fingerprint() {
        return DeviceIdentity.fingerprint(identity.publicKey());
    }

    /** Wipes the private key. */
    @Override
    public void close() {
        identity.close();
    }
}
