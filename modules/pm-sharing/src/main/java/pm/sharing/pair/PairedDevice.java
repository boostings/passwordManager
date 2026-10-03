package pm.sharing.pair;

import java.util.Objects;
import pm.crypto.DeviceIdentity;
import pm.sharing.wire.Octets;

/**
 * The outcome of a successful ceremony: the peer key to pin, and the name its HELLO gave.
 *
 * @param publicKey the peer's raw Ed25519 key, proved in TLS and bound into the SAS
 * @param name the peer's chosen device name, display only
 */
public record PairedDevice(Octets publicKey, String name) {
    /** Validates the fields. */
    public PairedDevice {
        if (Objects.requireNonNull(publicKey, "publicKey").length() != DeviceIdentity.PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("BAD_KEY");
        }
        Objects.requireNonNull(name, "name");
    }

    /** The peer's fingerprint, for showing next to the name. */
    public String fingerprint() {
        return DeviceIdentity.fingerprint(publicKey.toByteArray());
    }
}
