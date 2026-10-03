package pm.crypto.ssh;

/** The SSH key algorithms this package parses, adds and exports (ADR 0013). */
public enum SshKeyType {
    /** {@code ssh-ed25519} (RFC 8709). */
    ED25519("ssh-ed25519"),
    /** {@code ecdsa-sha2-nistp256} (RFC 5656). */
    ECDSA_P256("ecdsa-sha2-nistp256");

    private final String wire;

    SshKeyType(String wireName) {
        this.wire = wireName;
    }

    /** The algorithm name on the wire and in public key lines. */
    public String wireName() {
        return wire;
    }

    /**
     * The type named {@code name}.
     *
     * @throws SshException {@code UNSUPPORTED_KEY} for any other name
     */
    static SshKeyType fromWireName(String name) throws SshException {
        for (SshKeyType t : values()) {
            if (t.wire.equals(name)) {
                return t;
            }
        }
        throw new SshException(SshException.Code.UNSUPPORTED_KEY);
    }
}
