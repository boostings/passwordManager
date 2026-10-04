package pm.vault;

import java.util.Objects;

/**
 * A signed WebAuthn assertion released by {@link Vault#signWithPasskey} only after its counter was
 * saved (ADR 0016 addendum, SR-087). Not a secret: everything here goes to the relying party.
 * Arrays are copied in and out (OBJ05-J, OBJ06-J).
 */
public final class PasskeyAssertion {
    private final long counter;
    private final byte[] signedData;
    private final byte[] derSignature;

    PasskeyAssertion(long signCount, byte[] authenticatorData, byte[] signature) {
        this.counter = signCount;
        this.signedData = Objects.requireNonNull(authenticatorData, "authenticatorData").clone();
        this.derSignature = Objects.requireNonNull(signature, "signature").clone();
    }

    /** Returns the counter this assertion carries, already persisted. */
    public long signCount() {
        return counter;
    }

    /** Returns a copy of the signed authenticator data. */
    public byte[] authenticatorData() {
        return signedData.clone();
    }

    /** Returns a copy of the ES256 DER signature over {@code authenticatorData || clientDataHash}. */
    public byte[] signature() {
        return derSignature.clone();
    }

    @Override
    public String toString() {
        return "PasskeyAssertion[signCount=" + counter + "]";
    }
}
