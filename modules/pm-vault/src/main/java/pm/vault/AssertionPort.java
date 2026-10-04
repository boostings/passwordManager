package pm.vault;

import pm.vault.record.PasskeyRecord;

/**
 * Builds the authenticator data that {@link Vault#signWithPasskey} signs (ADR 0016 addendum,
 * SR-087). The WebAuthn authenticator (M6.3) implements it: {@code rpIdHash || flags ||
 * signCount (big-endian u32) || extensions}, with the counter of the record it is given, which is
 * already on disk. The private key never reaches the port; the vault signs.
 */
@FunctionalInterface
public interface AssertionPort {
    /**
     * Returns the authenticator data for one assertion. Runs under the vault lock, after the
     * advanced counter has been saved and the key loaded; it must not call back into the vault
     * from another thread, and a nested {@code signWithPasskey} on this thread is refused
     * ({@code REENTRANT}). A thrown exception or null becomes {@code SIGN_FAILED}.
     *
     * <p>The vault signs only authenticator data bound to this record: {@code rpIdHash} equal to
     * SHA-256 of the record's RP ID (computed by the vault), the UP flag set, the AT flag clear,
     * trailing extension bytes exactly when ED is set, and the counter equal to
     * {@code persisted.signCount()}. Anything else is {@code SIGN_FAILED}, nothing is signed, and
     * the counter value stays burnt.
     *
     * @param persisted a keyless view of the record as just saved, carrying the counter to embed;
     *     closing it changes nothing in the vault
     * @return authenticator data, 37 bytes to 16 KiB; the vault does not retain it
     */
    byte[] authenticatorData(PasskeyRecord persisted);
}
