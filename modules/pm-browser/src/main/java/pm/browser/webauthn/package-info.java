/**
 * The WebAuthn authenticator behind the browser bridge (M6.3, ADR 0016 M6.3 addendum, SR-115 to
 * SR-119): RP ID validation against the origin and a pinned Public Suffix List, client data
 * checks, authenticator data and the {@code none} attestation object, and the vault-backed
 * {@link pm.browser.bridge.PasskeyPort}. Keys are generated and used only inside the vault.
 */
package pm.browser.webauthn;
