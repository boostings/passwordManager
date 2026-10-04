/**
 * Passkey credential keys (ADR 0016, SR-080 to SR-084): P-256 key generation from
 * {@code Csprng}, the strict storage form the vault encrypts at rest, WebAuthn ES256 assertion
 * signatures (ASN.1 DER, RFC 6979 nonces), and the CTAP2 canonical COSE_Key of the public key.
 * The private scalar leaves only as the storage form, through
 * {@code pm.crypto.passkey.storage.PasskeyStorage} (exported to {@code pm.vault} alone); signing
 * is performed here (plan.md §13 M6). This package is exported only to {@code pm.vault},
 * {@code pm.domain} and {@code pm.browser}.
 */
package pm.crypto.passkey;
