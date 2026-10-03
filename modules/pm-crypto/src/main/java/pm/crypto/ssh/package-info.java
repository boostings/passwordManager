/**
 * SSH keys and the ssh-agent client (ADR 0013, SR-060 to SR-064). Parses unencrypted
 * {@code openssh-key-v1} Ed25519 and ECDSA P-256 keys from vault {@code SecretBytes}, adds, lists
 * and removes agent identities over {@code $SSH_AUTH_SOCK}, and, as the explicit fallback, writes a
 * key file. Private key bytes never leave this package except through {@link SshKeyExport}; only
 * {@code pm.cli} may use it (ArchUnit {@code onlyTheCliReachesSshKeys}, TM-61).
 */
package pm.crypto.ssh;
