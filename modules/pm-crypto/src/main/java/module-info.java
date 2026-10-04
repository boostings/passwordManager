/**
 * pm-crypto: sole owner of the JCA, secret buffers, and the redacting logger (plan.md §10, SR-017).
 * Tier 1, leaf module. Only the API packages are exported (OBJ01-J, SEC05-J).
 */
// CE-021: the qualified exports name modules (pm.cli, pm.vault, pm.domain, pm.browser) that javac
// cannot see while compiling pm.crypto alone.
@SuppressWarnings("module")
module pm.crypto {
    requires jdk.net;
    requires org.bouncycastle.provider;

    exports pm.crypto;
    exports pm.crypto.log;
    // SR-060 / ADR 0013: SSH key handling is visible to the CLI only, enforced by the compiler.
    exports pm.crypto.ssh to pm.cli;
    // SR-080 / SR-402 / ADR 0016: passkey keys (generate, sign, public key) reach only the vault,
    // the domain and the browser bridge (WebAuthn authenticator, M6.3/M6.4); the storage form,
    // the only way the private scalar leaves pm-crypto, reaches the vault alone (M6.2).
    // pm.crypto.passkey.internal is not exported.
    exports pm.crypto.passkey to pm.vault, pm.domain, pm.browser;
    exports pm.crypto.passkey.storage to pm.vault;
}
