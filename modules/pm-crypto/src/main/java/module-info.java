/**
 * pm-crypto: sole owner of the JCA, secret buffers, and the redacting logger (plan.md §10, SR-017).
 * Tier 1, leaf module. Only the API packages are exported (OBJ01-J, SEC05-J).
 */
// CE-021: the qualified export names pm.cli, which javac cannot see while compiling pm.crypto alone.
@SuppressWarnings("module")
module pm.crypto {
    requires jdk.net;
    requires org.bouncycastle.provider;

    exports pm.crypto;
    exports pm.crypto.log;
    // SR-060 / ADR 0013: SSH key handling is visible to the CLI only, enforced by the compiler.
    exports pm.crypto.ssh to pm.cli;
}
