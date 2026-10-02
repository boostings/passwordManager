/**
 * pm-crypto: sole owner of the JCA, secret buffers, and the redacting logger (plan.md §10, SR-017).
 * Tier 1, leaf module. Only the API packages are exported (OBJ01-J, SEC05-J).
 */
module pm.crypto {
    requires java.management;
    requires org.bouncycastle.provider;

    exports pm.crypto;
    exports pm.crypto.log;
}
