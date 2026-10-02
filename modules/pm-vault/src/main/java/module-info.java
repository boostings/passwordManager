/** pm-vault. Tier and boundaries per plan.md §10. */
module pm.vault {
    requires transitive pm.crypto;
    requires transitive pm.storage;

    exports pm.vault;
    exports pm.vault.record;
}
