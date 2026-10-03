/**
 * pm-vault. Tier and boundaries per plan.md §10.
 *
 * <p>Exports the vault service and the record model only. The CBOR codec, envelope
 * format and slot key derivation stay internal so no caller can bypass the
 * authenticate-before-parse order (SR-020).
 */
@SuppressWarnings("module") // the qualified export names a module that depends on this one
module pm.vault {
    requires transitive pm.crypto;
    requires transitive pm.storage;

    exports pm.vault;
    exports pm.vault.record;
    // The codec is shared, never public: the audit log and the LAN wire format use the same
    // deterministic subset and limits.
    exports pm.vault.cbor to pm.approval;
}
