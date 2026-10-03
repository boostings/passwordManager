/**
 * pm-sharing: the LAN share protocol (docs/protocols/lan-share.md, ADR 0010). Tier 1.
 */
module pm.sharing {
    requires transitive pm.vault;

    exports pm.sharing.wire;
}
