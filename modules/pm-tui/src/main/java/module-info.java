/** pm-tui. Tier and boundaries per plan.md §10. */
module pm.tui {
    requires transitive pm.vault;
    requires transitive pm.approval;
    // transitive: pm.tui.lan exposes the LAN protocol's types (PairedDevice, Message.ShareOffer).
    requires transitive pm.sharing;
    // transitive: TuiApp.run(Terminal) exposes a Lanterna type (javac -Xlint:exports under -Werror).
    requires transitive com.googlecode.lanterna;

    exports pm.tui;
    exports pm.tui.lan;
}
