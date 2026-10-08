/** pm-tui. Tier and boundaries per plan.md §10. */
module pm.tui {
    requires transitive pm.vault;
    requires transitive pm.approval;
    // transitive: pm.tui.lan exposes the LAN protocol's types (PairedDevice, Message.ShareOffer).
    requires transitive pm.sharing;
    // transitive: ApprovalHost.browser and BrowserRelay expose the bridge's types (M5.4, ADR 0014 §8).
    requires transitive pm.browser;
    // SO_PEERCRED on the browser relay socket (BrowserRelay).
    requires jdk.net;
    // transitive: TuiApp.run(Terminal) exposes a Lanterna type (javac -Xlint:exports under -Werror).
    requires transitive com.googlecode.lanterna;

    exports pm.tui;
    exports pm.tui.lan;
}
