/** pm-tui. Tier and boundaries per plan.md §10. */
module pm.tui {
    requires transitive pm.vault;
    // transitive: TuiApp.run(Terminal) exposes a Lanterna type (javac -Xlint:exports under -Werror).
    requires transitive com.googlecode.lanterna;

    exports pm.tui;
}
