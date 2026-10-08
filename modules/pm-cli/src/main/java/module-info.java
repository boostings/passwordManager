/** pm-cli. Tier and boundaries per plan.md §10. */
module pm.cli {
    requires pm.tui;
    requires pm.approval;
    requires pm.sharing;
    requires pm.browser;
    // The general pasteboard for the TUI's Copy (M7.8, SR-503).
    requires pm.platform.macos;
}
