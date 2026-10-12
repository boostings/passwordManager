/** pm-cli. Tier and boundaries per plan.md §10. */
module pm.cli {
    // Windows uses Lanterna's Swing terminal; resolve its static desktop dependency at runtime.
    requires java.desktop;
    requires pm.tui;
    requires pm.approval;
    requires pm.sharing;
    requires pm.browser;
    // The general pasteboard for the TUI's Copy (M7.8, SR-503).
    requires pm.platform.macos;
}
