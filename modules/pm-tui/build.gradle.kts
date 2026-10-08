// pm-tui — see plan.md §10 module tiers
dependencies {
    api(project(":modules:pm-vault"))
    // M2: Env accessor (pm-domain) now; the approval dialog (pm-approval) in M2.6.
    api(project(":modules:pm-approval"))
    // M3.6: devices, pairing and sharing screens (pm.tui.lan) drive the LAN protocol.
    api(project(":modules:pm-sharing"))
    // M5.4: the browser relay runs the bridge (pm.browser) next to the TUI's broker and session.
    api(project(":modules:pm-browser"))
    // M1 TUI toolkit (plan.md §13 M1); pinned stable 3.1.3, sha256-verified (signing key 94483BA5F4740C42 is on no public keyserver).
    // api: TuiApp.run(Terminal) exposes a Lanterna type, so the module is required transitively.
    api("com.googlecode.lanterna:lanterna:3.1.3")
}
