// pm-tui — see plan.md §10 module tiers
dependencies {
    api(project(":modules:pm-vault"))
    // M1 TUI toolkit (plan.md §13 M1); pinned stable 3.1.3, sha256-verified (signing key 94483BA5F4740C42 is on no public keyserver).
    // api: TuiApp.run(Terminal) exposes a Lanterna type, so the module is required transitively.
    api("com.googlecode.lanterna:lanterna:3.1.3")
}
