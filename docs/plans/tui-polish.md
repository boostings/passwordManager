# TUI polish

Requested 2026-10-03: "improve the UI of the terminal please". The approved table is in the session: a dark theme;
a full-screen dashboard with header and footer hints; Ctrl+N/L/Q; restyled unlock, detail and add-login screens;
tests updated. Gate: `./gradlew --rerun-tasks check certReport gitleaksScan` plus rendered before/after
screenshots of every screen. Commits are Lane E (Jacob), with no AI attribution.
Widened 2026-10-03: "make it pretty, tasteful, animtaed, colorful, etc etc." That adds a truecolor
palette with a 256-color fallback, the shimmering logo, a draining countdown meter (green to amber to
red, pulsing under 30 s), a staggered row fade-in, an error flash and a fading "saved" toast. All of it
runs off the controller tick and the injectable clock.

- [x] **T1** PmTheme plus TuiApp/TuiHarness wiring; unlock card restyle. Accept: pm-tui tests green; the unlock screenshot is dark.
  - Result: PmTheme (palette, rounded cards, pill buttons, 256-color) wired in TuiApp.newGui plus harness; unlock card with shimmering Banner, busy/error Notice.
- [x] **T2** Dashboard: header, empty states, footer, Ctrl shortcuts in TuiController. Accept: DashboardTest updated plus new shortcut and empty-state tests green.
  - Result: full-screen dashboard: header count plus draining lock meter, row fade-in, empty states, footer hints plus toast; ^N/^L/^X, Esc clears search; tests updated plus TuiLookTest (16).
- [x] **T3** Detail and add-login restyle, Esc to close. Accept: tests green; screenshots of all six screens reviewed.
  - Result: detail and add-login cards restyled, Esc closes or cancels (wipes boxes); screenshots of every screen reviewed in Chrome.
- [x] **T4** Full gate, README key table, commit `M1.7 E:`.
  - Result: gate BUILD SUCCESSFUL, 0 findings, no leaks; README key table; commit M1.7 E.
