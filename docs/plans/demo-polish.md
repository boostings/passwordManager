# Demo polish

Requested 2026-10-12, the day before the demo: "^S to share doesn't work, even when paired with another
device. improve the UI, and drive the app yourself and look for issues with it. ... we can only add
passwords, no passkeys or anything else."

Evidence drives every phase: the installed build is run in a real pty (macOS default termios, so IXON is
on, as in Terminal.app) through a pyte screen, and each screen is captured as text and PNG. The gate is
`./gradlew check certReport` with the Homebrew JDK 21. Commits are `M7.15 A:` as Jimmy, no AI attribution.

Root cause of ^S, found by driving: Lanterna 3.1.3 puts the tty in raw mode with
`stty -echo -icanon min 1 intr undef` and never `-ixon`, so the terminal driver takes Ctrl+S as XOFF
(output freezes until Ctrl+Q) and the app never sees the key. The tests use a virtual terminal, which
has no tty driver, so they could not catch it.

- [x] **D1** ^S reaches the app: a `UnixTerminal` that also turns flow control off (Lanterna restores the
  saved tty state on exit); a Share button on the item card as a second way in. Accept: in the pty, ^S on
  a selected row opens the Share window; pm-tui and pm-cli tests green.
  - Result: RawTerminal (pm-cli) adds `-ixon`; in the pty IXON is off while pm runs and back on after quit,
    and ^S opens Share. Card: Copy first and focused, Share button, c/r/e/s/d letters and ^S. pm rm now
    checks remove's result (SpotBugs RV_RETURN_VALUE_IGNORED_NO_SIDE_EFFECT appeared with the new class).
- [x] **D2** Share between two paired devices end to end (two vaults, two ptys): pair, send a login,
  receive it, see it on the other dashboard. Fix whatever breaks. Accept: the item arrives.
  - Result: pair, Send to device, Approve, Receive, Yes: GitHub arrives on the empty vault (0 to 1 item).
    This Mac's Wi-Fi address is 100.70.68.69 (RFC 6598, as campus networks hand out), and the default
    listen address took only RFC 1918, so pm fell back to loopback and another machine could never
    connect; it now takes 100.64.0.0/10 after RFC 1918. Wording and layout issues go to D4.
- [x] **D3** Adding more than logins: Ctrl+N opens a "New item" chooser with Login, Wi-Fi network,
  SSH key (import a key file through the CLI's ssh port, SR-060) and Passkey (explains that sites create
  passkeys through the browser extension). Accept: each type added in the pty; tests green.
  - Result: Ctrl+N menu: Login, Wi-Fi, SSH key (import through `SshActions.importKey`, implemented by
    `CliSshActions` over `pm ssh import`'s reader), Passkey and Project secrets (both explain: v1 has
    no passkeys, ADR 0016 addendum; projects come from `pm env import`). In the pty: login (with
    Generate), Wi-Fi, SSH key added; missing, passphrase-protected and duplicate keys refused with
    their own message. Found by driving and fixed: Ctrl+letter typed its letter into form boxes;
    Enter in a form's last field did nothing (a Lanterna Button takes Enter only when focused);
    the prefilled key path put the caret at its start; times showed in UTC. Login form: Generate,
    Show/Hide, short left-aligned labels. Tests: NewItemTest (6), CLI import test.
- [ ] **D4** UI polish from the walkthrough: item card (Copy first, Share), add/edit login (generate and
  show password), Devices and Share windows (layout, plain wording), dashboard footer and header.
  Accept: every screen re-captured and reviewed.
- [ ] **D5** Full gate, README key table and user guide, final walkthrough of the demo path. Accept:
  gate green with output reported.
