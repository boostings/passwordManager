# Supported Platform Matrix (v1)

Legend: **S** supported and exercised on that platform · **B** built for the platform and run by
the CI matrix when it is dispatched, not exercised by hand · **C** conditional (works with the
stated caveat) · **Not in v1** not built.

Only macOS (arm64) is exercised by hand for v1. Windows and Linux are covered by the manually
dispatched CI matrix (`ubuntu-22.04`, `macos-14`, `windows-2022`), which runs the full gate; the
native installers for those systems have never been built (docs/release/packaging.md).

**Windows is not verified.** In CI run 37737287483 (2026-10-08, commit c9a369e) the Ubuntu and macOS gates pass and the
Windows gate fails: about 150 tests in pm-vault, pm-storage, pm-cli, pm-tui and pm-fuzz assume
POSIX (they set file modes with POSIX calls, expect LF line endings or Unix paths), and the Tier 1
modules miss 100% branch coverage there because POSIX-only tests skip. The one product defect that
run exposed (the TUI browser relay could not create its lock file on Windows) is fixed but not yet
confirmed by a Windows run. Read every **B** in the Windows column as "builds; not verified" (R-014).

| Capability | macOS 13+ (arm64/x64) | Windows 10/11 (x64/arm64) | Linux glibc (x64/arm64) |
| --- | --- | --- | --- |
| Release archive with its own runtime (`.tar.gz`, `.zip`) | S | B — `bin/pm.bat` | B |
| Native installer (`jpackage`) | C — `.dmg` and `.pkg` built and smoke-tested; **not signed or notarized** (R-008) | Not in v1 — `.msi` needs WiX 3 on a Windows host; never built | Not in v1 — `.deb`/`.rpm` need a Linux host; never built |
| TUI (Lanterna) | S — Terminal.app, iTerm | B — desktop terminal window (Swing); graphical desktop required | B |
| Owner-only vault permissions | S — POSIX 0600/0700 | B — NTFS ACL via `AclFileAttributeView` | B — POSIX |
| Atomic rename write | S | C — `ATOMIC_MOVE` on NTFS; network drives untested | B |
| Local IPC (approval broker, browser relay) | S — Unix socket | C — AF_UNIX socket (Windows 10 1803+); the peer's user is not reported, so the folder ACL is the only check | B — Unix socket |
| LAN pairing and sharing (TLS 1.3, Ed25519 certificates, 6-digit SAS) | S — address and port typed by hand; no discovery | B | B |
| Native messaging host registration (`pm browser install`) | S — manifest written | C — prints the registry steps to do by hand | B — manifest written |
| Chrome, Chromium, Edge, Brave extension (unpacked) | S — Node tests with fakes; no real-browser test (security-review-record.md) | B | B |
| Firefox or Safari extension | Not in v1 | Not in v1 | Not in v1 |
| Vault-backed browser passkeys | Not in v1 (ADR 0016, v1 addendum) | Not in v1 | Not in v1 |
| Passkey storage, import and export | Not in v1 (ADR 0016, v1 addendum) | Not in v1 | Not in v1 |
| Browser, OS and hardware-key passkeys keep working with pm installed | S (the extension does not touch WebAuthn) | S | S |
| ssh-agent integration | S — `SSH_AUTH_SOCK` Unix socket, including the launchd agent | Not in v1 — Windows agents use named pipes (ADR 0013) | B — `SSH_AUTH_SOCK` Unix socket |
| SSH key export to a file (`pm ssh export`) | S — a new 0600 file | Not in v1 — refused because the file cannot be made 0600; nothing is written | B |
| Clipboard copy and clear (TUI, SR-503) | S — `pbcopy`/`pbpaste`; cleared after 30 s (`PM_CLIPBOARD_CLEAR`), on lock and on quit | Not in v1 — Copy says the clipboard is unavailable; Reveal works | Not in v1 — same; X11/Wayland differences, and Wayland may block a programmatic clear |
| Auto-lock after inactivity (5 min) | S | B | B |
| Auto-lock on system sleep or screen lock | Not in v1 — idle timer only | Not in v1 | Not in v1 |
| OS keychain unlock | Not in v1 | Not in v1 | Not in v1 |
| FIDO2 `hmac-secret` unlock | Not in v1 | Not in v1 | Not in v1 |
| Reproducible JARs, jlink image and archives | S — two clean builds compared (`repro-check.sh`) | B | B |
| Reproducible installer | Not by design — contents compared with the image instead (`releaseSmoke`) | n/a | n/a |

## Terminal minimums
80×24, 256-color preferred, 16-color fallback, no mouse required. Screen
reader support is best-effort (Lanterna limitation).

## CI runners
GitHub-hosted `macos-14`, `windows-2022`, `ubuntu-22.04`, dispatched by hand
(`gh workflow run ci.yml`). No hardware-key or keychain lanes exist, because v1
has neither feature.
