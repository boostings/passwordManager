# Supported Platform Matrix

Legend: **S** supported (target for v1) · **C** conditional (works with stated
caveat) · **U** unsupported in v1 · *spike* needs hands-on verification.

| Capability | macOS 13+ (arm64/x64) | Windows 10/11 (x64/arm64) | Linux glibc (x64/arm64) |
| --- | --- | --- | --- |
| Bundled-runtime installer (`jpackage`) | S — `.dmg`/`.pkg`, signed + notarized | S — `.msi`, Authenticode | S — `.deb`, `.rpm`, tarball; detached sig |
| TUI (Lanterna) in Terminal.app / iTerm / Windows Terminal / common Linux terminals | S | S (Windows Terminal; legacy conhost **C**: limited colors) | S |
| Owner-only vault permissions | S (POSIX 0600/0700) | S (NTFS DACL via `AclFileAttributeView`) | S (POSIX) |
| Atomic rename write | S | C — `Files.move(ATOMIC_MOVE)` works on NTFS; test on network drives is U | S |
| OS keychain slot | S — Keychain Services via `security`-free JNA-less approach: *spike* (options: `KeychainAccess` through JNI-free `Foundation` bridge is not available in pure Java; likely needs a small signed helper or JNA) | S — DPAPI via `CryptProtectData` (needs JNA or a tiny native helper) *spike* | C — Secret Service D-Bus (GNOME Keyring/KWallet) via pure-Java D-Bus library; absent on headless systems |
| FIDO2 `hmac-secret` slot | C — CTAP2 over USB HID needs a native HID library (`hidapi` via JNA) *spike*; macOS 14+ may require the Passkeys/ASAuthorization path for platform keys | C — Windows 10 1903+ routes FIDO2 through WebAuthn API (`webauthn.dll`), which supports `hmac-secret` for third-party apps *spike* | C — `hidapi` + udev rules |
| Local IPC (approval broker) | S — Unix socket | S — named pipe | S — Unix socket |
| mDNS discovery | S — JmDNS (pure Java) | S | S (avahi optional) |
| TLS 1.3 mutual with Ed25519 certs | S (JDK 21) | S | S |
| Native messaging host registration | S | S (HKCU registry) | S |
| Chrome/Edge/Brave extension | S | S | S |
| Firefox extension | S | S | S |
| Safari extension | U for v1 (needs native app) | n/a | n/a |
| Vault-backed browser passkeys | C — only via native credential-provider companion (Q3 decision) | U for v1 | U for v1 |
| Hardware-backed passkeys (metadata + backup) | S | S | S |
| ssh-agent integration | S — `SSH_AUTH_SOCK` Unix socket | C — OpenSSH for Windows named pipe `\\.\pipe\openssh-ssh-agent`; Pageant U | S |
| Clipboard clear | S | S | C — X11/Wayland differences; Wayland may block programmatic clear |
| Auto-lock on system sleep/lock | C — no pure-Java signal; poll uptime gap + idle timer *spike* | C — same | C — same |
| Reproducible JARs + jlink image | S | S | S |
| Reproducible installer | U by design (signatures) — contents verified instead | U | U |

## Terminal minimums
80×24, 256-color preferred, 16-color fallback, no mouse required. Screen
reader support is best-effort (Lanterna limitation) and documented.

## CI runners (Phase 8)
GitHub-hosted `macos-14`, `windows-2022`, `ubuntu-22.04`. Hardware-key and
keychain integration tests run on self-hosted or manual lanes and are tagged
`@Tag("hardware")` so hosted runners skip them without hiding the gap.
