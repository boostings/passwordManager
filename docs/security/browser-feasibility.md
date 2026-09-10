# Browser Integration Feasibility

Status: **desk research, 2026-09-10**. Items marked *verify* need a hands-on
spike before the M5/M6 go/no-go. Findings here feed `risk-register.md` R-004
and the M6 decision in `plan.md` §16.

## 1. Native messaging (M5 foundation)

| Browser | Mechanism | Host registration | Message limits | Status |
| --- | --- | --- | --- | --- |
| Chrome / Chromium / Edge / Brave | `chrome.runtime.connectNative` → stdio JSON, 4-byte native-endian length prefix | JSON manifest in per-OS path (macOS `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`, Linux `~/.config/google-chrome/NativeMessagingHosts/`, Windows registry `HKCU\Software\Google\Chrome\NativeMessagingHosts`); manifest lists `allowed_origins` = extension IDs | 1 MiB to host, 64 MiB from host (Chrome docs) | Supported |
| Firefox | `browser.runtime.connectNative`, same wire format | Manifest with `allowed_extensions` (extension IDs) in `~/Library/Application Support/Mozilla/NativeMessagingHosts/` etc. | 1 MiB / 64 MiB (verify current) | Supported |
| Safari | No native messaging; Safari Web Extensions communicate with a containing macOS app via `SFSafariApplication`/XPC, requiring an App Store or notarized app bundle | Xcode project, Swift/ObjC shim | n/a | **Conditional** — needs a native macOS companion; out of scope for v1 |

Security notes: host manifest `allowed_origins` is the only origin control
(SR-301); the host must additionally validate the parent process is the
browser where the OS allows (Windows: parent PID check is weak; rely on
manifest + TUI approval). Host binary path in the manifest must be an absolute
path inside the install directory with no user-writable ancestors (FIO00-J).

## 2. Autofill

- Content script identifies login forms; the extension popup shows matching
  records for `location.origin` only; fill happens on explicit click (SR-304).
- Origin matching: exact `scheme://host[:port]`; a record may opt into
  registrable-domain matching (public suffix list bundled) (SR-300).
- Cross-origin iframes: fill only when the top-level origin **and** the frame
  origin both match; otherwise refuse and explain (TM-50).
- Manifest V3 required for Chrome; Firefox supports MV3 (verify service-worker
  lifecycle vs. native port persistence — MV3 service workers are killed after
  30 s idle, so the native port must be reopened per request; design the host
  to be stateless per message with the session token).

## 3. Passkeys (M6 inputs)

| Approach | Chrome/Edge | Firefox | Safari | Assessment |
| --- | --- | --- | --- | --- |
| Extension acting as WebAuthn authenticator via a sanctioned API | None exists (*verify* each release; Chrome has discussed but not shipped an extension authenticator API) | None | None | Not viable today |
| Content script overriding `navigator.credentials.create/get` | Works technically; detectable by RPs; breaks with page CSP `script-src` restrictions and cross-origin iframes; MV3 world isolation needs `world: "MAIN"` injection | Same, with `exportFunction` | Same, more restricted | **Fragile**; only for an explicit opt-in "compatibility mode" with a warning, if at all |
| DevTools protocol virtual authenticator | Requires `--remote-debugging` or `chrome.debugger` permission (scary permission prompt; user-hostile) | n/a | n/a | Not acceptable for a security product (ENV05-J spirit) |
| OS credential-provider APIs | Windows: no third-party passkey provider API for Win32 apps (only via Windows Hello); macOS 14+: **ASCredentialProviderExtension** supports passkeys for third-party managers, requires a signed macOS app extension (Swift) — Safari and Chrome on macOS route WebAuthn through it; Linux: none | *verify* current status per OS | **Conditional**: macOS is achievable with a native companion app; Windows and Linux are not for a Java app |
| Hardware-backed passkeys (FIDO2 key holds credential; we store metadata + backup of the public part only) | Works everywhere via platform WebAuthn | Works | Works | **Viable** fallback: vault stores passkey *records* (metadata) and supports import/export of the documented format; signing stays on the security key |

Recommendation for the Q3 go/no-go: plan for **no-go on vault-backed browser
passkeys for v1** on Windows and Linux; **conditional go on macOS** only if the
team is willing to ship a native Swift credential-provider extension as a
separate Tier 1 component. Ship passkey storage/backup and hardware-backed
passkeys on all platforms.

## 4. Spike checklist (before M5)

- [ ] Chrome MV3 native port lifecycle with 30 s service-worker idle.
- [ ] Firefox MV3 parity and manifest paths on all three OSes.
- [ ] Windows registry manifest path with per-user install.
- [ ] Message size limit confirmation for current stable versions.
- [ ] macOS `ASCredentialProviderExtension` passkey demo from a stub app
  (decides the macOS passkey path).
- [ ] Fuzz harness for the host's JSON parser (T-FUZZ-NM) running on stub host.
