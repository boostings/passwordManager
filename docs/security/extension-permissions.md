# Browser extension permissions

Status: M5.3, 2026-10-03. Normative for `extension/src/manifest.json` (SR-308). Any change to the
manifest's permissions, CSP or keys needs a row here and a security-owner review;
`extension/test/manifest.test.js` (T-EXT-06) fails on any addition.

## Requested permissions

| Permission | Why it is needed | What it would allow if the extension were compromised | Why nothing narrower works |
| --- | --- | --- | --- |
| `nativeMessaging` | The only channel to pm: `chrome.runtime.sendNativeMessage("pm.browser", …)`, one message per request (ADR 0014 §1). | Talk to any native host whose manifest lists this extension's ID. Only `pm.browser` does, and that host checks the caller ID again against its own allowlist (ADR 0014 §4) and releases nothing without approval in pm (SR-302). | None exists; this is the only browser-to-native channel in MV3. |
| `activeTab` | Read the URL of the tab the user is looking at, and inject the fill into it, **only after the user clicks the toolbar button**. The grant lasts until that tab navigates. | Read the URL and inject into the one tab the user just invoked the extension on. No background access to other tabs or sites. | `host_permissions` (even for one site) would give standing access to every page of those sites without a click; `<all_urls>` would give it to all sites. |
| `scripting` | `chrome.scripting.executeScript` to run `fillInPage` in the top frame (`frameIds: [0]`) of the active tab. Required in MV3 to inject anything at all; `activeTab` supplies the host access, `scripting` the API. | Inject a function into the active tab the user clicked on (same scope as `activeTab`). | MV3 has no injection API without it. Declared content scripts would run on every matching page automatically, which SR-304 forbids. |

## Deliberately absent

- **`host_permissions`, `optional_host_permissions`, `<all_urls>`**: none. The extension never
  reads a page it was not invoked on.
- **`content_scripts`**: none. Nothing runs on page load (SR-304); filling is a click in the popup.
- **`storage`, `cookies`, `tabs`, `webRequest`, `webNavigation`, `clipboardWrite`, `history`,
  `downloads`**: not needed. The URL of the active tab comes from `activeTab`; nothing is stored
  in the browser (no `chrome.storage`, no `localStorage`).
- **`web_accessible_resources`**: none, so pages cannot load or frame extension files or detect
  the extension by probing them.
- **`externally_connectable`**: absent, and the background registers no `onMessageExternal` or
  `onConnectExternal` listener. Messages are accepted only from the extension's own popup
  (`sender.id` is this extension, `sender.url` is `popup.html`, no `sender.tab`).
- **`key`, `update_url`**: absent in the source tree; the store or the installer adds them.

## Content Security Policy

```
default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none';
base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

- Only scripts and styles packaged with the extension run on extension pages; no
  `'unsafe-eval'`, `'unsafe-inline'`, `'wasm-unsafe-eval'`, CDN or `data:`/`blob:` sources.
  `connect-src` falls back to `'none'`: extension pages make no network requests.
- No remote code: no `fetch`, `XMLHttpRequest`, `WebSocket`, dynamic `import()`, `eval` or
  `new Function` in any packaged script, and every static import is a packaged `./x.js` module.
  `popup.html` has one `<script src="popup.js">`, no inline script, no `on*=` handlers and no
  inline styles. Host data is rendered with `textContent` only. All of this is asserted by
  `manifest.test.js`.

## Fill rules (SR-304, SR-309)

1. The user clicks the toolbar button; the popup asks the background for `lookup`.
2. The background takes the origin from the active tab's URL itself (never from the popup), and
   refuses non-`http(s)` tabs.
3. Fill, save and generate each send one native message; pm prompts (or applies a session policy
   the user created for that extension, origin and action).
4. The host's reply carries the canonical origin it approved. The background injects only if
   that equals the tab's origin, only into frame 0, and `fillInPage` checks again inside the page
   that `window.top === window` and `location.origin` equals the approved origin. A tab that
   navigated in between, or any iframe, gets nothing.
5. Only fields the user can see are filled: enabled, writable, `checkVisibility` with the
   opacity, visibility and content-visibility checks (field and ancestors), and a non-zero box.
   DOM methods are called through the prototypes, so a form control named `querySelectorAll`
   cannot redirect the fill. This is why `minimum_chrome_version` is 121.
6. Passwords never go to the popup: the background passes them straight to the injected function.
7. Generate is "generate, save and fill": pm stores the new login before it answers, so a
   generated password always exists in pm even if the fill fails.
8. If the background stops while pm waits for approval (MV3 service-worker lifetime), the popup
   says the request was interrupted; nothing is filled later (ADR 0014 §7).

Accepted limitation (TM-54): once filled, the value is in the page's DOM and the page's own
scripts can read it. That is inherent to form filling.

## Native host registration

`extension/native-host/pm.browser.json.template` is the host manifest. The installer
(`pm browser install`, M5.4) fills in `__HOST_PATH__` (absolute path of the host launcher inside
the install directory, with no user-writable ancestor) and `__EXTENSION_ID__` (the 32-letter ID
of the installed extension), and writes it to:

| Platform | Location |
| --- | --- |
| macOS | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/pm.browser.json` |
| Linux | `~/.config/google-chrome/NativeMessagingHosts/pm.browser.json` |
| Windows | file anywhere in the install directory, registered at `HKCU\Software\Google\Chrome\NativeMessagingHosts\pm.browser` |

The same ID goes into the host's own allowlist file (ADR 0014 §4), which the host checks before
reading stdin. `allowed_origins` must list exactly one origin; wildcards are not allowed by Chrome
and never written.

## Tests

`./gradlew :modules:pm-browser:extensionTest` (part of `check`) runs `node --test` in
`extension/` with small fakes for `chrome.*` and the page DOM; it needs Node 20+ on `PATH` and
fails with a clear message otherwise. There are no npm dependencies.
