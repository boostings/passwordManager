# Extension permission review (M5.5)

Status: review record, 2026-10-05, security owner (Lane A, @boostings). Reviews
`extension/src/manifest.json` against the normative `extension-permissions.md` and SR-308: first
as of M5.3 (`deebbb2`), then again after the one change this review asked for, an explicit
`"externally_connectable": {"ids": []}` (second review row). Any later change to the manifest's
permissions, CSP or keys needs a new review row at the bottom of this file. The node lock test
`extension/test/manifest.test.js` (T-EXT-06) fails on any added permission or key, so a change
cannot land silently. The second review added one lock-test case, which pins
`externally_connectable` to exactly `{"ids": []}`.

Reviewed files (SHA-256):

```
7d6e45f31365761ec6f3afaf2940ec4b3472278da8f4a6058028292cc1f02b02  extension/src/manifest.json
e2537dd7c8ecca93169d25830803000bf44416100ac593cbd2f280e2ca67855e  extension/native-host/pm.browser.json.template
```

Verdict: **accepted.** Three permissions, each needed and none replaceable by a narrower one; no
host access, content scripts or web-accessible resources; `externally_connectable` admits no
extension and no web page; a CSP stricter than the MV3 default. The one defence-in-depth suggestion
from the first review (declare `externally_connectable` as `{"ids": []}`) is applied.

## VERIFIED

Each line names the command run on 2026-10-05 in the M5.5 worktree and what it printed.

| Check | Command | Output |
| --- | --- | --- |
| The lock test passes on the reviewed manifest | `cd extension && node --test test/manifest.test.js` (Node v24.14.0) | `tests 8`, `pass 8`, `fail 0` |
| Exactly these top-level keys | `node -e` printing `Object.keys(manifest).sort()` | `action, background, content_security_policy, description, externally_connectable, manifest_version, minimum_chrome_version, name, permissions, version` |
| Exactly three permissions, in this order | same | `["nativeMessaging","activeTab","scripting"]` |
| No host access, content scripts or web-accessible resources | same, `key in manifest` for each | `host_permissions` false, `content_scripts` false, `web_accessible_resources` false |
| `externally_connectable` admits nothing | same, printing `JSON.stringify(manifest.externally_connectable)` and `"matches" in` it | `{"ids":[]}`, `false` |
| `minimum_chrome_version` | same | `"121"` |
| CSP | same | `extension_pages`: `default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`; no `sandbox` key |
| No external-message listeners anywhere in the extension | `grep -rn "onMessageExternal\|onConnectExternal\|onConnect\b\|connect(" extension/src` | no output |
| The host manifest template allows exactly one origin | `manifest.test.js` "the native host manifest template allows exactly one extension origin" | pass (in the 8 above); the template's `allowed_origins` is `["chrome-extension://__EXTENSION_ID__/"]` |

## Per-permission review

| Permission | Used by (source) | Why it is needed | Narrower alternative considered | Decision |
| --- | --- | --- | --- | --- |
| `nativeMessaging` | `bridge.js` `chrome.runtime.sendNativeMessage(HOST, request)`, one message per request | The only browser-to-native channel in MV3; pm is reached through `pm.browser` only | None exists | Keep. Abuse is bounded twice more: Chrome launches only hosts whose manifest names this extension, and the host re-checks the caller against its own allowlist before reading stdin (ADR 0014 §4, fuzzed by `NativeHostFuzzTest`) |
| `activeTab` | `bridge.js` `chrome.tabs.query({active: true, currentWindow: true})` reads `tab.url`; the grant also supplies the host access `executeScript` needs | The URL and injection rights for the one tab the user clicked the toolbar button on, until that tab navigates | `host_permissions` for even one site gives standing access without a click; `tabs` exposes every tab's URL | Keep |
| `scripting` | `bridge.js` `chrome.scripting.executeScript({target: {tabId, frameIds: [0]}, func: fill, args})` | MV3 has no injection API without it; the injected function is the packaged `fillInPage`, never a string | Declared `content_scripts` would run on page load, which SR-304 forbids | Keep |

## Not requested, and why

| Absent | Why it is not needed |
| --- | --- |
| `host_permissions`, `optional_host_permissions`, `<all_urls>` | `activeTab` gives exactly the clicked tab; nothing reads a page it was not invoked on (SR-304) |
| `optional_permissions` | No feature is gated behind a later prompt; a runtime prompt is another way to widen scope |
| `tabs` | The active tab's URL comes from the `activeTab` grant; other tabs' URLs are never needed |
| `storage`, `unlimitedStorage`, `cookies` | Nothing is kept in the browser (`manifest.test.js` bans `chrome.storage` and `localStorage`) |
| `clipboardWrite`, `clipboardRead` | Filling writes into the page field; no clipboard path exists, so no clipboard residue |
| `webRequest`, `webNavigation`, `declarativeNetRequest`, `history`, `downloads`, `alarms`, `notifications`, `identity`, `offscreen` | No feature uses them |
| `content_scripts` | Nothing runs on page load (SR-304); filling is one click in the popup |
| `web_accessible_resources` | Pages cannot load, frame or probe extension files, so they cannot detect the extension that way |
| `key`, `update_url`, `oauth2`, `sandbox`, `chrome_url_overrides` | Not in the source tree; the store or the installer adds `key`/`update_url` |

## Specific keys

- **CSP (`content_security_policy.extension_pages`).** Stricter than the MV3 default
  (`script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`): no `'wasm-unsafe-eval'`, no inline,
  no remote source, and `default-src 'none'` makes `connect-src`, `img-src`, `frame-src` and
  `font-src` `'none'`. `base-uri`, `form-action` and `frame-ancestors` are `'none'`. The popup's
  only script is `<script type="module" src="popup.js">` and its only style sheet is `popup.css`,
  both packaged (asserted by the lock test). No `sandbox` CSP because there are no sandbox pages.
- **`externally_connectable`: `{"ids": []}`.** With the key absent, Chrome lets no web page
  connect but lets **every other extension** send messages to this extension's ID. An empty `ids`
  list admits no extension, and with no `matches` key no web page is admitted either, so Chrome
  refuses both before any listener is consulted. Behind that, nothing would answer anyway: external
  messages arrive only through `runtime.onMessageExternal` / `onConnectExternal`, which the
  extension never registers (the lock test bans both names), and `runtime.onMessage` also checks
  that the sender is this extension's own popup (`sender.id`, `sender.url`, no `sender.tab`). The
  lock test "no other extension and no web page may connect" pins the value to exactly
  `{"ids": []}`, so adding an ID or a `matches` pattern fails it. This was the first review's one
  open suggestion. It was applied at M5.5 and is reviewed in the second row below.
- **`web_accessible_resources`: absent.** No file is reachable from a web page.
- **`minimum_chrome_version`: `"121"`.** The fill's visibility check calls
  `Element.prototype.checkVisibility` with `{opacityProperty, visibilityProperty,
  contentVisibilityAuto}` (`fill.js` line 28). Older versions accept the call but ignore unknown
  option names, so a transparent or `visibility: hidden` field would count as visible and be filled
  (SR-309). The floor stops installation on those versions. The promise forms of
  `sendNativeMessage` and `executeScript` with `func`/`args`, and module service workers, are all
  older than 121.
- **`background`: `{service_worker: "background.js", type: "module"}`.** Static imports only, of
  packaged `./x.js` modules (lock test); MV3 service workers cannot load remote code anyway.
- **Native host manifest template.** `type: "stdio"`, exactly one `allowed_origins` entry, no
  wildcard; `path` is absolute and filled by the installer (M5.4, pending merge).

## INFERRED

Statements about Chrome's behaviour, from Chrome's extension documentation as recalled by the
reviewer, not measured: **no real Chrome was run for this review.**

| Statement | Confidence |
| --- | --- |
| With `externally_connectable` set to `{"ids": []}`, Chrome refuses messages and connections from every other extension and every web page before any listener runs (with the key absent, web pages are refused and other extensions are not) | High |
| The `activeTab` grant exposes `tab.url` to `tabs.query` and allows `executeScript` on that tab, and ends when the tab navigates or closes | High |
| `checkVisibility` before 121 ignores `opacityProperty`/`visibilityProperty`/`contentVisibilityAuto` instead of throwing | Medium |
| The install-time warning shown for these three permissions is only the native-messaging one ("Communicate with cooperating native applications") | Medium |
| Chrome passes `chrome-extension://<id>/` as the host's first argument on every OS, and `--parent-window=<n>` as the second on Windows (the shape `ExtensionAllowlist.caller` accepts) | High |

These are to be confirmed by the real-browser manual test (user-only, listed in the M5 sign-off).

## Review rows

| Date | Manifest SHA-256 (first 16) | Change | Reviewer | Result |
| --- | --- | --- | --- | --- |
| 2026-10-05 | `f51428b4590793d5` | Initial review of the M5.3 manifest | Lane A, security owner | Accepted; `externally_connectable: {"ids": []}` suggested |
| 2026-10-05 | `7d6e45f31365761e` | `"externally_connectable": {"ids": []}` added, with a lock-test case | Lane A, security owner | Accepted; no open items |
