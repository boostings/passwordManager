# ADR 0014: Browser bridge — Chrome native messaging host, exact origins, broker-gated release

- Status: Accepted (M5.1 host, M5.2 bridge, M5.3 extension; M5.4 TUI relay, prompt and installer, §8)
- Date: 2026-10-03

## Context

M5 adds a Manifest V3 extension that looks up, fills, saves and generates passwords
(plan.md §13 M5, `docs/security/browser-feasibility.md`). The extension is the least trusted
component that ever receives a secret: it runs inside the browser, next to hostile pages
(threat model TM-50..TM-54, attack trees AT-5, AT-6). Requirements SR-300..SR-304 apply.

## Decision

### 1. Shape

```
page ── content fill ── extension (MV3) ──native messaging── pm-browser host ── bridge ── broker + vault
```

- `modules/pm-browser` (Tier 1) owns everything between the browser's stdio and the approval
  broker: framing, a strict JSON codec, the message schema, the extension-ID allowlist
  (`pm.browser.host`, this section), and from M5.2 the origin rules and the bridge.
- Chrome starts the host per `chrome.runtime.sendNativeMessage` call. The host is stateless per
  message, so a stopped MV3 service worker loses no host state (browser-feasibility §2). It can
  still lose the *answer*: if Chrome stops the worker while a `fill` waits for approval in pm,
  the pending call dies with it (§7 says how the extension reports this; §8 says what the TUI does).

### 2. Framing (`NativeFrames`)

- Each message is a 4-byte length in native byte order followed by that many bytes of UTF-8
  JSON. All shipped platforms (x86-64, AArch64) are little-endian, so the host fixes
  little-endian instead of asking the JVM.
- Browser → host: at most **1 MiB** (`MAX_INBOUND`). Chrome allows 64 MiB in this direction; no
  request needs more than a few KiB, so the host sets the lower cap (SR-303). Host → browser: at
  most **1 MiB** (`MAX_OUTBOUND`, Chrome's own limit). A reply that would be larger is replaced by
  an `error` reply with code `FRAME_SIZE`. (browser-feasibility §1 lists the two limits the other
  way round; Chrome's documentation gives 1 MB from the host and 64 MiB to it.)
- The length is checked before anything is allocated. A length of zero or above the cap is
  refused without reading the body (`FRAME_SIZE`). End of stream inside a header or body is
  `TRUNCATED`. End of stream at a frame boundary is a normal close. A framing error cannot be
  resynchronised: the host sends one `error` reply and exits with status 3.
- The body is decoded as strict UTF-8 (`CodingErrorAction.REPORT`). Malformed, overlong,
  truncated and surrogate-encoding sequences are refused with `BAD_UTF8`, never replaced. The
  frame bytes and the decoded characters are zeroed after parsing.
- Every request gets exactly one reply. A `RuntimeException` while answering one request (a bug
  or a faulty port) is caught per message and answered `INTERNAL` with no exception text; the
  session continues. A reply that cannot be encoded (an unpaired surrogate in a secret string)
  is also replaced by `INTERNAL`. Non-secret strings from the vault (titles, usernames) have
  unpaired surrogates replaced by U+FFFD when the reply is built, so one malformed title cannot
  break `lookup`.

### 3. JSON and schema (`JsonText`, `Messages`)

- A hand-written RFC 8259 subset parser and writer, so the host adds no dependency
  and every limit is enforced while reading:
  one value, RFC whitespace only, no BOM or comments, depth ≤ 8, ≤ 256 members per object or
  array, duplicate names refused, strings ≤ 65,536 UTF-16 units with no raw control characters,
  only RFC escapes, escaped surrogates only as valid pairs, integers only (≤ 15 digits, no
  leading zero, no fraction or exponent). Violations are `MALFORMED`.
- Strings are kept as `char[]` (`Json.Str`), so a password goes from the frame into a
  `SecretChars` and from a `SecretBytes` into the reply without becoming a `String` (MSC03-J,
  ADR 0008). Every reply tree is wiped after it is written.
- Every request is one object. Its member names must be **exactly** the set for its `type`;
  a missing, extra or wrongly-typed member is `BAD_FIELD`, an unknown `type` is `UNKNOWN_TYPE`:

  | `type` | members | notes |
  | --- | --- | --- |
  | `hello` | `type`, `id`, `version` | `version` must be 1, else `VERSION` |
  | `lookup` | `type`, `id`, `origin` | |
  | `fill` | `type`, `id`, `origin`, `entry` | `entry`: lowercase canonical UUID |
  | `save` | `type`, `id`, `origin`, `username`, `password` | username 0–1,024 chars, no controls; password 1–4,096 chars |
  | `generate` | `type`, `id`, `origin`, `username`, `policy` | username as for `save` (stored with the new login); `policy` = exactly `length` (8–128), `lower`, `upper`, `digits`, `symbols` (booleans, at least one true) |

  `id` is the extension's correlation id (1–64 of `[A-Za-z0-9_-]`), echoed in the reply.
  `origin` is 1–256 printable ASCII characters at this layer; the bridge canonicalises it (§5).
- Replies are objects `{"type", "id", ...}`. Errors are
  `{"type":"error","id":<id or null>,"code":"<CODE>"}` where the code is a `HostException.Code`
  name (or, from M5.2, a broker `Decision` name). A schema error does not end the session.

### 4. Caller allowlist (`ExtensionAllowlist`, SR-301)

- Chrome passes the caller's origin `chrome-extension://<id>/` as the first argument (on Windows
  also `--parent-window=<n>`). The host accepts exactly that form, with `<id>` 32 letters a–p and
  present in its allowlist file, plus at most the parent-window argument. Anything else exits
  with status 2 **before a byte of stdin is read**, and nothing is written.
- This duplicates the manifest's `allowed_origins` on purpose: the manifest lives in a
  user-writable browser directory, and another browser profile may register a different
  extension under the same host name. The allowlist file (one ID per line, `#` comments, at most
  4 KiB, a regular file and not a link) is written by `pm browser install` (M5.4, §8).

### 5. Exact origins (`pm.browser.bridge.Origin`, SR-300, SR-306)

- An origin is `(scheme, host, port)`. The extension sends `location.origin` of the top-level
  page; `Origin.parse` accepts exactly that form (no path, query or fragment). Registered URLs on a
  login go through `Origin.ofUrl`, which drops path, query and fragment; a URL without an
  `http(s)` scheme (`example.com`, `android://…`) never matches anything.
- Canonicalisation, in order: scheme lowercased (A–Z only) and limited to `http`/`https`; the
  authority must contain no `@` (userinfo), `[`/`]` (IPv6), `\`, `%` or whitespace; the port, if
  any, is 1–65535 without sign or leading zero, and the scheme default (80/443) is made explicit so
  `https://example.com:443` equals `https://example.com`; the host is lowercased (A–Z only) and
  must be ASCII LDH labels of 1–63 characters, at most 253 in all. **No IDNA mapping is done**:
  any non-ASCII host is refused. `java.net.IDN` implements IDNA2003 (transitional), which maps
  `faß.de` to `fass.de`, final `ς` to `σ` and silently drops ZWJ/ZWNJ, while browsers use UTS #46
  non-transitional processing (`faß.de` is `xn--fa-hia.de`, a different registrable name, and
  joiners are refused). Browsers already serialise `location.origin` with A-labels, so requiring
  A-labels on both sides compares exactly what the browser compares. A login URL stored in Unicode
  form never matches; it must be stored as the browser shows it in `location.origin`. A trailing dot, an empty label or an
  underscore is refused. A host whose last label is numeric or starts `0x` must be a canonical
  dotted quad (`127.0.0.1`); `0x7f.0.0.1`, `2130706433`, `127.1`, `010.0.0.1` are refused rather
  than guessed at. IPv6 literals are refused for now (no use case; one less parser).
- Matching is `equals` on the canonical triple: `a.example.com` ≠ `example.com`, `http` ≠ `https`,
  `:8443` ≠ default, and an IDN lookalike (`https://аpple.com` with Cyrillic `а`) reaches the
  host as `xn--pple-43d.com`, which is a different origin from `apple.com`. No public-suffix or
  "same site" leniency exists anywhere.

### 6. Broker-gated release (`Bridge`, `VaultPort`, `ApprovalPort`, SR-302, SR-307)

- `Bridge` implements the host's `Handler`. It depends on two ports, so `pm-browser` never depends
  on `pm-tui` or the vault: `VaultPort` (login metadata, `password(Grant, id)`,
  `save(Grant, origin, username, password)`) and `ApprovalPort` (`isUnlocked`, `approve`).
  `ApprovalPort.inProcess(broker, wait)` presents the broker's session token, waits at most `wait`
  and turns a timeout or interrupt into `DENIED_TIMEOUT` and a locked vault into `DENIED_LOCKED`.
- `lookup` needs an unlocked vault but no prompt; it returns ids, titles and usernames of logins
  registered for exactly that origin (at most 64), never a password.
- `fill`, `save` and `generate` each build **one** `ApprovalRequest`: operation `AUTOFILL`,
  requester `(EXTENSION, <extension id>)`, scope project = the canonical origin text, no
  variables, no record ids, duration 0. The profile is `save`, `generate`, or for a fill
  `fill-<login id in base 36>` (all 128 bits, at most 30 characters, a valid profile name). Effect
  `SEND` (fill) or `WRITE_FILE` (save, generate). So a session or temporary policy the user grants
  covers that extension, that origin, that action and, for fills, **that one login** ("allow
  filling *Example / alice* on example.com until lock"), and nothing else (SR-302); another login
  on the same site prompts again.
- The prompt names what is released: the display line is `<origin> - fill login "<title>",
  username "<username>"` (or `save a new login, username "…"`, `generate a password, save it as a
  new login (username "…") and fill it`), never a password. Title and username are cut to 64 code
  points with control characters replaced by `?`. `ApprovalRequest.Display` has no separate
  subject field, so this text travels in `Display.origin`; the broker never matches on the display,
  and the TUI dialog renders it, with the origin on its own line (§8). A dedicated field would be
  a `pm-approval` change; M5.4 did not need one. `pm-approval` has no `SAVE`/`GENERATE` operation; the profile carries the action
  instead. A later `pm-approval` change may add dedicated operations; the bridge's requests would
  change, not its checks.
- `fill` first finds the login by id **and** exact origin (else `NOT_FOUND`, no prompt, so a page
  cannot spam prompts for logins it is not registered for). It then asks the broker. Any denial
  becomes an `error` whose code is the `Decision` name (`DENIED`, `DENIED_TIMEOUT`, …) and the
  vault is not called. On approval the bridge checks the grant is for **exactly** the request it
  built and unused, hands it to the vault port, and after the call refuses (`INTERNAL`, password
  wiped) if the port did not consume it. A `Grant` has no public constructor, so neither a port
  nor the extension can manufacture one; the tests drive a real `ApprovalBroker` that denies,
  approves once and approves for the session.
- Replies to `fill` and `generate` carry the canonical origin; the extension fills only if the
  tab's top-level origin still equals it (§7, M5.3).
- `generate` draws each character uniformly by rejection sampling from the chosen classes and
  redraws a candidate that lacks a chosen class (at most 64 candidates). It then **stores the
  password as a new login** for the origin (with the request's username) through
  `VaultPort.save` under the same grant, checks the grant was consumed, and only then replies
  with the origin, the new entry id and the password. If the save fails nothing is released, so
  a generated password can never exist only in a page form (an account the user could not log in
  to again). A password change on an existing account therefore creates a second login; the user
  deletes the old one in pm.
- Process boundary: Chrome starts the host as its own process, while the broker and the open vault
  live in the TUI process. M5.4 provides the relay (§8: the host forwards the decoded request to
  the TUI over its own socket in the broker's 0700 run directory, where `Bridge` runs against the
  TUI's broker and session). The host process itself never holds the vault key or a grant.

### 7. The extension (`extension/`, SR-304, SR-308, SR-309)

- Manifest V3 with exactly `nativeMessaging`, `activeTab` and `scripting`, no host permissions,
  no content scripts, no web-accessible resources and a `script-src 'self'` CSP. Each permission
  is justified in `docs/security/extension-permissions.md`.
- `background.js` (module service worker) delegates to `bridge.js`, which accepts messages only
  from its own popup, reads the origin from the active tab itself, sends one native message per
  action to host `pm.browser`, checks the reply's `type`, `id` and shape, and injects
  `fillInPage` with `frameIds: [0]` only when the reply's approved origin equals the tab origin.
  `fill.js` checks again inside the page (`window.top === window`, `location.origin` equal).
  Passwords go from the native reply straight into the injected call, never to the popup.
- `fill.js` writes only into fields the user can see: enabled, writable,
  `checkVisibility({opacityProperty, visibilityProperty, contentVisibilityAuto})` true (which
  covers `display:none`, `visibility:hidden` and `opacity:0` on the field or any ancestor) and a
  non-zero bounding box; hence `minimum_chrome_version` 121. It calls DOM methods through
  `Document.prototype`, `Element.prototype` and the `HTMLInputElement.prototype.form` getter,
  because a form control named `querySelectorAll` or `getAttribute` shadows that property on its
  form. Off-screen but rendered fields are still eligible (a scrolled login form is legitimate).
- `generate` sends the popup's username, requires the reply to carry the stored entry id, and
  then fills. If the fill fails after the save, the popup is told the login was saved and why it
  was not filled.
- Service worker lifetime: Chrome may stop an idle MV3 service worker (about 30 s) even while a
  `sendNativeMessage` call waits on a slow approval; whether a pending native call keeps the
  worker alive is not verified (INFERRED). The extension therefore never fails silently: a
  native call that rejects after the host started is `HOST_DISCONNECTED`, a host that cannot be
  started is `HOST_UNAVAILABLE`, and the popup turns a rejected or empty answer from the
  background (worker stopped) into "the request was interrupted before pm answered". §8
  documents the TUI side (the waiting prompt is denied, nothing released). Still to do: measure this with the real relay and, if approvals routinely outlive the worker, keep it
  alive for the duration (for example a popup-held `runtime.connect` port that the background
  pings) or move to a `connectNative` port; nothing is filled after an interruption, because the
  answer that would carry the password is lost with the worker.
- `popup.html`/`popup.js` list logins (metadata from `lookup`), and offer a generate-save-and-fill
  form and a save form.
  DOM is built with `textContent`; the typed password is cleared after a save.
- Tests run with `node --test` and fakes for `chrome.*` and the DOM (no npm dependencies), wired
  into Gradle as `:modules:pm-browser:extensionTest`, which `check` depends on.
- `extension/native-host/pm.browser.json.template` is the host manifest the M5.4 installer fills in.

### 8. Installer, TUI relay and prompt (M5.4, SR-113, SR-114)

**Installing (`pm browser install | uninstall | status`, `pm.cli.BrowserCommands`, SR-114).**

- `pm browser install [--browser chrome|chromium|edge|brave|all] [--extension-id <id>]` writes the
  manifest `<browser dir>/NativeMessagingHosts/pm.browser.json` for each selected browser whose
  per-user folder exists (`all`, the default, skips absent browsers; a browser named explicitly
  but absent is reported and the command exits `NOT_DONE`). The folders are, on macOS,
  `~/Library/Application Support/{Google/Chrome, Chromium, Microsoft Edge,
  BraveSoftware/Brave-Browser}` and, on Linux, `$XDG_CONFIG_HOME/{google-chrome, chromium,
  microsoft-edge, BraveSoftware/Brave-Browser}`, where an unset or relative `XDG_CONFIG_HOME`
  means `~/.config` (the base directory spec ignores relative values, and so does pm).
- The manifest has exactly `name` (`pm.browser`), `description`, `path`, `type` (`stdio`) and
  `allowed_origins`, which is exactly one `"chrome-extension://<id>/"` per extension installed
  for that browser (see below). `path` is the absolute,
  symlink-resolved path of the installed pm launcher: the jpackage executable
  (`jpackage.app-path`), else `bin/pm` of the release archive, worked out from where the
  `pm.cli` module was loaded. A source checkout's `scripts/pm` (it starts Gradle on every
  launch) is refused with a message saying to run `pm browser install` from the release
  archive's `bin/pm` or the packaged app. The launcher must be a regular
  executable file owned by the user or root and writable by neither group nor others, and
  **every folder above it** must be owned by the user or root and not writable by group or
  others, unless it is root-owned and sticky (`/tmp`); otherwise nothing is installed. A
  consequence: a launcher under macOS `/Applications` (root:admin, `0775`) is refused, because
  any admin user could replace the program the browser starts; install the app under
  `~/Applications` or a folder only root can write.
- The extension ID (32 letters a–p) goes into the allowlist next to the **default** vault
  (`browser-extensions`, §4); without `--extension-id` the allowlist must hold exactly one ID.
  Every check (ID, vault folder, allowlist, launcher, each browser's slot) runs before anything
  is written, and the allowlist is written only after at least one manifest for that extension
  is pm's (written now or already identical): if every selected browser holds a foreign or
  unsafe manifest, nothing is written and the allowlist is unchanged. The allowlist stays the
  single list of allowed extensions: the host and the relay read only it, and the manifest is
  the browser's own first gate.
- Every write is atomic: a new `0600` file created with `CREATE_NEW` next to the target, flushed
  (`force`), then renamed over it (`ATOMIC_MOVE`); a missing `NativeMessagingHosts` folder is
  created `0700`. The browser folder, the manifest folder, the manifest, the vault folder and the
  allowlist must each be no symbolic link (checked with `NOFOLLOW_LINKS`; a manifest is also
  read with `NOFOLLOW_LINKS`), owned by the current user and not writable by group or others;
  otherwise that browser (or the whole command, for the vault folder) is refused and left alone.
  The folders **above** the browser folder follow the launcher's rule: on the real path of its
  parent, up to and including the user's home (or up to `/` for an `XDG_CONFIG_HOME` outside the
  home), each folder must be owned by the user or root and not writable by group or others,
  unless root-owned and sticky. A link among them is followed and the folder it leads to is what
  counts, so a world-writable `XDG_CONFIG_HOME`, or `Application Support/Google` linked to a
  world-writable folder, is refused: whoever could rename entries there could swap the browser
  folder and choose the program the browser starts.
- A manifest under the name `pm.browser` that pm did not write (any other member set,
  description or type, or not strict JSON) is **foreign**: install refuses to replace it and
  uninstall leaves it. Installing again with identical bytes writes nothing ("already
  installed"). **Each browser's manifest is its own record** (M5.4 round 3, m54c-001): installing
  `<id>` for a browser adds that one ID to that browser's manifest, after the IDs it already
  allows that are still allowlisted, and touches no other browser's manifest. An extension
  installed for Chrome is never widened to Chromium by a later Chromium install, and one taken
  off Chromium stays off when another extension is installed there. The allowlist is the
  **union** of what pm's manifests allow: install adds the ID; `uninstall` deletes only pm's
  manifests; `uninstall --extension-id <id>` takes that extension off the named browsers'
  manifests (rewriting each with the others, and deleting one that would allow nothing); after
  either, an ID leaves the allowlist once no manifest of pm's allows it any more. When no
  browser is left with an installed manifest of pm's, the allowlist is cleared, so an
  uninstalled bridge leaves no extension allowed. `status` reports
  each browser as installed, not installed, foreign, stale (pm's manifest naming another
  launcher or an extension no longer allowlisted), unsafe or not found, lists under each
  installed or stale browser exactly the extension IDs its manifest allows, and then lists the
  allowlisted extension IDs, marking any that no browser's manifest allows.
- Windows registers native hosts in the registry
  (`HKEY_CURRENT_USER\Software\<vendor>\NativeMessagingHosts\pm.browser`). pm never writes the
  registry: `install` prints the keys, the manifest and the allowlist line for the user to apply
  by hand, writes nothing and exits `NOT_DONE` (10); `status` and `uninstall` exit `NOT_DONE`.
- `pm --vault <other> browser …` is a usage error: the host has no way to learn a vault path
  (Chrome passes no options), so the extension always works with the default vault.

**Host process (`pm.cli.BrowserHost`).** Chrome starts the manifest's `path` with
`chrome-extension://<id>/` as the first argument, which is what selects host mode (stdout then
carries frames only). The host reads the default vault's allowlist (missing or damaged: exit 2,
stdin unread), runs `NativeHost` (§2–§4), answers `hello` itself and forwards every other
request to the TUI through the default vault's relay socket. It never opens the vault, never
approves anything and creates nothing.

**Relay (`pm.tui.BrowserRelay`, SR-113).** This refines §6: the relay is its own socket,
`browser.sock`, served by the TUI next to `BrokerServer` from the first unlock until exit.

- **Where.** The socket lives in `<default vault file>.browser/`, created `0700` and checked
  owner-only and not a link (`RunDir.prepare`). The path is derived from the vault path alone,
  never from `XDG_RUNTIME_DIR` or another environment variable, because Chrome starts the host
  with an environment that need not match the terminal's; the TUI and the host compute the same
  path. A path longer than the JDK binds is not bound, and the TUI's status line says "browser
  off: socket path too long". The limit is the JDK's, not the raw `sun_path` size: `sun_path`
  holds 104 bytes on macOS and the BSDs and 108 on Linux, and the JDK keeps two of them back, so
  the longest path it binds is 102 bytes on macOS and 106 on Linux (measured: on macOS a 103-byte
  path fails with "Unix domain path too long"). If binding fails anyway, the reason is reported
  for what it is: a path too long for the OS the JVM runs on is "path too long", a socket another
  TUI bound first and that accepts connections is "another pm window serves it", and anything
  else is "unsafe"; a failed bind is never reported as in use without a live socket.
- **Who serves.** Only a TUI on the default vault starts the relay; on another vault the status
  line says "browser off: not the default vault", and if the TUI's broker cannot start, "browser
  off: approvals unavailable". The serving TUI holds a lock on `relay.lock` in the relay folder.
  A second TUI that finds the lock held, or the socket live (a probe connection is accepted),
  leaves the socket alone ("browser off: another pm window serves it"). A socket nobody accepts
  on (a crashed TUI) is replaced. `BrokerServer` got the same probe in this round: it used to
  delete whatever socket file it found, so a second TUI took the first one's broker socket over.
- **What the peer must show.** The host sends a frame `<extension id> <host>` and one with the
  request, re-encoded member for member; the TUI decodes it again with the host's schema
  (`Messages.decodeWithoutPasskeys`) and answers with exactly one reply frame. Peer credentials are checked (`SO_PEERCRED`, same OS
  user) where the platform has them; elsewhere the `0700` folder is the gate. On every request
  the extension ID must be **in the allowlist**, read again each time, so taking an ID off takes
  effect without a restart (a well-formed ID is not enough). For a request that needs a prompt
  the allowlist is read again when the dialog is about to show the prompt and when the answer
  arrives: a prompt whose extension was taken off meanwhile is denied without being shown, and an
  approval given anyway is dropped with its grant unused; the extension gets `DENIED_AUTH`. For
  `fill` and `generate`, whose replies carry a password, the allowlist is read **once more after
  the password is in hand and immediately before the reply is written**: an extension taken off
  while the vault was being read gets `DENIED_AUTH`, and the reply holding the password is wiped
  unsent (a generated login has been saved by then and stays in the vault; only its password is
  withheld). `<host>` is the host instance:
  128 random bits (32 lower-case hex digits) the host process draws once from `Csprng`. It groups
  one host's requests for the limits below and the prompt shows its first 8 digits as
  `from browser host <8 hex> (unverified)`; it proves nothing. The relay does not look at the
  process behind the socket (no process ID, start time or program): process APIs are confined to
  the env runner and the platform adapters (SR-100, `ModuleBoundaryTest`), and a process ID the
  peer sends would only be its claim (SR-101).
- **An overruled approval is audited as refused** (m54c-002). The broker audits the user's
  answer when it is given. When the user allowed a request that the relay then refuses all the
  same (the host went away, the wait ran out, the extension was taken off the allowlist while the
  prompt waited, or the reply was withheld by the final check above), the relay writes a second
  `approval` entry for the same request ID with the refusing decision (`DENIED`,
  `DENIED_TIMEOUT` or `DENIED_AUTH`), through the same `AuditLog` (its API is unchanged), so the
  log never shows a release that did not happen. If the user's answer is still in flight when the
  relay gives up (the prompt has left the queue but the broker is writing its entry), the relay
  waits up to 5 s for it before deciding whether a second entry is needed. The refusal stands
  whether or not that entry can be written. A denial needs no second entry.
- **Approvals never outlive a connection.** The requester label is `<extension id>
  #<connection>`, so a session or one-hour policy can never match a request on another
  connection, from the same program or any other. The browser prompt therefore offers only
  "once" and "deny" (`s` and `p` do nothing). Each host instance may have one prompt waiting;
  another request from it meanwhile is answered `DENIED_BUSY`.
- **Lookups.** `lookup` returns titles and usernames without a prompt, so it is rate-limited by
  token buckets: 10 a minute per host instance and 20 a minute in all, then `DENIED_BUSY`. Every served
  lookup is audited (requester kind `EXTENSION`, profile `lookup`) with the origin and the number
  of logins found, never their titles or usernames; a refused burst is audited once a minute. If
  the audit entry cannot be written, the lookup is not answered (`INTERNAL`).
- **Slots and deadlines.** At most 4 requests are served at once (more get `DENIED_BUSY`). A peer
  that sends no complete request within 5 s, or does not take its reply within 5 s, is
  disconnected, so silent or non-reading peers cannot hold the slots.
- In the TUI, `Bridge` runs against the TUI's broker (`RelayApproval`, which presents the
  session token like `ApprovalPort.inProcess`) and the open session (`GuiThreadBrowserVault`,
  every access on the GUI thread, a password copied out only under an unused `AUTOFILL` grant
  from an `EXTENSION` requester, which the copy consumes). Each `fill`, `save` and `generate`
  is therefore a TUI prompt. On lock the vault port is withdrawn and the broker denies waiting
  prompts. Browser passkeys are not in v1 (M6.4 descoped): the host
  (`NativeHost.runWithoutPasskeys`) and the relay (`Messages.decodeWithoutPasskeys`) treat
  `webauthn.create` and `webauthn.get` exactly like a type they do not know: only the `type`
  member is read, and the reply is the unknown type's, byte for byte (`UNKNOWN_TYPE` with a null
  `id`), whether the rest of the body is valid, partial or missing, so the reply reveals nothing
  about passkey support or its schema. Nothing is relayed, the relay's `Bridge` is built with
  `PasskeyPort.NONE`, and no production path constructs `VaultPasskeys`.
- **No TUI, no release.** With no TUI running (or before the first unlock, or after the TUI
  exits) there is no socket, and the host answers `DENIED_LOCKED` to every request; the
  extension shows that pm is locked. There is no host-side session policy and no automatic
  approval.
- **Residual risk (accepted).** Any process of the same OS user can connect to the relay and
  claim to be the native host, with any allowlisted extension ID and any host instance (a new
  one per request escapes the per-host limits; the global lookup bucket still holds). It gets no
  password unless the user approves a prompt that shows the exact origin and the claimed host
  instance, and every connection needs its own approval. The prompt cannot say which program is
  asking. The TM-20
  session token is deliberately not required here: it would sit in a run-folder file the same
  user can read, so it would add no barrier against this attacker. Within the rate limits such a
  process can list the titles and usernames saved for an origin, and each such lookup is
  audited. Recorded as R-011 in the risk register.
- **Residual risk (accepted, M5.4).** `BrokerServer` probes an existing socket before replacing
  it, but unlike the relay it holds no lock file around check, delete and bind: two TUIs starting
  on the same vault within the same instant can both find no live socket, and the later bind
  replaces the first one's socket file, leaving the first broker unreachable (it keeps running,
  and its prompts are not lost). Both processes belong to the user, nothing is released, and
  restarting the stranded TUI recovers; a `broker.lock` like `relay.lock` (with the Windows
  owner-only handling of `RunDir`) is the follow-up.

**Prompt (`ApprovalDialog`, SR-113).** For an `AUTOFILL` request the dialog shows the requester
label, the sending host (`from browser host <8 hex> (unverified)`, or in red "from an unknown sender" if the
relay did not register the request), then `site <origin>` (the request's canonical origin,
exactly as matched) and `action <what>` (the display text after `<origin> - `, e.g.
`fill login "Example", username "alice"`). Everything goes through `DisplaySafe`, so C0/C1
controls, bidi overrides and line separators render as `�` and never reach the terminal. Lines
are measured in terminal columns (a CJK character takes two); the origin is wrapped over as many
lines as it needs and never cut. If the whole prompt does not fit the terminal, when it opens or
after the terminal shrinks, the request is **denied** and the dialog says so until Enter or Esc.
An internationalised host (`xn--` A-label, which a browser may show as a lookalike Unicode name)
or any non-ASCII character adds a red "check the site letter by letter" warning. The input
guard, confirmation and timeout are the same as for every prompt (SR-109, SR-111); approving
once releases one password, and the next request prompts again.

**Service worker lifetime (M5.3 §7 follow-up).** If the extension's service worker is stopped
while a request waits for approval, Chrome closes the native host's pipes and ends the host
process (INFERRED from Chromium's native messaging host lifecycle; not measured against a real
browser in M5.4). The host's relay connection then closes; the TUI notices the end of stream on
that connection, **denies the waiting prompt** (it disappears from the TUI), and if an approval
races it, the grant is dropped unused, so **nothing is released** for an answer nobody would
receive. The same happens if the host gives up waiting (`REPLY_WAIT`, the prompt timeout plus a
margin). The extension reports such a call as interrupted (§7) and fills nothing. Whether
approvals routinely outlive the worker in practice is still to be measured; until then a user who
is slow to approve simply clicks again.

## Alternatives considered

- **A JSON library** (Jackson, Gson, minimal-json): rejected. It adds a dependency to a Tier 1
  module, accepts more than the protocol needs (floats, big numbers, lenient modes), and would
  turn every password into a `String`. The subset here is a few hundred lines with 100% branch
  coverage, and the M5.5 fuzz harness targets it directly.
- **Long-lived `connectNative` port**: rejected. The MV3 service worker can be killed after 30 s
  idle, so a port would need reconnect logic anyway; one process per message keeps the host
  stateless.
- **Trusting `allowed_origins` alone**: rejected for the reasons in §4.
- **eTLD+1 or "same site" matching** (what some managers do for subdomains): rejected. It needs a
  public-suffix list that must be kept current, and it is exactly the leniency AT-5 exploits
  (a hostile or compromised subdomain). The user can register more URLs on a login instead.
- **Putting the record id in the request scope**: rejected. A scope with record ids never matches a
  policy (approval-model §3), so session policies would be impossible for autofill.

## Consequences

- Every message costs one host process start (JVM start-up, about 100 ms with CDS). Acceptable
  for click-driven fills.
- Big-endian hosts are unsupported; none is in the platform matrix.

## CERT rules referenced

MSC05-J (bounded input), IDS00-J/IDS01-J (validate after decoding, strict UTF-8), STR00-J
(no partial characters), MSC03-J and FIO13-J (secrets never in `String` or logs), ERR01-J
(codes only), FIO04-J (streams closed by the owner).
