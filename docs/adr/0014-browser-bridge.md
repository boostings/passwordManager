# ADR 0014: Browser bridge — Chrome native messaging host, exact origins, broker-gated release

- Status: Accepted (M5.1 host, M5.2 bridge)
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
  the pending call dies with it (§7 says how the extension reports this; M5.4 must measure it).

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
  4 KiB, a regular file and not a link) is written by `pm browser install` (M5.4).

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
  and the TUI dialog shows it once M5.4 renders `Display.origin` (it currently shows project and
  profile only). A dedicated field is a `pm-approval` change for M5.4. `pm-approval` has no `SAVE`/`GENERATE` operation; the profile carries the action
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
  live in the TUI process. M5.4 provides the relay (`pm browser host` forwards the decoded request
  to the TUI over the existing 0600 broker socket, where `Bridge` runs with
  `ApprovalPort.inProcess`). The host process itself never holds the vault key or a grant.

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
