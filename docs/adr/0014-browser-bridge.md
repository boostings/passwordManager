# ADR 0014: Browser bridge — Chrome native messaging host, exact origins, broker-gated release

- Status: Accepted (M5.1 host)
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

## Alternatives considered

- **A JSON library** (Jackson, Gson, minimal-json): rejected. It adds a dependency to a Tier 1
  module, accepts more than the protocol needs (floats, big numbers, lenient modes), and would
  turn every password into a `String`. The subset here is a few hundred lines with 100% branch
  coverage, and the M5.5 fuzz harness targets it directly.
- **Long-lived `connectNative` port**: rejected. The MV3 service worker can be killed after 30 s
  idle, so a port would need reconnect logic anyway; one process per message keeps the host
  stateless.
- **Trusting `allowed_origins` alone**: rejected for the reasons in §4.

## Consequences

- Every message costs one host process start (JVM start-up, about 100 ms with CDS). Acceptable
  for click-driven fills.
- Big-endian hosts are unsupported; none is in the platform matrix.

## CERT rules referenced

MSC05-J (bounded input), IDS00-J/IDS01-J (validate after decoding, strict UTF-8), STR00-J
(no partial characters), MSC03-J and FIO13-J (secrets never in `String` or logs), ERR01-J
(codes only), FIO04-J (streams closed by the owner).
