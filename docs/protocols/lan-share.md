# LAN Share Protocol v1

Normative specification for device pairing and secret/project transfer
(`pm-sharing`). Decision recorded in ADR 0010. All cryptography is JDK-only:
TLS 1.3, Ed25519, X25519 (via TLS), HKDF, SHA-256, AES-256-GCM.

## 1. Identity

Each install generates once, inside the vault (Secret class):
- `id_sk`: Ed25519 private key; `id_pk` public key.
- `device_id` = first 16 bytes of SHA-256(id_pk).
- A self-signed X.509 certificate for `id_pk`, CN = base32(device_id),
  validity 10 years, regenerated on identity rotation.

Fingerprint shown to users: SHA-256(id_pk) as 8 groups of 4 hex.

## 2. Discovery (advisory only, SR-200)

mDNS/DNS-SD service `_pmshare._tcp` with TXT `v=1`, `id=<base32 device_id>`,
`name=<user-chosen, ≤32 chars>`. Discovery output populates a list; nothing in
it is trusted. Manual entry of `host:port` is always available.

Discovery is announced **only** while a pairing or share window is open.

## 3. Transport

TLS 1.3 only, cipher suites `TLS_AES_256_GCM_SHA384` and
`TLS_CHACHA20_POLY1305_SHA256`, mutual authentication required, custom
`X509TrustManager` that:
- during pairing: accepts any self-signed cert whose key is Ed25519, records it
  as *candidate*;
- after pairing: accepts only certs whose SHA-256(pk) matches a pinned trusted
  device; revoked or unknown → handshake failure (SR-205).
Hostname verification is disabled (identity is the pinned key, not DNS).
Listener binds one chosen interface address, ephemeral port, `SO_REUSEADDR`
off, backlog 4, per-connection read timeout 10 s, idle timeout 60 s.

## 4. Messages

Framing: `u32 length (≤ 1 MiB) ‖ CBOR body`. Body is a map with
`{t: <type>, seq: uint, ...}`. `seq` starts at 0 per direction per session and
must increase by exactly 1; any gap or repeat closes the session (SR-202).
Unknown `t` closes the session. All bodies are validated against
`docs/schemas/lan-share.cddl` before dispatch (SR-206).

```
HELLO        {t:"hello", seq, v:1, device_id, name, caps:[..]}
PAIR_REQ     {t:"pair_req", seq}
PAIR_COMMIT  {t:"pair_commit", seq, commit(32B)}   ; initiator → responder, see §5
PAIR_NONCE   {t:"pair_nonce", seq, nonce(32B)}     ; responder → initiator
PAIR_REVEAL  {t:"pair_reveal", seq, nonce(32B)}    ; initiator → responder
PAIR_SAS_OK  {t:"pair_sas_ok", seq, mac}          ; see §5
PAIR_DONE    {t:"pair_done", seq}
SHARE_OFFER  {t:"share_offer", seq, share_id(16B), kind:"secret"/"project", summary, expires, one_use:bool}
SHARE_ACCEPT {t:"share_accept", seq, share_id}
SHARE_DATA   {t:"share_data", seq, share_id, payload: bytes}   ; CBOR record set (ADR 0006), ≤ 1 MiB
SHARE_ACK    {t:"share_ack", seq, share_id, applied:bool}
REVOKE       {t:"revoke", seq, device_id}          ; courtesy notice only
ERROR        {t:"error", seq, code:uint}
BYE          {t:"bye", seq}
```

## 5. Pairing ceremony (SR-201, SR-203)

1. Both users open "Pair" in the TUI. Initiator I connects to responder R.
2. TLS 1.3 mutual handshake with candidate certs. Both sides now have the
   authenticated `pk_I` and `pk_R`. (JDK 21 has no TLS exporter; ADR 0010
   Amendment 1 explains why none is needed and why the earlier construction was
   unsafe.)
3. Commit, then reveal (ADR 0010 Amendment 1):
   - I draws a 32-byte random `n_I` and sends `PAIR_COMMIT` with
     `commit = SHA-256("pm/pair/commit/v1" ‖ pk_I ‖ n_I)`.
   - R draws `n_R` and sends `PAIR_NONCE`. R sends it only after it has received the commitment.
   - I sends `PAIR_REVEAL` with `n_I`. R checks, in constant time, that it opens
     the commitment under `pk_I`. Otherwise the ceremony fails and counts toward the
     lockout.
   Each side computes `sas_key = HKDF-SHA256(ikm = n_I ‖ n_R, salt = "pm/pair/v1",
   info = "pm/sas/v1" ‖ min(pk_I,pk_R) ‖ max(pk_I,pk_R), 32)`, ordering keys by
   unsigned bytes, and `SAS = (first 8 bytes of sas_key, unsigned big-endian) mod
   1_000_000`, zero-padded to 6 digits. Both screens display it.
4. Each user confirms "the other screen shows the same 6 digits". Only then
   does each side send `PAIR_SAS_OK` with `mac = HMAC-SHA256(sas_key, "ok" ‖ own pk)`.
   The MAC proves the peer derived the same `sas_key` (i.e. same tunnel, no MITM)
   without ever transmitting the SAS.
5. On valid MAC both send `PAIR_DONE`, pin the peer's `pk` in the vault trust
   list with name, platform, and time. Pairing window closes.
6. Rate limiting: 3 failed ceremonies from any source → listener refuses new
   pairings for 60 s, doubling per failure, cap 1 h. A MITM who cannot make the
   SAS match on both screens has a 1-in-10^6 chance per attempt; with lockout,
   brute force is impractical (SR-203).

Why this is safe without a PAKE: an attacker in the middle runs two sessions.
In each one it must fix its own nonce before it learns a random nonce from the
victim (the commitment does this when it plays the initiator, and the message
order does it when it plays the responder). So it cannot steer the two screens
to the same digits; they match with probability 10^-6, and the lockout bounds
the attempts. Both certificate keys are in the derivation, so a matching SAS
also authenticates exactly the keys that are then pinned.

## 6. Share transfer (SR-204, SR-208)

1. Sender S selects records/project, target device T, expiry (default 10 min,
   max 24 h), and one-use (default on). Approval broker prompt (operation
   `share`) is mandatory.
2. S opens listener, connects or accepts T (pinned TLS). `SHARE_OFFER`.
3. T shows the offer summary (names/counts, never values) and the user
   accepts → `SHARE_ACCEPT`.
4. S sends `SHARE_DATA`. Payload is the CBOR record set; it is already inside
   the TLS tunnel and the tunnel is mutually authenticated, so no extra layer
   is needed. (Records are re-encrypted into T's vault by T.)
5. T fully decodes and validates the payload, then applies it atomically in
   one vault save; sends `SHARE_ACK applied=true`. Any failure → nothing
   applied, `applied=false`, `ERROR`.
6. S marks `share_id` used (if one-use) or decrements; expiry is enforced by
   S regardless of T. Audit entries on both sides (no values).
7. Listener closes when no active share window remains (SR-207).

Implementation notes (M3.4, `pm.sharing.share`):

- A one-use share is consumed when S releases `SHARE_DATA`, before it is sent,
  so a lost `SHARE_ACK` can never lead to a second copy. A failed apply on T
  therefore also consumes it; S opens a new window to retry.
- T keeps the ids it has applied and refuses an offer that repeats one
  (`REPLAY`). T also refuses an offer whose `expires` is not after its own
  clock, independently of S.
- S accepts a TLS client only if it is trusted **and** has an open window, so
  a revoked device or one with nothing offered fails at the handshake. Each
  such refusal is reported for the audit log.
- `ERROR` codes: 1 protocol, 2 expired, 3 used, 4 revoked, 5 unknown share,
  6 not applied, 7 replay. Any other code is treated as an abort.
- The listener polls every 100 ms for expiry and closes itself, releasing the
  port, when no window is open: after the last one-use send, at expiry, or on
  revocation.

## 7. Browser-only receiving (SR-209, SR-210)

1. S generates `k_web` (32 B random) and `share_id` (16 B); encrypts the
   payload (UTF-8 text, ≤ 1 MiB) with AES-256-GCM(k_web, nonce = 12 zero bytes,
   AAD = share_id). `k_web` encrypts exactly one message (ADR 0005).
2. S starts an HTTPS listener with a throwaway ECDSA P-256 certificate made
   for this share (browsers do not accept Ed25519; ADR 0010 Amendment 2), TLS 1.3
   only, no client certificate. It serves the page `https://<ip>:<port>/s/<share_id hex>`
   (nothing secret; repeatable, so link previews cannot burn the share) and
   `/d/<share_id hex>` once, only after the page, then closes; it also closes at
   expiry or on revocation, cutting off any request in flight. Each connection
   is closed 5 s after accept. Anything else: 404, 405 or 410. Every response carries
   `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none';
   script-src 'sha256-<inline>'; style-src 'unsafe-inline'; connect-src 'self';
   base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
   `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`,
   `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`,
   `Cross-Origin-Resource-Policy: same-origin`, `Connection: close`.
3. The URL shown/QR-encoded is `https://<ip>:<port>/s/<share_id hex>#<base64url k_web>`.
   The fragment never leaves the browser.
4. The page's inline script removes the fragment from the address bar and the
   session history entry (the browser's history database keeps the full URL;
   ADR 0010 Amendment 2), fetches `/d/<share_id>` (ciphertext ‖ tag) with `cache: no-store`,
   decrypts with WebCrypto, shows the text with `textContent`, offers Copy, and
   clears it after 120 s or on `pagehide`. No storage APIs, cookies or service
   workers are used.
5. The recipient sees a browser certificate warning for the self-signed cert;
   the page explains this, and the TUI shows the certificate's SHA-256
   fingerprint (as browsers display it) so the recipient can compare.
   Confidentiality against a passive observer does not depend on that check
   because of `k_web`; an active attacker who substitutes the page can read the
   fragment, which is the residual risk documented to the sender.

## 8. Revocation (SR-205)

Delete the pinned key from the trust list; save vault; send courtesy `REVOKE`
if connected. Future handshakes fail at the trust manager. UI shows a "rotate
these secrets" checklist built from audit entries `kind=share` with that
`device_id` (R-005).

### 8.1 As built in M3.6 (CLI and TUI)

- **Where state lives (SR-090).** This device's Ed25519 identity and certificate are a
  `device-identity` record, and each pinned peer is a `trusted-device` record, both inside the
  encrypted vault (`docs/schemas/records.cddl`); nothing is written to plain files. They are
  internal records: `list`, `search`, the dashboard and sharing skip them.
- **Commands.** `pm devices` lists this device and the pinned peers; `pm devices remove <name|fingerprint>`
  unpins one and prints the rotate checklist. `pm pair --listen [--bind ip]` waits; `pm pair <ip:port>`
  connects. Both show the six-digit code and pin only after a typed `y` (SR-091). `pm share <title>
  --to <device> [--ttl 10m]` and `pm share <title> --browser [--ttl]` show a summary (the browser form
  first prints the Amendment 2 warnings), require a typed `y`, audit `approval`, then open the window
  and print its address or URL and certificate SHA-256 (SR-092). `pm receive <ip:port>` shows the
  sender, its fingerprint, the summary and the expiry and applies the item only after a typed `y`, under
  a fresh id (SR-093). `pm revoke <share-id>` closes a waiting share. New exit code 10 (`NOT_DONE`):
  pairing, sharing or receiving did not complete.
- **Cross-process revoke.** A waiting `pm share` holds the window in memory with its own copies of the
  payload and identity (the vault is closed while it waits) and creates `share-<id>` in the owner-only
  run directory. `pm revoke` deletes that marker; the waiting process polls it every 100 ms and revokes
  when it is missing, so a deleted run directory also revokes (fail closed).
- **Rotate checklist.** The checklist comes from the `shared` list on the `trusted-device` record (item
  ids, oldest first, at most 1 024), recorded when a share window is opened for that device, rather
  than from audit entries: the audit log does not carry item ids. An offer that was never taken still
  appears, which errs on the side of rotating.
- **Lockout scope (SR-203, SR-096).** The lockout is shared by every pm process of the user: its
  failure count and lock end are kept in `pair-lockout` (mode 0600, written to a temporary file and
  moved into place) in the owner-only run directory, read when a pairing starts and written after
  every failure and when the pairing ends, so a new `pm pair --listen` or TUI pairing starts locked
  rather than afresh. A stored lock more than 1 h ahead is cut to 1 h (a clock set back cannot lock
  pairing for longer). Without a run directory (a TUI with no approval host) the lockout is per
  process.
  - *Concurrency.* Pairings can run side by side (on the user's different vaults). Every write is a
    read-merge-write under an exclusive lock (`FileChannel.lock` on `pair-lockout.lock`, plus an
    in-process lock): the stored and the local state are merged by the larger failure count and the
    later lock end, so a pairing that read a clean state before another one locked never writes the
    lock away. A success clears the count only if no other process changed the file since this
    pairing read it; otherwise the other process's failures stay.
  - *Fail closed.* A file that does not parse, is too large, is not a plain file, or is not
    owner-only (any group or other permission bit, or another owner) counts as locked for the full
    hour, as does a lock file that cannot be taken.
  - *Residuals.* Deleting `pair-lockout` resets the lockout; only a process of the same user can do
    that, and such a process can already read the vault file and run pairings itself, so it is not
    defended against. The run directory follows `XDG_RUNTIME_DIR`, so pairings started with
    different values (for example one from a desktop session and one over ssh) count separately;
    each still enforces the per-process lockout of §5 step 6.
- **Removal reaches open windows (SR-205, SR-095).** `pm devices remove` and the TUI's Remove write
  `removed-<public key hex>` (mode 0600) before the vault forgets the device; if that file cannot be
  written nothing is removed. The markers live in an owner-only (0700, not a link) directory next to
  the vault file, `<vault file name>.lan`, named from the vault's real path (links resolved). Its
  place depends only on the vault file, never on `XDG_RUNTIME_DIR` or on the path a process was given,
  so the remover and every sender of that vault agree on it however each was started. Every share
  window, in any process, checks the marker when the device's TLS connection is accepted and again
  just before `SHARE_DATA`; a removed device is refused and the window revokes itself (`REVOKED`), so
  a window opened before the removal releases nothing more. Pairing the same key again deletes the
  marker. A share to a device removed since the list was shown records nothing and opens nothing.
  Residuals: a marker deleted by a process of the same user is not detected (as above); a second
  *hard* link to the vault file in another directory (links are resolved only for symbolic links)
  would have its own marker directory, so the removal message names windows "of this vault".
- **Replay guard in the vault (SR-204, SR-097).** The receiver keeps the ids of shares it applied in
  the sender's `trusted-device` record (`received`, `<id hex>@<expiry>`, at most 1 024, each dropped
  once the longest window, 24 h, has passed) and writes the entry in the same vault save as the item,
  so a replayed share id is refused by any later `pm receive` or TUI receive.
- **Offer and payload agree (SR-208, SR-098).** The receiver applies the payload only if its kind and
  summary (`login: <title>`, `project: <title> (<n> secrets)` and so on) equal the offer the user
  accepted; otherwise nothing is applied. A received login, Wi-Fi or SSH item whose title already
  exists is added beside it under a fresh id (nothing is overwritten); a project whose title exists
  is refused.
- **Bind address.** `--bind` must be an address of a local interface or loopback; the wildcard
  addresses `0.0.0.0` and `::` and addresses of other machines are refused.
- **TUI.** Ctrl+D opens the Devices screen (pair here, pair with address, receive, remove), Ctrl+S the
  Share dialog for the selected item (to a paired device or a browser link, with Approve/Deny). Network
  steps run on worker threads; vault access and questions run on the GUI thread; a question that is
  not answered within 2 minutes counts as no. Questions are queued: only the first is on screen,
  and Yes or No answers only that one, so a pairing code is never confirmed by a Yes given to
  another question; a new step or Remove is refused while a question waits. Locking or quitting stops every LAN step and revokes open
  windows. Audit entries go through the approval host (the broker's audit log in production).

## 9. State machine (responder side)

```
IDLE ─open pairing→ LISTEN_PAIR ─TLS ok→ PAIR_HELLO ─HELLO→ PAIR_WAIT_SAS
PAIR_WAIT_SAS ─user confirms & valid PAIR_SAS_OK→ PAIRED_DONE ─PAIR_DONE→ IDLE(+trust)
any pairing state ─timeout 120 s | invalid msg | bad MAC | user cancels→ IDLE(+lockout counter)

IDLE ─open share→ LISTEN_SHARE ─TLS pinned ok→ SHARE_HELLO ─SHARE_OFFER→ OFFER_SHOWN
OFFER_SHOWN ─user accepts→ ACCEPTED ─SHARE_DATA→ VALIDATING
VALIDATING ─valid→ APPLYING ─save ok→ ACKED ─BYE→ IDLE
VALIDATING|APPLYING ─fail→ ERROR_SENT → IDLE (nothing applied)
any share state ─timeout | invalid | user cancels→ IDLE
```
Every transition has a failure branch to IDLE; the listener socket is closed
on every IDLE entry when no other window is active.

## 10. Threat mapping

TM-30..TM-38, TM-40..TM-42 in `docs/security/threat-model.md`; tests
T-LAN-01..08, T-WEB-01..02, T-FUZZ-LAN.
