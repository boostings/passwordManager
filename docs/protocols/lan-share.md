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
