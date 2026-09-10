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
2. TLS 1.3 mutual handshake with candidate certs. Both sides now have
   `pk_I`, `pk_R`, and the TLS exporter secret
   `es = exportKeyingMaterial("EXPORTER-pm-pair-v1", ctx=∅, 32)`.
   (Java: `SSLEngine`/`SSLSocket` exporter via the JDK 21 `ExtendedSSLSession`
   when available; if the JDK build lacks exporter support, the fallback
   binds to the TLS `Finished` messages' transcript hash obtained from the
   session's `getPeerCertificates` + a fresh X25519 ECDH performed inside the
   tunnel — decision deferred to implementation spike, recorded in ADR 0010.)
3. Each side computes `sas_key = HKDF(es, salt=∅, info="pm/sas/v1" ‖ min(pk_I,pk_R) ‖ max(pk_I,pk_R), 32)`
   and `SAS = decimal(first 20 bits of sas_key) mod 1_000_000`, zero-padded to
   6 digits. Both screens display it.
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

Why this is safe without a PAKE: the security rests on the human comparison
of a value derived from the *authenticated TLS session*. An attacker in the
middle terminates two different TLS sessions, so the exporter secrets and the
public keys differ, so the two screens show different digits.

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

## 7. Browser-only receiving (SR-209, SR-210)

1. S generates `k_web` (32 B random) and `share_id`; encrypts the payload with
   AES-256-GCM(k_web, nonce random 12 B, AAD = share_id).
2. S starts an HTTPS listener with its device cert and serves
   `https://<ip>:<port>/s/<share_id>` for the share lifetime, one fetch only.
   Response headers: `Cache-Control: no-store`, `Content-Security-Policy:
   default-src 'none'; script-src 'sha256-<inline>'; style-src 'unsafe-inline'`,
   `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`.
3. The URL shown/QR-encoded is `https://<ip>:<port>/s/<share_id>#<base64url k_web>`.
   The fragment never leaves the browser.
4. The page's inline script fetches `/d/<share_id>` (ciphertext), decrypts
   with WebCrypto using `k_web` from `location.hash`, renders once, wipes
   `location.hash`, offers copy and an encrypted-package download, and clears
   the DOM on a visible countdown or on unload. No storage APIs are used.
5. The recipient sees a browser certificate warning for the self-signed cert;
   the page explains this, and the TUI shows the fingerprint so the recipient
   can compare. Confidentiality does not depend on the recipient's diligence
   here because of `k_web`; integrity of the page itself (a MITM substituting
   a malicious page) is the residual risk and is documented to the sender.

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
