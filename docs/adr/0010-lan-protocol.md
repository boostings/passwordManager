# ADR 0010: LAN share protocol — mutual TLS + short authentication string, no PAKE

- Status: Accepted, amended (Amendment 1, M3.1, 2026-10-03)
- Date: 2026-09-10

## Decision
Adopt `docs/protocols/lan-share.md`. Pairing security rests on mutual TLS 1.3
with per-device Ed25519 identities and a 6-digit SAS derived from the TLS
exporter secret and both public keys, confirmed by humans on both screens and
proven with a MAC (never transmitted). Post-pairing trust is key pinning.

Open item for an implementation spike (M3 start): confirm JDK 21 exposes TLS
exporter keying material for `SSLSocket`/`SSLEngine`. If not, the fallback in
§5 step 2 is used and this ADR is amended.

## Alternatives considered
- SPAKE2/CPace/OPAQUE: no audited Java implementation; rejected per R-006.
- QR code carrying the full public key (no SAS): works when a camera is
  available, but terminals do not have one; retained as a future option.
- Bluetooth/WebRTC transports: out of scope for v1.

## Consequences
Users must be physically able to compare two screens (or read digits over a
trusted channel). This is the same model as Signal safety numbers and
Bluetooth numeric comparison.

## CERT rules referenced
MSC00-J, MSC02-J, MSC05-J, IDS11-J, THI04-J, TPS02-J, FIO14-J, ERR03-J, LCK09-J
(no blocking I/O under the vault lock).

## Amendment 1 (M3.1, 2026-10-03): commit-then-reveal SAS, no TLS exporter

**The open item is closed: JDK 21 has no TLS exporter.** Checked on openjdk 21.0.12.1:
`javap javax.net.ssl.ExtendedSSLSession | grep -i export` prints nothing, and no other public JSSE
type offers RFC 8446 §7.5 keying material. The §5 fallback ("transcript hash + an in-tunnel
X25519") is not used either, for the reason below.

**The original construction had a flaw, corrected here.** As first written, the SAS was a function
of values each side contributes without committing to them first (DH shares, or the exporter of
a handshake whose key share the attacker picks). A machine in the middle runs two TLS sessions and
picks its own contribution to each. A 6-digit SAS has 10^6 values, so it can try contributions
offline (about 10^6 key generations, seconds of work) until the digits shown to the two victims
match, and then the humans' comparison succeeds. "The exporter secrets differ" is true but not
enough: they differ in a way the attacker steers. Fixing this needs one side to commit to its
random contribution before seeing the other's. This is the standard SAS-based authentication
(MANA IV / ZRTP / Bluetooth numeric comparison) pattern.

**Adopted construction** (`pm.crypto.Pairing`, normative text in lan-share.md §5):

1. Mutual TLS 1.3 with the candidate certificates, as before. The pin accepts any well-formed
   self-signed Ed25519 certificate during pairing. Each side reads the peer's raw key from the
   authenticated session (`Tls.peerPublicKey`).
2. The initiator draws a 32-byte nonce `n_I` and sends `c_I = SHA-256("pm/pair/commit/v1" ‖ pk_I ‖ n_I)`.
3. The responder draws `n_R` and sends it.
4. The initiator reveals `n_I`. The responder checks that it opens `c_I` under `pk_I`, in constant
   time, and aborts the ceremony (counting a failure) if not.
5. Both derive `sas_key = HKDF-SHA256(ikm = n_I ‖ n_R, salt = "pm/pair/v1", info = "pm/sas/v1" ‖
   min(pk_I, pk_R) ‖ max(pk_I, pk_R), 32)`, ordering the keys by unsigned bytes.
   `SAS = (first 8 bytes of sas_key as an unsigned big-endian integer) mod 10^6`, zero-padded to
   6 digits.
6. After the human comparison, each side sends `HMAC-SHA256(sas_key, "ok" ‖ own pk)` and checks
   the peer's against the peer's key. A reflected MAC fails because the key in it is the wrong one.

Why it holds: in each of its two sessions the attacker either plays the initiator, where it is
bound to `n` before it sees the victim's nonce, or plays the responder, where it must send `n_R`
before it sees the victim's committed `n_I`. Either way the digits each victim sees include a
uniformly random value the attacker could not know when it fixed its own, so both screens match
with probability 10^-6 per attempt. The lockout (§5 step 6) then caps attempts. The public keys
are in `info`, so the SAS also binds both certificate keys. These are the keys TLS authenticated
(each side proved possession in CertificateVerify), so the SAS needs no separate binding to the
TLS session. All inputs except `sas_key` are public, and the nonces are sent inside the tunnel.

Also corrected: the old formula took "the first 20 bits mod 10^6". 20 bits range up to 1 048 575,
so the reduction biased the low values toward twice the probability. 64 bits mod 10^6 has a bias
below 2^-44.

Tests: `PairingTest` checks known answers from an independent Python implementation (hashlib, hmac,
RFC 5869 HKDF). It also checks order independence (property test), key binding, nonce-role
binding, commitments opening only for their own key, reflected confirmations failing, and the
unsigned reduction. The MITM ceremony test (screens differ) belongs to the protocol layer (M3.3).

This amendment needs the external review listed as a user-only item in docs/plans/M2-M7.md before
v1 ships; it is recorded as open in the M3 sign-off.

## Amendment 2 (2026-10-03, M3.5): browser-only receiving

Building §7 showed three problems with the text as first written.

1. **The device certificate cannot serve browsers.** It is Ed25519, and no shipping browser accepts
   an Ed25519 server certificate. Each browser share therefore gets its own throwaway identity,
   `pm.crypto.WebIdentity`: an ECDSA P-256 key and a self-signed certificate. The certificate
   names the listener's IP address (subjectAltName), has `serverAuth` EKU, and is valid from one
   hour before creation until the end of the share window. It is never stored. The browser
   listener asks for no client certificate (`Tls.browserContext`, `Tls.browserParameters`), but it
   keeps TLS 1.3 and the same two AEAD suites.
2. **The CSP in §7 would block the page's own fetch.** `default-src 'none'` also covers `connect-src`.
   The policy is now `default-src 'none'; script-src 'sha256-…'; style-src 'unsafe-inline';
   connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`.
3. **Nonce.** `k_web` encrypts exactly one message, so the nonce is twelve zero bytes. This is the
   same rule as ADR 0005, and the sealing goes through `Aead.sealWithFreshKey`, which consumes the
   key. A random nonce would add nothing.

Further decisions:

- **The ciphertext is fetched once.** `/d/<id>` is served once and only after the page. Then the
  listener closes and frees the port. It also closes at expiry, and `close()` (revocation) also
  cuts off a request already being read. The page `/s/<id>` holds nothing secret and is served
  again until then: a chat app's link preview or a scanner that fetches the path without the
  fragment must not burn the share (the first review build served it once, and a single `curl`
  locked the real recipient out). The `opened` event therefore means "something fetched the page",
  not "the recipient has the key". Anything else gets 404, 405 or 410; only `HTTP/1.0` and
  `HTTP/1.1` request lines are accepted, and after expiry or revocation every request gets 410.
- **Bounded connections.** Connections are served one at a time. Each read waits at most 2 s, the
  request head is limited to 8 KiB, and a watchdog closes any connection still open 5 s after
  accept, so a client that stalls the handshake or sends one byte at a time cannot hold the
  listener open (the first review build had only the per-read timeout, and a trickling client kept
  it open for over a minute past expiry and was then served the ciphertext).
- **No encrypted-package download.** It would give the recipient a file holding ciphertext, and the
  key for it sits in the same URL, so it adds a copy to manage and no protection. The page offers
  Copy instead.
- **The key stays in the browser's history database.** `history.replaceState` removes the fragment
  from the address bar and the session history entry, but Chrome had already written the full URL,
  key included, to its History database (checked with `sqlite3` on a test profile). It can show in
  address-bar suggestions and be synced. No page script can remove it. The key opens only this
  share's ciphertext, which the listener serves once and never after expiry, so the copy is useless
  once the share is delivered or expired. The TUI (M3.6) must tell the sender to keep windows short and
  suggests a private window to the recipient.
- **Residual risk (unchanged from §7 step 5).** A network attacker can answer the first request
  with a page of its own and read the fragment. The recipient's only defence is comparing the
  certificate fingerprint (`WebIdentity.fingerprint()`, the SHA-256 of the certificate as browsers
  display it). This mode is for recipients without the app. The TUI must say so to the sender, and
  paired-device sharing remains the default.

Tests:

- `WebIdentityTest`, and the browser handshake in `TlsTest`.
- `WebShareTest`: key from the fragment opens the ciphertext; a different id fails.
- `WebPageTest`: the CSP hash matches the only script; no storage APIs or markup sinks.
- `WebServerTest`: real loopback TLS. The page is served until the ciphertext is fetched once; the
  port is closed after delivery, at expiry and on close; close cuts off a request in flight; a
  client sending one byte a second is cut off at the deadline while another is served; malformed
  heads and versions are refused.
- `NodePageTest`: runs the real inline script under Node's WebCrypto.

Also checked by hand in headless Chrome 2026-10-03: the page decrypted and rendered under the CSP,
and the listener reported opened, then delivered, then closed. An adversarial review the same day
found the trickling-client, in-flight revocation, page-burning, history and version defects above;
all are fixed or documented here.
