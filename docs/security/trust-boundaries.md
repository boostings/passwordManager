# Trust Boundaries

Each boundary lists: peer, data crossing, direction, what authenticates the peer,
and behavior on failure. Boundary IDs are referenced by the threat model
(`TB-n`).

| ID | Boundary | Peer | Data crossing | Authenticates peer by | On failure |
| --- | --- | --- | --- | --- | --- |
| TB-1 | User ↔ TUI | Human at the terminal | Passphrase in, masked secrets out, approvals | Possession of passphrase / unlock slot | Vault stays locked; generic error |
| TB-2 | TUI ↔ application services | In-process | `SecretBytes` handles, commands | Same process (JPMS module boundary) | N/A (compile-time) |
| TB-3 | Application ↔ `pm-crypto` | In-process, Tier 1 | Keys, plaintext, ciphertext | Module boundary; only caller of JCA | Exceptions with codes, no material |
| TB-4 | Application ↔ filesystem (`pm-storage`) | OS filesystem | Encrypted vault, backups, audit log, config | Owner-only permissions; canonical paths | Refuse to open; suggest backup |
| TB-5 | Approval broker ↔ requesting process | Local process (`env run` child, agent, CLI) | Approval request, injected env vars | Peer UID (Unix socket creds) or user SID (named pipe DACL) + session token; broker is parent of `env run` | Deny, log, no secret released |
| TB-6 | App ↔ OS keychain | Keychain daemon / DPAPI / Secret Service | Slot wrapping key | OS user session; macOS code-signing requirement | Slot unavailable; other slots remain |
| TB-7 | App ↔ hardware key | FIDO2 authenticator over CTAP | hmac-secret / PRF output | User presence + PIN; credential ID stored in vault | Slot unavailable; fallback listed |
| TB-8 | App ↔ LAN peer | Another paired install | Pairing handshake, encrypted share payload | Mutual TLS 1.3 with pinned Ed25519-derived certs; SAS at pairing | Close session; nothing applied |
| TB-9 | App ↔ browser share page | Browser on recipient device | Ciphertext + page; key in URL fragment only | Fragment key possession; TLS fingerprint shown | Page expires; no secret served in clear |
| TB-10 | App ↔ browser extension | Extension via native messaging host | Lookup, autofill, save, generate requests | Extension ID allowlist in host manifest; message schema; TUI approval | Reject message; extension shows failure |
| TB-11 | Browser extension ↔ web page | Arbitrary origin | Autofill values into DOM | Exact origin match against record URLs | No fill; user notified |
| TB-12 | App ↔ ssh-agent | Local agent socket | Key add/remove, signing requests | Socket path owned by user; keys only via `pm-crypto` | Feature disabled; explain |
| TB-13 | App ↔ breach service | Remote HTTPS API | k-anonymity hash prefix (5 hex chars) | TLS with system trust store; no auth | Check unavailable; nothing else affected |
| TB-14 | App ↔ update server | Remote HTTPS | Signed package + manifest | Pinned signing public key | Refuse update; remain on current version |
| TB-15 | Import/restore ↔ files | User-supplied `.env`, backup archive | Untrusted bytes | None (untrusted) | Reject on schema/size/path failure |

Untrusted by default: everything on the far side of TB-5, TB-8, TB-9, TB-10,
TB-11, TB-13, TB-14, TB-15, plus all environment variables and config files
(`ENV02-J`).
