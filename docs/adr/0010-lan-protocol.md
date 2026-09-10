# ADR 0010: LAN share protocol — mutual TLS + short authentication string, no PAKE

- Status: Proposed
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
