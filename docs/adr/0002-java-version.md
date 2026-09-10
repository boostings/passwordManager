# ADR 0002: Java 21 LTS

- Status: Proposed
- Date: 2026-09-10
- Deciders: project team

## Context
`plan.md` defers the Java LTS choice to implementation start. The choice affects
JPMS, `jpackage`, crypto API availability (Ed25519, ChaCha20-Poly1305, HKDF),
and toolchain support in Error Prone, PMD, SpotBugs, and Lanterna.

## Decision
Target **Java 21 LTS** for development, CI, and release. Pin via Gradle
toolchains (`languageVersion = 21`) with the Foojay resolver disabled in CI in
favor of a pre-installed, checksum-verified Temurin 21 distribution.
Re-evaluate at M7 whether to move to the next LTS.

## Alternatives considered
- Java 17: supported, but lacks Sequenced collections, pattern matching for
  switch (useful for strict message dispatch), and has an older TLS stack.
- Java 25: newer, but static-analysis tool support lags at the time of writing
  and the Security Manager removal timeline needs no action for us either way.

## Consequences
- `SecurityManager` is deprecated for removal and disabled; CERT rules that
  depend on it are Not applicable (superseded) per `plan.md` Part III.
- Ed25519, X25519, ChaCha20-Poly1305, AES-GCM, HKDF (via `KDF` API where
  available, else a reviewed in-house HKDF over `javax.crypto.Mac` — the one
  permitted "construction" because it is RFC 5869 and trivially testable
  against vectors) are all in the JDK.

## Security considerations
A single pinned JDK removes "works on my JDK" divergence in crypto behavior and
lets the reproducible build gate be meaningful.

## CERT rules referenced
MET02-J (avoid deprecated APIs: no SecurityManager), ENV04-J (bytecode
verification stays on; no `-Xverify:none`).
