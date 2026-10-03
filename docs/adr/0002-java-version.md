# ADR 0002: Java 21 LTS

- Status: Accepted
- Ratified 2026-10-03 by the M1 team
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

## Implementation note (2026-10-03, checked against the M1 code at ratification)

The Java 21 decision holds: the root `build.gradle.kts` pins
`JavaLanguageVersion.of(21)`, CI installs Temurin 21 with `actions/setup-java`,
no Foojay resolver plugin is applied, and `ModuleBoundaryTest.noSecurityManager`
bans `SecurityManager` and `AccessController`. One difference:

- HKDF. The Consequences name the JDK `KDF` API or an in-house HKDF over
  `javax.crypto.Mac`. Java 21 has no `javax.crypto.KDF`, and
  `pm.crypto.Kdf.hkdfSha256` uses neither option. It uses Bouncy Castle's
  `HKDFBytesGenerator` (`bcprov-jdk18on`), the same dependency that provides
  Argon2id (ADR 0007). Ed25519, X25519, ChaCha20-Poly1305 and AES-GCM still
  come from the JDK.
