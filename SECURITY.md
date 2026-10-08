# Security Policy

passwordManager stores every credential a user owns. We treat security reports
as the highest-priority work in the project.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes: security fixes |
| earlier (0.x, milestone builds) | No: upgrade to 1.0.x |

## Reporting a vulnerability

Do **not** put the details of a security problem in a public issue, pull
request or discussion.

- Use GitHub's private vulnerability reporting on this repository
  ("Security" tab → "Report a vulnerability").
- If that button is not there, open a public issue titled only
  "Security contact request", with no details. The security owner
  (`@boostings`, see `CODEOWNERS`) replies with a private channel.

Include: affected version or commit, platform, steps to reproduce, impact, and
any proof-of-concept. Please do not include real credentials or vault files.
How reports are handled, from triage to the advisory, is in
[docs/security/disclosure-policy.md](docs/security/disclosure-policy.md).

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement | within 48 hours |
| Triage and severity assignment | within 7 days |
| Fix for Critical | within 24 hours of triage |
| Fix for High | within 7 days of triage |
| Fix for Medium | next milestone release |
| Fix for Low | backlog, tracked in the risk register |

We coordinate disclosure with the reporter and publish a GitHub Security
Advisory (requesting a CVE where applicable) when a fix ships. Reporters are
credited unless they prefer otherwise.

## Safe harbor

Good-faith research that respects user privacy, does not access or destroy
other people's data, and follows this policy will not be pursued legally by the
project.

## Scope

In scope: the application (CLI and full-screen app), the vault and backup
formats, the approval broker and audit log, the ssh-agent client, the LAN
pairing and sharing protocol and its one-time browser page, the browser
extension and native messaging host, the release archives and installers, and
this repository's build pipeline.

Out of scope:

- Attacks that need a fully compromised operating system, or root or
  administrator access, on the user's machine (R-001 in
  `docs/security/risk-register.md`).
- Limitations already accepted and documented: same-user processes reaching
  the local relay socket (R-011), a recipient keeping a copy of a shared
  secret (R-005), Java's best-effort memory wiping (R-003), and the residual
  risks listed in each milestone sign-off
  (`docs/security/milestone-signoff.md`). A way to make one of them worse than
  documented is in scope.
- Passkeys and WebAuthn: v1 does not create or use passkeys (ADR 0016, v1
  addendum). The M6 passkey code in the tree is unreachable from the shipped
  program. A path that reaches it from a v1 build is in scope.
- Unsigned installers: v1 releases are not code-signed or notarized; verify
  them with `SHA256SUMS` (`docs/release/packaging.md`).

## Severity scale

- **Critical**: secret disclosure without user approval, vault key recovery,
  remote code execution, bypass of the approval broker.
- **High**: local same-user secret disclosure not already accepted in the threat
  model, authentication bypass in pairing, tamper going undetected.
- **Medium**: information leak of sensitive (non-secret) data, denial of
  service of the local app, weakened but not broken crypto parameters.
- **Low**: hardening gaps, defense-in-depth misses, documentation errors.
