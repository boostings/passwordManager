# Security Policy

passwordManager stores every credential a user owns. We treat security reports
as the highest-priority work in the project.

## Reporting a vulnerability

Do **not** open a public issue for a security problem.

- Use GitHub's private vulnerability reporting on this repository
  ("Security" tab → "Report a vulnerability"), or
- email the security owner listed in `CODEOWNERS`.

Include: affected version or commit, platform, steps to reproduce, impact, and
any proof-of-concept. Please do not include real credentials or vault files.

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

In scope: the application, its installers, the browser extension, the native
messaging host, the LAN sharing protocol, and this repository's build pipeline.

Out of scope: attacks requiring a fully compromised operating system or root
access on the user's machine (documented as an accepted limitation in
`docs/security/threat-model.md`).

## Severity scale

- **Critical**: secret disclosure without user approval, vault key recovery,
  remote code execution, bypass of the approval broker.
- **High**: local same-user secret disclosure not already accepted in the threat
  model, authentication bypass in pairing, tamper going undetected.
- **Medium**: information leak of sensitive (non-secret) data, denial of
  service of the local app, weakened but not broken crypto parameters.
- **Low**: hardening gaps, defense-in-depth misses, documentation errors.
