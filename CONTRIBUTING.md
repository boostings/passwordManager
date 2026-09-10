# Contributing

## Non-negotiable: RULES.md

**All Java in this repository must comply with [`RULES.md`](RULES.md)**, the
SEI CERT Oracle Coding Standard for Java digest. This applies to production,
test, and build code, and to code written by humans and by AI agents alike.
Compliance is enforced by CI (`./gradlew check certReport`) and by review. A
CERT violation identified in review is a blocking change request.

Read `RULES.md` and [`docs/security/threat-model.md`](docs/security/threat-model.md)
before your first change. See `plan.md` Part III for the enforcement program and
the exception process. Never add a `@SuppressWarnings("cert:...")` without a
ledger entry in `docs/security/cert-exceptions.md`.

## Workflow

1. Branch from `main`. Direct pushes to `main` are blocked.
2. Any decision touching crypto, storage format, protocols, approvals, or trust
   boundaries needs an ADR in `docs/adr/` **before** code.
3. Keep commits small; every commit compiles and passes tests.
4. Every new external input (file, socket, IPC message, env var, CLI argument)
   ships with a size-bounded parser and a fuzz harness in the same PR.
5. Fill in the PR template: trust boundaries touched, CERT rules considered,
   new inputs and their fuzz harness, secrets handled and how they are cleared,
   threat IDs addressed.
6. Tier 1 modules (`pm-crypto`, `pm-vault`, `pm-storage`, `pm-approval`,
   `pm-sharing`, `pm-browser`) require two approving reviews; everything else
   requires one. `CODEOWNERS` routes this automatically.
7. Run the full gate locally and paste its output in the PR before requesting
   review.

## Project coding rules (superset of RULES.md)

- Secrets live in `SecretBytes`, never `String`, except at documented
  `@SecretBoundary` points.
- No Java native serialization. `ObjectInputStream` is banned.
- No `Runtime.exec(String)`. Only `ProcessBuilder` with a `List<String>`.
- No reflection on project classes; no `setAccessible(true)`.
- No `System.exit()` outside `Main`. No `Thread.stop`, `ThreadGroup`, or
  finalizers.
- All file I/O goes through `pm-storage`; all crypto through `pm-crypto`.
- Log only through the project logger, which redacts and refuses secrets.
- Canonicalize paths before validating them. Treat environment variables and
  config values as untrusted input.

## Never commit

Real credentials, vault files, recovery keys, test secrets, exported `.env`
files, private keys, or anything matching the patterns in `.gitignore`. Sample
data must be obviously fake.

## Commit messages

Imperative subject line under 72 characters. For work executed against
`docs/plans/M0.md`, include the phase number.
