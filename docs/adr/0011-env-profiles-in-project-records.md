# ADR 0011: Environment profiles live inside the project record

- Status: Accepted
- Date: 2026-10-03

## Decision
A project's environment profiles (`dev`, `prod`, ...) are stored in the existing
`ProjectRecord.variables` map, keyed `<profile>/<NAME>`. A key without `/` belongs to the
`default` profile, so M1 vaults read unchanged. Profile names match `[a-z0-9][a-z0-9_-]{0,31}`;
variable names match `[A-Za-z_][A-Za-z0-9_]*` (at most 256 characters). `pm.domain.env.ProjectEnv`
is the only code that builds or splits these keys.

`.env` files are parsed by `pm.domain.env.DotEnv`, a strict byte-level parser: values go
straight into `SecretBytes` and never become a `String` (ADR 0008). Errors carry a code and a
line number only.

Environment variables of the pm process itself are read only through `pm.domain.env.Env`
(ENV02-J), which allows a fixed list of variables and treats a malformed value as unset.

## Alternatives considered
- A new `profiles` map in the record schema: needs a format version bump and a migration in M2
  for no security gain; revisit with the M7 migration framework if profiles need metadata.
- One project record per profile: splits a project's identity and its path registration.

## Consequences
The per-record limits (1,024 variables, 64 KiB per value) apply across all profiles of a
project together.

## CERT rules referenced
ENV02-J, IDS00-J (strict input validation), MSC03-J, FIO13-J.
