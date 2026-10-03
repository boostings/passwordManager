/**
 * Environment handling (plan.md §13 M2): {@link pm.domain.env.Env} is the only reader of process
 * environment variables (ENV02-J), {@link pm.domain.env.DotEnv} parses {@code .env} files into
 * secret buffers, and {@link pm.domain.env.ProjectEnv} stores named profiles inside a project
 * record.
 */
package pm.domain.env;
