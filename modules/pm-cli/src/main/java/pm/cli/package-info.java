/**
 * Command-line front end (plan.md §13 M1): {@code init | add-login | list | search <q> | tui}.
 * User-facing text comes only from {@link pm.cli.Messages} (SR-501); passphrases stay in
 * {@code SecretChars}/{@code SecretBytes} and never reach output (SR-500, ADR 0008).
 */
package pm.cli;
