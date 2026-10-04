package pm.cli;

/**
 * Fixed catalogue of every user-facing string the CLI prints (SR-501, ERR01-J). Nothing else is
 * ever written: no exception message, path, passphrase or secret field.
 */
enum Messages {
    USAGE("usage: pm [--vault <path>] [--] [init | add-login | list | search <query> | tui"
            + " | project add <title> [--dir <path>] | project list"
            + " | env list | env import <file> | env export <file> --plaintext"
            + " | env run [--only A,B] -- <command> [args...]"
            + " | generate [--length N] [--classes lower,upper,digit,symbol] [--exclude-ambiguous]"
            + " | generate --passphrase [--words N] [--separator C]"
            + " | health [--max-age-days N] [--breach]"
            + " | ssh import <file> [--title T] | ssh list | ssh add <item> [--lifetime 1h] [--confirm]"
            + " | ssh remove <item> | ssh remove --all | ssh export <item> <file>]"
            + " (env commands take [--project <title>] [--profile <name>]);"
            + " with no command, pm opens the app"),
    NO_TERMINAL("interactive terminal required"),
    JVM_OPTIONS_IN_ENVIRONMENT("JAVA_TOOL_OPTIONS, _JAVA_OPTIONS or JDK_JAVA_OPTIONS is set;"
            + " pm does not run with JVM options from the environment. Unset them and run pm again"),
    UNKNOWN_COMMAND("unknown command"),
    UNKNOWN_OPTION("unknown option"),
    WRONG_ARG_COUNT("wrong number of arguments for this command"),
    MISSING_VAULT_PATH("--vault needs a path"),
    DUPLICATE_VAULT_OPTION("--vault given more than once"),
    EMPTY_VAULT_PATH("vault path is empty"),
    INVALID_VAULT_PATH("vault path is not valid"),
    VAULT_PATH_NOT_FILE("vault path must name a file, not a directory"),
    VAULT_PATH_TILDE("'~' is not expanded in --vault; give the full path"),
    NO_HOME_DIR("cannot determine the home directory; pass --vault <path>"),
    INPUT_CLOSED("input closed"),
    EMPTY_PASSPHRASE("passphrase must not be empty"),
    EMPTY_PASSWORD("password must not be empty"),
    MALFORMED_SECRET("input contains malformed characters"),
    PASSPHRASE_MISMATCH("passphrases do not match; no vault was created"),
    INVALID_TEXT("input contains control or invisible formatting characters"),
    EMPTY_TITLE("title must not be empty"),
    EMPTY_QUERY("search query must not be empty"),
    INVALID_RECORD("record fields are out of bounds"),
    BAD_VARIABLE_NAME("variable names use A-Z, a-z, 0-9 and _, and do not start with a digit"),
    RUN_NEEDS_COMMAND("give the command after --, e.g. pm env run -- npm start"),
    EMPTY_PROFILE("this profile has no variables; import a .env file first"),
    NO_SUCH_VARIABLE("a variable named with --only is not in this profile"),
    BAD_PROFILE("profile names use a-z, 0-9, - and _, at most 32 characters"),
    PROJECT_EXISTS("a project with this title or directory already exists"),
    NO_SUCH_PROJECT("no project with this title"),
    NO_PROJECT_HERE("no project registered for this directory; run 'pm project add <title>' or pass --project"),
    NOT_A_DIRECTORY("project directory does not exist or is not a directory"),
    ENV_FILE_UNREADABLE(".env file is missing, unreadable or larger than 1 MiB"),
    EXPORT_NEEDS_PLAINTEXT("export writes secrets to disk in plain text; add --plaintext to confirm"),
    EXPORT_EXISTS("the export file already exists; pm never overwrites it"),
    EXPORT_UNREPRESENTABLE("a value holds control characters a .env file cannot carry; nothing was exported"),
    EXPORT_FAILED("the export file could not be written"),
    AUDIT_UNAVAILABLE("the audit log could not be written, so nothing was exported"),

    // ---- M4.4: generate, health, ssh ----
    DUPLICATE_OPTION("an option was given more than once"),
    GENERATE_MIXED_OPTIONS("--passphrase takes --words and --separator; --length, --classes and"
            + " --exclude-ambiguous are for passwords"),
    BAD_GENERATE_POLICY("password length is 4 to 1024 and at least the number of classes; classes are"
            + " lower, upper, digit, symbol; passphrases have 3 to 64 words and a one-character"
            + " printable separator that is not a lowercase letter"),
    GENERATED_ENTROPY("entropy (bits): "),
    BAD_MAX_AGE("--max-age-days takes a whole number of days, at least 1"),
    HEALTH_CHECKED("passwords checked: "),
    HEALTH_CLEAN("no weak, reused or old passwords"),
    HEALTH_WEAK("weak: "),
    HEALTH_REUSED("reused (groups sharing one password): "),
    HEALTH_OLD("not changed in more than "),
    BREACH_NOTICE("--breach looks each password up in the Pwned Passwords range API"
            + " (api.pwnedpasswords.com, HTTPS). Only the first 5 hex characters of each password's"
            + " SHA-1 hash leave this machine; the password, the full hash and record titles never do."),
    BREACH_COUNT("hash prefixes to send, one per distinct password: "),
    BREACH_CONFIRM("Type y and press Enter to send them: "),
    BREACH_SKIPPED("breach check not confirmed; nothing was sent"),
    BREACH_NOTHING("breach check: no passwords to look up; nothing was sent"),
    BREACH_FOUND("found in known breaches: "),
    BREACH_SUMMARY("breach check: distinct passwords found in known breaches: "),
    BREACH_TIMEOUT("breach check timed out; the offline report above is complete"),
    BREACH_MALFORMED("the breach service sent an invalid reply; nothing was concluded from it"),
    BREACH_HTTP_STATUS("the breach service answered with an error status"),
    BREACH_NETWORK("could not reach the breach service; check the network connection"),
    BREACH_FAILED("breach check failed"),
    SSH_TIMEOUT("ssh-agent did not answer within 10 seconds; the connection was dropped"),
    SSH_NO_AGENT("no ssh-agent found: SSH_AUTH_SOCK is unset or nothing listens there; start ssh-agent first"),
    SSH_UNSAFE_SOCKET("the ssh-agent socket failed its owner, permission or link checks; nothing was sent"),
    SSH_AGENT_REFUSED("ssh-agent refused the request"),
    SSH_BAD_REPLY("ssh-agent sent an invalid reply"),
    SSH_IO("ssh-agent or key file input/output failed"),
    SSH_MALFORMED_KEY("not a valid unencrypted OpenSSH private key"),
    SSH_ENCRYPTED_KEY("the key is passphrase-protected; remove the passphrase with 'ssh-keygen -p'"
            + " on a copy, import that, then delete the copy"),
    SSH_UNSUPPORTED_KEY("only Ed25519 and ECDSA P-256 keys are supported"),
    SSH_KEY_FILE_UNREADABLE("key file is missing, a link, not a regular file, unreadable or larger than 64 KiB"),
    SSH_KEY_FILE_SHARED("warning: the key file can be read by other users; it may already have been copied"),
    SSH_DELETE_ORIGINAL("the key is now in the vault; delete the plaintext original (for example with 'rm')"
            + " once you have checked it works"),
    SSH_EXPORT_NO_DIR("the export file's folder does not exist; nothing was written"),
    SSH_KEY_EXISTS("an SSH key with this fingerprint is already in the vault"),
    SSH_NO_SUCH_KEY("no SSH key item with this title or id"),
    SSH_AMBIGUOUS_KEY("several SSH key items have this title; use the id from 'pm list'"),
    SSH_BAD_LIFETIME("--lifetime is a number of seconds, or a number with s, m, h or d, up to 2147483647 seconds"),
    SSH_NOT_IN_AGENT("ssh-agent does not hold this key"),
    SSH_EXPORT_EXISTS("the export file already exists; pm never overwrites it"),
    SSH_UNSAFE_TARGET("the export file cannot be made owner-only (0600) there; nothing was written"),
    SSH_IMPORTED("ssh key imported: "),
    SSH_LIST_HEADER("fingerprint  type  comment"),
    SSH_AGENT_EMPTY("(ssh-agent holds no keys)"),
    SSH_ADDED("added to ssh-agent: "),
    SSH_REMOVED("removed from ssh-agent: "),
    SSH_REMOVED_ALL("all keys removed from ssh-agent"),
    SSH_EXPORTED("private key exported; the file is owner-only (0600). It is a plaintext key: delete it"
            + " when it is no longer needed"),

    PROMPT_PASSPHRASE("Passphrase: "),
    PROMPT_NEW_PASSPHRASE("New passphrase: "),
    PROMPT_REPEAT_PASSPHRASE("Repeat passphrase: "),
    PROMPT_TITLE("Title: "),
    PROMPT_USERNAME("Username: "),
    PROMPT_LOGIN_PASSWORD("Password: "),
    PROMPT_URLS("URLs (comma-separated): "),
    PROMPT_TAGS("Tags (comma-separated): "),
    PROMPT_OPEN_APP("Press Enter to open pm: "),

    FIRST_RUN("no vault yet; create one to get started"),
    VAULT_CREATED("vault created"),
    RECOVERY_KEY_NOTICE("recovery key (shown once; write it down and store it offline):"),
    LOGIN_ADDED("login added: "),
    LIST_HEADER("id  type  title  updated"),
    PROJECT_ADDED("project added: "),
    RUN_SUMMARY("no pm window is running, so approve here. Inject "),
    RUN_VARIABLES("variables: "),
    RUN_COMMAND("into exactly this command (one argument per line):"),
    RUN_CONFIRM("Type y and press Enter to run it: "),
    RUN_DENIED("not approved, nothing ran: "),
    BROKER_UNREACHABLE("the pm window's approval service did not answer: "),
    PROJECT_HEADER("title  directory  profiles"),
    ENV_HEADER("variables in "),
    ENV_IMPORTED("variables imported: "),
    ENV_EXPORTED("variables exported (file is 0600): "),
    ENV_REJECTED(".env file rejected: "),
    WARN_GIT_NOT_IGNORED("warning: this file is inside a git repository and no .gitignore rule covers it;"
            + " it could be committed"),
    WARN_PLAINTEXT_LEFT("warning: the plaintext .env file is still on disk; delete it once the import is checked"),

    ERR_WRONG_CREDENTIAL("wrong passphrase or recovery key"),
    ERR_CORRUPT("vault file is corrupt or has been tampered with"),
    ERR_UNSUPPORTED_VERSION("vault format version is not supported"),
    ERR_ALREADY_EXISTS("a vault already exists at this path"),
    ERR_LOCKED("vault is in use by another process"),
    ERR_STORAGE("vault storage error"),
    ERR_NOT_FOUND("no vault at this path; run 'pm init' first"),
    ERR_INSUFFICIENT_MEMORY("this vault needs more memory than Java was given;"
            + " raise the heap limit (for example -Xmx2g) and try again"),
    ERR_TERMINAL("terminal error"),
    ERR_RECOVERY_NOT_SHOWN("the vault was created but its recovery key could not be shown;"
            + " delete the new vault file and run 'pm init' again"),
    ERR_INTERNAL("internal error");

    private final String catalogueText;

    Messages(String catalogueText) {
        this.catalogueText = catalogueText;
    }

    /** The fixed text for this entry. */
    String text() {
        return catalogueText;
    }
}
