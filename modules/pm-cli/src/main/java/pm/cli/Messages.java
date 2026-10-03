package pm.cli;

/**
 * Fixed catalogue of every user-facing string the CLI prints (SR-501, ERR01-J). Nothing else is
 * ever written: no exception message, path, passphrase or secret field.
 */
enum Messages {
    USAGE("usage: pm [--vault <path>] [--] [init | add-login | list | search <query> | tui"
            + " | project add <title> [--dir <path>] | project list"
            + " | env list | env import <file> | env export <file> --plaintext]"
            + " (env commands take [--project <title>] [--profile <name>]);"
            + " with no command, pm opens the app"),
    NO_TERMINAL("interactive terminal required"),
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
