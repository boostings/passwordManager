package pm.cli;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The command table (M7.7): every command and subcommand pm accepts, its area and line in the
 * usage, and its help text. {@link Cli} resolves the words typed against this table before it
 * runs anything and then dispatches with an exhaustive switch over it, so a command that is not
 * listed here cannot run and every entry here is dispatched. Like every other output the help is
 * a fixed catalogue (SR-501); no line is wider than {@link #MAX_COLUMNS}.
 */
enum Command {
    HELP(Area.HELP, "help", null, Command.OWN_ARGS, "help [<command>]", "explain a command; also pm <command> --help",
            """
            usage: pm help [<command> [<subcommand>]]

            Explains a command; pm <command> --help does the same. With no command it
            prints the list of commands."""),

    INIT(Area.VAULT, "init", null, 0, "init", "create a vault; shows its recovery key once",
            """
            usage: pm init

            Creates a new vault at the vault path (--vault, or the default for this
            system). Asks for a new passphrase twice, then prints the recovery key
            once: write it down and keep it offline. It is the only way back in if
            the passphrase is lost."""),
    TUI(Area.VAULT, "tui", null, 0, "tui", "open the full-screen app",
            """
            usage: pm tui

            Opens the full-screen app on an existing vault. Bare pm does the same,
            and creates the vault first when there is none."""),

    PASSPHRASE(Area.VAULT, "passphrase", null, Command.OWN_ARGS, "passphrase [--recovery]",
            "change the master passphrase",
            """
            usage: pm passphrase [--recovery]

            Changes the master passphrase. Asks for the current passphrase (with
            --recovery, the recovery key instead), then for the new one twice. The
            recovery key and every item stay as they are. Earlier .bak files and
            backups still open with the old passphrase: make a new backup, then
            delete them if the old passphrase may be known."""),
    RECOVER(Area.VAULT, "recover", null, Command.OWN_ARGS, "recover", "set a new passphrase with the recovery key",
            """
            usage: pm recover

            For a lost passphrase: asks for the recovery key, then for a new
            passphrase twice. The same as pm passphrase --recovery; the recovery key
            stays valid."""),

    ADD_LOGIN(Area.RECORDS, "add-login", null, 0, "add-login", "add a login; prompts for each field",
            """
            usage: pm add-login

            Adds a login. Prompts for the title, username, password (not shown while
            you type), URLs and tags, and prints the new item's id."""),
    WIFI_ADD(Area.RECORDS, "wifi", "add", Command.OWN_ARGS, "wifi add <ssid>", "add a Wi-Fi network; prompts for its password",
            """
            usage: pm wifi add <ssid> [--title <title>] [--security <type>] [--hidden]
                               [--notes <text>]

            Adds a Wi-Fi network. Its password is asked for twice and is not shown
            while you type; an OPEN network has none.

              --title <title>     title in pm (default: the SSID)
              --security <type>   WPA2 (default), WPA3, WEP or OPEN
              --hidden            the network does not broadcast its SSID
              --notes <text>      a note"""),
    LIST(Area.RECORDS, "list", null, 0, "list", "list items: id, type, title, last change",
            """
            usage: pm list

            Lists every item as id, type, title and time of last change. Secrets are
            never printed."""),
    SEARCH(Area.RECORDS, "search", null, 1, "search <query>", "list the items whose details match",
            """
            usage: pm search <query>

            Lists the items whose title or other non-secret fields contain the query,
            in the same form as pm list."""),
    SHOW(Area.RECORDS, "show", null, Command.OWN_ARGS, "show <item> [--reveal]", "show an item; --reveal prints its password",
            """
            usage: pm show <item> [--reveal]

            Shows the fields of one item. Secret fields are masked unless --reveal is
            given.

              <item>     the item's title, or its id from pm list
              --reveal   print the password of a login or of a Wi-Fi network. This is
                         the only command that prints a stored secret. SSH private
                         keys and project variables are never printed: they leave the
                         vault through pm ssh add or pm ssh export, and through
                         pm env run or pm env export."""),
    EDIT(Area.RECORDS, "edit", null, Command.OWN_ARGS, "edit <item> <options>", "change a login or a Wi-Fi network",
            """
            usage: pm edit <item> [--title <title>] [--username <name>] [--urls <list>]
                              [--tags <list>] [--ssid <ssid>] [--security <type>]
                              [--hidden | --not-hidden] [--notes <text>]
                              [--password | --generate [<generate options>]]

            Changes a login or a Wi-Fi network; fields not named keep their value. An
            empty value ("") clears a username, URLs, tags or notes.

              --title <title>     rename the item
              --username <name>   login: the account name
              --urls <list>       login: comma-separated URLs; replaces the old ones
              --tags <list>       login: comma-separated tags; replaces the old ones
              --ssid <ssid>       Wi-Fi: the network name
              --security <type>   Wi-Fi: WPA2, WPA3, WEP or OPEN (OPEN has no password)
              --hidden            Wi-Fi: the network does not broadcast its SSID
              --not-hidden        Wi-Fi: the network broadcasts its SSID
              --notes <text>      a note
              --password          ask for a new password twice (never on the command
                                  line)
              --generate          a new random password made as pm generate makes it,
                                  with its options (--length, --classes,
                                  --exclude-ambiguous; or --passphrase, --words,
                                  --separator). It is not printed: see it with
                                  pm show <item> --reveal"""),
    RM(Area.RECORDS, "rm", null, Command.OWN_ARGS, "rm <item> [--yes]", "remove an item",
            """
            usage: pm rm <item> [--yes]

            Removes an item from the vault after you type y, or at once with --yes.
            Removing an SSH key does not take it out of a running ssh-agent; run
            pm ssh remove <item> first."""),

    GENERATE(Area.TOOLS, "generate", null, Command.OWN_ARGS, "generate [<options>]", "print a random password or passphrase",
            """
            usage: pm generate [--length <n>] [--classes <list>] [--exclude-ambiguous]
                   pm generate --passphrase [--words <n>] [--separator <c>]

            Prints one random password or passphrase on stdout and its entropy on
            stderr, so pm generate | pbcopy carries only the secret. Needs no vault.

              --length <n>          4 to 1024 characters (default 20)
              --classes <list>      any of lower,upper,digit,symbol (default: all)
              --exclude-ambiguous   leave out look-alikes such as 0, O, 1, l and I
              --passphrase          words instead of characters
              --words <n>           3 to 64 words (default 6)
              --separator <c>       one printable character between words (default -)"""),
    HEALTH(Area.TOOLS, "health", null, Command.OWN_ARGS, "health [<options>]", "report weak, reused and old passwords",
            """
            usage: pm health [--max-age-days <n>] [--breach]

            Reports weak, reused and old passwords by title, offline.

              --max-age-days <n>   a password is old after n days (default 365)
              --breach             also look the passwords up in the Pwned Passwords
                                   range API after you type y; only the first 5 hex
                                   characters of each password's SHA-1 hash are sent"""),

    SSH_IMPORT(Area.SSH, "ssh", "import", Command.OWN_ARGS, "ssh import <file>", "store an OpenSSH private key",
            """
            usage: pm ssh import <file> [--title <title>]

            Stores an unencrypted OpenSSH Ed25519 or ECDSA P-256 private key as an SSH
            key item. Delete the plaintext file once the key works from pm.

              --title <title>   title in pm (default: the key's comment)"""),
    SSH_LIST(Area.SSH, "ssh", "list", Command.OWN_ARGS, "ssh list", "list the keys ssh-agent holds",
            """
            usage: pm ssh list

            Lists the keys your ssh-agent (SSH_AUTH_SOCK) holds: fingerprint, type and
            comment."""),
    SSH_ADD(Area.SSH, "ssh", "add", Command.OWN_ARGS, "ssh add <item>", "load a stored key into ssh-agent",
            """
            usage: pm ssh add <item> [--lifetime <time>] [--confirm]

            Loads a stored SSH key into ssh-agent. The release is written to the audit
            log first.

              --lifetime <time>   seconds, or a number with s, m, h or d (as ssh-add -t)
              --confirm           the agent asks before each use (as ssh-add -c)"""),
    SSH_REMOVE(Area.SSH, "ssh", "remove", Command.OWN_ARGS, "ssh remove <item> | --all", "take keys out of ssh-agent",
            """
            usage: pm ssh remove <item>
                   pm ssh remove --all

            Takes a stored key, or every key, out of ssh-agent. The vault is not
            changed."""),
    SSH_EXPORT(Area.SSH, "ssh", "export", Command.OWN_ARGS, "ssh export <item> <file>", "write a stored key to an owner-only file",
            """
            usage: pm ssh export <item> <file>

            Writes a stored key to a new owner-only (0600) file; never overwrites one.
            The release is written to the audit log first. The file holds the key in
            plain text: delete it when it is no longer needed."""),

    PROJECT_ADD(Area.ENV, "project", "add", Command.OWN_ARGS, "project add <title>", "register a directory as a project",
            """
            usage: pm project add <title> [--dir <path>]

            Registers a directory (default: the current one) as a project, so the
            pm env commands run there find it."""),
    PROJECT_LIST(Area.ENV, "project", "list", Command.OWN_ARGS, "project list", "list projects and their profiles",
            """
            usage: pm project list

            Lists the projects: title, directory and profiles."""),
    ENV_LIST(Area.ENV, "env", "list", Command.OWN_ARGS, "env list", "list the variable names of a profile",
            """
            usage: pm env list [--project <title>] [--profile <name>]

            Lists the variable names of a profile. Values are never printed.
            """ + Command.ENV_OPTIONS),
    ENV_IMPORT(Area.ENV, "env", "import", Command.OWN_ARGS, "env import <file>", "import a .env file into a profile",
            """
            usage: pm env import <file> [--project <title>] [--profile <name>]

            Imports a .env file into a profile. Delete the plaintext file once the
            import is checked.
            """ + Command.ENV_OPTIONS),
    ENV_EXPORT(Area.ENV, "env", "export", Command.OWN_ARGS, "env export <file>", "write a profile to a plaintext .env file",
            """
            usage: pm env export <file> --plaintext [--project <title>]
                                 [--profile <name>]

            Writes a profile to a new owner-only .env file; never overwrites one.
            --plaintext confirms that the values are written unencrypted.
            """ + Command.ENV_OPTIONS),
    ENV_RUN(Area.ENV, "env", "run", Command.OWN_ARGS, "env run -- <command>", "run a command with a profile's variables",
            """
            usage: pm env run [--only <names>] [--project <title>] [--profile <name>]
                              -- <command> [<args>...]

            Runs a command with the profile's variables in its environment, once it
            is approved: in the open pm window if one runs, otherwise here by typing
            y. Nothing is written to disk.

              --only <names>      comma-separated variable names (default: all)
            """ + Command.ENV_OPTIONS),

    DEVICES(Area.DEVICES, "devices", null, Command.OWN_ARGS, "devices", "list paired devices",
            """
            usage: pm devices

            Shows this device's name and fingerprint and lists the paired devices."""),
    DEVICES_REMOVE(Area.DEVICES, "devices", "remove", Command.OWN_ARGS, "devices remove <device>", "unpair a device",
            """
            usage: pm devices remove <name|fingerprint>

            Unpairs a device and lists the items that were offered to it, so you can
            change those secrets."""),
    PAIR(Area.DEVICES, "pair", null, Command.OWN_ARGS, "pair --listen | <ip:port>", "pair with a device on this network",
            """
            usage: pm pair --listen [--bind <ip>] [--name <name>]
                   pm pair <ip:port> [--name <name>]

            Pairs with another device on the local network. One side listens, the
            other connects to the address it shows; then both screens show a code to
            compare.

              --bind <ip>     listen on this address of this machine
              --name <name>   this device's name as the other side sees it"""),
    SHARE(Area.DEVICES, "share", null, Command.OWN_ARGS, "share <title> --to <device>", "offer an item to a device (or --browser)",
            """
            usage: pm share <title> --to <device> [--ttl <time>] [--bind <ip>]
                   pm share <title> --browser [--ttl <time>] [--bind <ip>]

            Offers one item, after you type y, to a paired device or to a browser
            through a one-time link. The window closes after one delivery or when
            its time is up.

              --ttl <time>   1s to 24h, e.g. 10m (default 10m)
              --bind <ip>    listen on this address of this machine"""),
    RECEIVE(Area.DEVICES, "receive", null, Command.OWN_ARGS, "receive <ip:port>", "accept an item another device offers",
            """
            usage: pm receive <ip:port>

            Accepts the item a paired device is sharing, after you type y."""),
    REVOKE(Area.DEVICES, "revoke", null, Command.OWN_ARGS, "revoke <share-id>", "close an open share window",
            """
            usage: pm revoke <share-id>

            Closes a share window this machine has open; nothing more is sent."""),

    BROWSER_INSTALL(Area.BROWSER, "browser", "install", Command.OWN_ARGS, "browser install",
            "let the pm browser extension reach pm",
            """
            usage: pm browser install [--browser <name>] [--extension-id <id>]

            Registers pm as the native messaging host of the pm extension for this
            user in Chrome, Chromium, Edge or Brave, and allows that extension. Works
            with the default vault only. On Windows it prints the steps to do by hand.
            Every request from the extension still needs your yes in the open pm
            window.

              --browser <name>      chrome, chromium, edge, brave or all (default)
              --extension-id <id>   the extension's ID from chrome://extensions;
                                    needed unless exactly one is allowed already"""),
    BROWSER_UNINSTALL(Area.BROWSER, "browser", "uninstall", Command.OWN_ARGS, "browser uninstall",
            "stop browser extensions reaching pm",
            """
            usage: pm browser uninstall [--browser <name>] [--extension-id <id>]

            Removes pm's native messaging manifest from the named browsers (default:
            all), or with --extension-id takes only that extension off them. An
            extension that no manifest allows any more is taken off the allowlist."""),
    BROWSER_STATUS(Area.BROWSER, "browser", "status", Command.OWN_ARGS, "browser status",
            "show which browsers can reach pm",
            """
            usage: pm browser status [--browser <name>]

            Shows, for each browser, whether pm's manifest is installed and which
            extensions it allows, then the extensions on pm's allowlist."""),

    BACKUP_CREATE(Area.BACKUP, "backup", "create", Command.OWN_ARGS, "backup create <folder>", "write an encrypted backup into a folder",
            """
            usage: pm backup create <folder> [--keep <n>]

            Writes an encrypted backup of the vault as last saved into a folder,
            named pm-backup-<time>-<n>.pmbackup, then deletes the oldest backups
            there until <n> remain. Other files in the folder are never touched. A
            missing folder is created owner-only.

              --keep <n>   how many backups to keep, 1 to 999 (default 10)"""),
    BACKUP_VERIFY(Area.BACKUP, "backup", "verify", Command.OWN_ARGS, "backup verify <file>", "check a backup; writes nothing",
            """
            usage: pm backup verify <file>

            Checks a backup with the passphrase the vault had when the backup was
            made: it must be intact, authentic and fully readable. Writes nothing."""),
    RESTORE(Area.BACKUP, "restore", null, Command.OWN_ARGS, "restore <file>", "restore the vault from a verified backup",
            """
            usage: pm restore <file> [--overwrite]

            Verifies a backup with the passphrase the vault had when it was made,
            then installs it as the vault (--vault, or the default path). An existing
            vault is replaced only with --overwrite, and is kept next to it as
            <vault>.bak.1. The restored vault opens with the passphrase and recovery
            key it had when the backup was made, even if you changed them since.""");

    /** The widest line any usage or help text may have. */
    static final int MAX_COLUMNS = 80;
    /** Marks a command that parses the words after it itself (all but the M1 commands). */
    static final int OWN_ARGS = -1;
    private static final String ENV_OPTIONS = """

              --project <title>   the project (default: the one for this directory)
              --profile <name>    the profile (default: default)""";
    private static final int SYNOPSIS_WIDTH = 28;
    private static final String INDENT = "  ";
    private static final String NEWLINE = "\n";

    /** The usage groups, in the order the usage prints them. */
    enum Area {
        HELP("help"),
        VAULT("vault"),
        RECORDS("records"),
        TOOLS("tools"),
        SSH("ssh"),
        ENV("env and projects"),
        DEVICES("devices and sharing"),
        BROWSER("browser"),
        BACKUP("backup");

        private final String headingText;

        Area(String heading) {
            this.headingText = heading;
        }

        /** The heading the usage prints above the area's commands. */
        String heading() {
            return headingText;
        }
    }

    private final Area listedUnder;
    private final String commandWord;
    private final String subWord;
    private final int operandCount;
    private final String synopsis;
    private final String summary;
    private final String helpText;

    Command(Area area, String word, String sub, int arity, String synopsis, String summary, String helpText) {
        this.listedUnder = area;
        this.commandWord = word;
        this.subWord = sub;
        this.operandCount = arity;
        this.synopsis = synopsis;
        this.summary = summary;
        this.helpText = helpText;
    }

    /** The usage area this command is listed under. */
    Area area() {
        return listedUnder;
    }

    /** The command word, e.g. {@code ssh}. */
    String word() {
        return commandWord;
    }

    /** The subcommand word, e.g. {@code add} for {@code ssh add}, if this entry has one. */
    Optional<String> sub() {
        return Optional.ofNullable(subWord);
    }

    /** The words that name this entry: the command word and, if any, the subcommand word. */
    List<String> words() {
        return subWord == null ? List.of(commandWord) : List.of(commandWord, subWord);
    }

    /**
     * Whether the top-level parser reads this command's operands (the M1 commands, which also take
     * {@code --vault} after the command word); otherwise the command parses the words after it.
     */
    boolean topLevelOperands() {
        return operandCount != OWN_ARGS;
    }

    /** How many operands a {@linkplain #topLevelOperands() top-level} command takes. */
    int arity() {
        return operandCount;
    }

    /** This entry's help text, without a trailing line break. */
    String help() {
        return helpText;
    }

    /** This entry's line in the usage. */
    String usageLine() {
        return INDENT + String.format(java.util.Locale.ROOT, "%-" + SYNOPSIS_WIDTH + "s", synopsis) + " " + summary;
    }

    /** Whether some entry has {@code word} as its command word. */
    static boolean known(String word) {
        return Arrays.stream(values()).anyMatch(c -> c.commandWord.equals(word));
    }

    /** Every entry whose command word is {@code word}, in table order. */
    static List<Command> named(String word) {
        return Arrays.stream(values()).filter(c -> c.commandWord.equals(word)).toList();
    }

    /**
     * The entry a command word and the words after it name: the subcommand entry when the first
     * word after it is one of its subcommands, else the entry without a subcommand.
     *
     * @throws UsageException {@code WRONG_ARG_COUNT} when a subcommand is required and none is
     *     given, {@code UNKNOWN_COMMAND} when the word or the subcommand is not in the table
     */
    static Command resolve(String word, List<String> rest) throws UsageException {
        List<Command> entries = named(word);
        if (!rest.isEmpty()) {
            Optional<Command> bySub = entries.stream().filter(c -> rest.get(0).equals(c.subWord)).findFirst();
            if (bySub.isPresent()) {
                return bySub.get();
            }
        }
        Optional<Command> bare = entries.stream().filter(c -> c.subWord == null).findFirst();
        if (bare.isPresent()) {
            return bare.get();
        }
        throw new UsageException(entries.isEmpty() || !rest.isEmpty() ? Messages.UNKNOWN_COMMAND : Messages.WRONG_ARG_COUNT);
    }

    /** The help for every entry named {@code word}, separated by blank lines. */
    static String helpFor(String word) {
        return named(word).stream().map(Command::help).collect(Collectors.joining(NEWLINE + NEWLINE));
    }

    /** The usage: how to call pm, then every entry's line grouped by area, within 80 columns. */
    static String usage() {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("usage: pm [--vault <path>] <command> [<arguments>]").append(NEWLINE)
                .append(NEWLINE)
                .append("With no command, pm opens the app (and creates a vault on first run).").append(NEWLINE)
                .append("<item> is an item's title, or its id from pm list.").append(NEWLINE);
        for (Area a : Area.values()) {
            sb.append(NEWLINE).append(a.heading()).append(NEWLINE);
            Arrays.stream(values()).filter(c -> c.listedUnder == a)
                    .forEach(c -> sb.append(c.usageLine()).append(NEWLINE));
        }
        sb.append(NEWLINE).append("pm --version prints the version.");
        return sb.toString();
    }

    /** Every line of {@code text}, for width checks. */
    static List<String> lines(String text) {
        return Objects.requireNonNull(text, "text").lines().toList();
    }
}
