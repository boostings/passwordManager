package pm.cli;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import pm.approval.AuditEvent;
import pm.approval.AuditException;
import pm.approval.AuditLog;
import pm.approval.ipc.IpcException;
import pm.approval.ipc.RunDir;
import pm.crypto.CryptoException;
import pm.domain.env.Env;
import pm.sharing.pair.Lockout;
import pm.sharing.pair.PairedDevice;
import pm.sharing.pair.PairingException;
import pm.sharing.pair.SasPrompt;
import pm.sharing.share.OfferPrompt;
import pm.sharing.share.ShareException;
import pm.sharing.share.Shares;
import pm.sharing.wire.Message;
import pm.tui.Session;
import pm.tui.VaultPort;
import pm.tui.lan.BrowserWindow;
import pm.tui.lan.Devices;
import pm.tui.lan.LanAddress;
import pm.tui.lan.LanException;
import pm.tui.lan.LanState;
import pm.tui.lan.Local;
import pm.tui.lan.Pairing;
import pm.tui.lan.Receiving;
import pm.tui.lan.SendWindow;
import pm.tui.lan.SharePayload;
import pm.vault.VaultException;
import pm.vault.record.TrustedDeviceRecord;
import pm.vault.record.VaultRecord;

/**
 * {@code pm devices}, {@code pm pair}, {@code pm share}, {@code pm receive} and {@code pm revoke}
 * (M3.6, lan-share.md §5 to §8). The trust list and this device's identity live in the vault
 * ({@link Devices}). A share is approved here the way a standalone {@code env run} is: the
 * passphrase plus a typed {@code y} after the summary, recorded in the audit log before anything
 * is sent. While a share window waits, the vault is locked again; {@code pm revoke} reaches the
 * waiting process through a marker file in the owner-only run directory, and a missing marker
 * revokes the window (fail closed). Values are never printed except a browser share's link, which
 * the sender must pass on.
 */
final class LanCommands {
    static final String CONFIRM = "y";
    static final String MARKER_PREFIX = "share-";
    /** How often a waiting share checks its window and its revoke marker. */
    static final Duration POLL = Duration.ofMillis(100);
    private static final Pattern SHARE_ID = Pattern.compile("[0-9a-f]{32}");
    private static final String LISTEN_OPTION = "--listen";
    private static final String BIND_OPTION = "--bind";
    private static final String NAME_OPTION = "--name";
    private static final String TO_OPTION = "--to";
    private static final String BROWSER_OPTION = "--browser";
    private static final String TTL_OPTION = "--ttl";
    private static final String GAP = "  ";
    private static final String REVOKE_COMMAND = "revoke";
    private static final String REMOVE_SUBCOMMAND = "remove";
    private static final int ONE = 1;
    private static final int REMOVE_OPERANDS = 2;
    private static final long SECONDS_PER_MINUTE = 60;
    private static final long SECONDS_PER_HOUR = 3600;

    private final UnaryOperator<String> properties;
    private final Clock clock;
    private final Env environment;
    private final Consumer<String> listening;

    /**
     * @param listening told {@code ip:port} whenever this process starts listening (pairing or a
     *     share window); a test hook, a no-op in production
     */
    LanCommands(UnaryOperator<String> properties, Clock clock, Env environment, Consumer<String> listening) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.environment = Objects.requireNonNull(environment, "environment");
        this.listening = Objects.requireNonNull(listening, "listening");
    }

    /** Parsed {@code operands [--listen] [--browser] [--to D] [--ttl T] [--bind IP] [--name N]}. */
    record Args(List<String> operands, boolean listen, boolean browser, Optional<String> to, Optional<String> ttl,
            Optional<String> bind, Optional<String> name) {

        static Args parse(List<String> raw) throws UsageException {
            Deque<String> in = new ArrayDeque<>(raw);
            List<String> operands = new ArrayList<>();
            boolean listen = false;
            boolean browser = false;
            Optional<String> to = Optional.empty();
            Optional<String> ttl = Optional.empty();
            Optional<String> bind = Optional.empty();
            Optional<String> name = Optional.empty();
            while (!in.isEmpty()) {
                String a = in.removeFirst();
                switch (a) {
                    case LISTEN_OPTION -> listen = true;
                    case BROWSER_OPTION -> browser = true;
                    case TO_OPTION -> to = Optional.of(value(in, to));
                    case TTL_OPTION -> ttl = Optional.of(value(in, ttl));
                    case BIND_OPTION -> bind = Optional.of(value(in, bind));
                    case NAME_OPTION -> name = Optional.of(value(in, name));
                    case EnvCommands.END_OF_OPTIONS -> {
                        operands.addAll(in);
                        in.clear();
                    }
                    default -> {
                        if (a.startsWith("-")) {
                            throw new UsageException(Messages.UNKNOWN_OPTION);
                        }
                        operands.add(a);
                    }
                }
            }
            for (String operand : operands) {
                if (operand.isBlank() || Cli.hasUnsafeChars(operand)) {
                    throw new UsageException(Messages.INVALID_TEXT);
                }
            }
            return new Args(List.copyOf(operands), listen, browser, to, ttl, bind, name);
        }

        private static String value(Deque<String> in, Optional<String> already) throws UsageException {
            if (already.isPresent() || in.isEmpty() || in.peekFirst().startsWith("-")) {
                throw new UsageException(Messages.WRONG_ARG_COUNT);
            }
            String v = in.removeFirst().strip();
            if (v.isEmpty() || Cli.hasUnsafeChars(v)) {
                throw new UsageException(Messages.INVALID_TEXT);
            }
            return v;
        }

        /** The one operand, or a usage error. */
        String only() throws UsageException {
            if (operands.size() != ONE) {
                throw new UsageException(Messages.WRONG_ARG_COUNT);
            }
            return operands.get(0);
        }

        void none() throws UsageException {
            if (!operands.isEmpty()) {
                throw new UsageException(Messages.WRONG_ARG_COUNT);
            }
        }
    }

    /** Runs {@code command} ({@code devices}, {@code pair}, {@code share}, {@code receive}, {@code revoke}). */
    int run(String command, List<String> sub, VaultOpener opener, Path vaultPath, ConsoleIo io)
            throws UsageException, VaultException {
        Args args = Args.parse(sub);
        if (REVOKE_COMMAND.equals(command)) {
            return revoke(args, vaultPath, io);
        }
        VaultPort port = opener.open(vaultPath, false);
        return switch (command) {
            case "devices" -> devices(args, port, io, vaultPath);
            case "pair" -> pair(args, port, io, vaultPath);
            case "share" -> share(args, port, io, vaultPath);
            default -> receive(args, port, io, vaultPath);
        };
    }

    // ---- devices -----------------------------------------------------------------------------

    @SuppressWarnings("PMD.CloseResource") // CE-035: device records are the session's; the PrintWriter is the ConsoleIo's
    private int devices(Args args, VaultPort port, ConsoleIo io, Path vaultPath)
            throws UsageException, VaultException {
        if (args.operands().isEmpty()) {
            try (Session session = Cli.unlock(port, io); Local self = local(session)) {
                PrintWriter out = io.out();
                out.println(Messages.THIS_DEVICE.text() + Cli.displaySafe(self.name()) + GAP + self.fingerprint());
                List<TrustedDeviceRecord> trusted = Devices.trusted(session);
                if (trusted.isEmpty()) {
                    out.println(Messages.NO_DEVICES.text());
                    return ExitCodes.OK;
                }
                out.println(Messages.DEVICES_HEADER.text());
                trusted.forEach(d -> out.println(String.join(GAP, Cli.displaySafe(d.title()), d.fingerprint(),
                        d.pairedAt().toString())));
            }
            return ExitCodes.OK;
        }
        if (!REMOVE_SUBCOMMAND.equals(args.operands().get(0))) {
            throw new UsageException(Messages.UNKNOWN_COMMAND);
        }
        if (args.operands().size() != REMOVE_OPERANDS) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
        try (Session session = Cli.unlock(port, io)) {
            // Only once the vault has opened: a missing vault leaves no LAN state behind it.
            LanState state = lanState(vaultPath);
            TrustedDeviceRecord device = lan(() -> Devices.find(session, args.operands().get(1)));
            String name = device.title();
            List<String> rotate = Devices.sharedWith(session, device).stream()
                    .map(r -> SharePayload.typeName(r) + ": " + Cli.displaySafe(r.title())).toList();
            audit(vaultPath, "revoke", name, "REMOVED", "pm devices", Messages.REMOVE_AUDIT_UNAVAILABLE);
            // Marked removed for every pm process first: a share window open to it elsewhere checks
            // this before releasing anything (SR-205). Only then is it taken off the trust list.
            byte[] key = device.rawPublicKey();
            try {
                state.removed(key);
            } catch (IOException e) {
                throw new UsageException(Messages.LAN_STATE_UNAVAILABLE);
            }
            try {
                Devices.remove(session, device);
            } catch (VaultException e) {
                state.pinned(key);
                throw e;
            }
            io.out().println(Messages.DEVICE_REMOVED.text() + Cli.displaySafe(name));
            if (rotate.isEmpty()) {
                io.out().println(Messages.ROTATE_NONE.text());
            } else {
                io.out().println(Messages.ROTATE_CHECKLIST.text());
                rotate.forEach(line -> io.out().println("  [ ] " + line));
            }
        }
        return ExitCodes.OK;
    }

    // ---- pair --------------------------------------------------------------------------------

    @SuppressWarnings("PMD.CloseResource") // CE-035: the pinned record is the session's (ADR 0008)
    private int pair(Args args, VaultPort port, ConsoleIo io, Path vaultPath) throws UsageException, VaultException {
        Optional<InetSocketAddress> peer = Optional.empty();
        if (args.listen()) {
            args.none();
        } else {
            String address = args.only();
            peer = Optional.of(lan(() -> LanAddress.parse(address)));
        }
        InetAddress bind = bindAddress(args);
        try (Session session = Cli.unlock(port, io)) {
            // Only once the vault has opened: a missing vault leaves no LAN state behind it.
            LanState state = lanState(vaultPath);
            Optional<PairedDevice> paired;
            try (Local self = args.name().isPresent() ? renamed(session, args.name().get()) : local(session)) {
                io.out().println(Messages.THIS_DEVICE.text() + Cli.displaySafe(self.name()) + GAP + self.fingerprint());
                // The lockout is shared by every pm process (SR-203): read now, saved after each failure.
                Lockout lockout = state.lockout(clock.instant());
                SasPrompt prompt = sasPrompt(io);
                try {
                    paired = peer.isPresent() ? initiate(self, peer.get(), lockout, prompt, io)
                            : respond(self, bind, lockout, state, prompt, io);
                } finally {
                    state.save(lockout, clock.instant());
                }
            }
            if (paired.isEmpty()) {
                return ExitCodes.NOT_DONE;
            }
            TrustedDeviceRecord pinned = Devices.pin(session, paired.get(), clock.instant());
            state.pinned(pinned.rawPublicKey());
            // Pinned and saved already: a failed audit must not claim that nothing happened.
            boolean audited = auditDone(vaultPath, "pair", pinned.title(), "PAIRED", "pm pair",
                    Messages.PAIRED_AUDIT_FAILED, io);
            io.out().println(Messages.PAIRED.text() + Cli.displaySafe(pinned.title()) + GAP + pinned.fingerprint());
            return audited ? ExitCodes.OK : ExitCodes.NOT_AUDITED;
        }
    }

    private Optional<PairedDevice> initiate(Local self, InetSocketAddress peer, Lockout lockout, SasPrompt prompt,
            ConsoleIo io) {
        if (!lockout.allows(clock.instant())) {
            io.err().println(Messages.PAIR_LOCKED.text() + lockout.remaining(clock.instant()).toSeconds());
            return Optional.empty();
        }
        try {
            return Optional.of(Pairing.initiate(self, peer, clock, lockout, prompt));
        } catch (PairingException e) {
            io.err().println(Messages.PAIR_FAILED.text() + e.code().name());
        } catch (IOException | CryptoException e) {
            io.err().println(Messages.PAIR_FAILED.text() + Messages.RECEIVE_UNREACHABLE.text());
        }
        return Optional.empty();
    }

    @SuppressWarnings("checkstyle:ParameterNumber")
    private Optional<PairedDevice> respond(Local self, InetAddress bind, Lockout lockout, LanState state,
            SasPrompt prompt, ConsoleIo io) throws UsageException {
        Instant deadline = clock.instant().plus(Pairing.DEFAULT_WINDOW);
        if (!lockout.allows(clock.instant())) {
            io.err().println(Messages.PAIR_LOCKED.text() + lockout.remaining(clock.instant()).toSeconds());
            return Optional.empty();
        }
        try (Pairing.Listener listener = Pairing.Listener.open(self, clock, bind)) {
            String address = LanAddress.show(bind, listener.port());
            io.out().println(Messages.PAIR_LISTENING.text() + address);
            io.out().println(Messages.PAIR_WINDOW.text() + deadline);
            io.out().flush();
            listening.accept(address);
            Optional<PairedDevice> paired = listener.await(lockout, prompt, deadline, code -> {
                state.save(lockout, clock.instant());
                if (code == PairingException.Code.LOCKED) {
                    io.err().println(Messages.PAIR_LOCKED.text() + lockout.remaining(clock.instant()).toSeconds());
                } else {
                    io.err().println(Messages.PAIR_FAILED.text() + code.name());
                }
                io.err().flush();
            });
            if (paired.isEmpty()) {
                io.err().println(Messages.PAIR_TIMED_OUT.text());
            }
            return paired;
        } catch (IOException | CryptoException e) {
            throw new UsageException(Messages.LAN_FAILED);
        }
    }

    /** Shows the code with the peer's name and fingerprint; only a typed {@code y} confirms. */
    private static SasPrompt sasPrompt(ConsoleIo io) {
        return (sas, peerName, peerFingerprint) -> {
            PrintWriter out = io.out();
            out.println(Messages.PAIR_PEER.text() + Cli.displaySafe(peerName) + GAP + peerFingerprint);
            out.println(Messages.PAIR_CODE.text() + sas);
            out.println(Messages.PAIR_COMPARE.text());
            out.flush();
            return confirmed(io, Messages.PAIR_CONFIRM);
        };
    }

    /** This device's identity under a new announced name, saved in the vault. */
    private Local renamed(Session session, String name) throws UsageException, VaultException {
        try {
            return Devices.rename(session, name, clock);
        } catch (CryptoException e) {
            throw new UsageException(Messages.LAN_FAILED);
        }
    }

    // ---- share -------------------------------------------------------------------------------

    private int share(Args args, VaultPort port, ConsoleIo io, Path vaultPath) throws UsageException, VaultException {
        String title = args.only();
        if (args.browser() == args.to().isPresent()) {
            throw new UsageException(Messages.SHARE_TARGET_NEEDED);
        }
        Duration ttl = args.ttl().isPresent() ? lan(() -> LanAddress.ttl(args.ttl().get())) : Shares.DEFAULT_TTL;
        InetAddress bind = bindAddress(args);
        return args.browser() ? shareToBrowser(title, ttl, bind, port, io, vaultPath)
                : shareToDevice(title, args.to().get(), ttl, bind, port, io, vaultPath);
    }

    @SuppressWarnings({"PMD.CloseResource", "checkstyle:ParameterNumber"}) // CE-035: records are the session's; the window closes its Local; PrintWriter is the ConsoleIo's
    private int shareToDevice(String title, String to, Duration ttl, InetAddress bind, VaultPort port,
            ConsoleIo io, Path vaultPath) throws UsageException, VaultException {
        SendWindow opened;
        String itemTitle;
        Path runDir;
        try (Session session = Cli.unlock(port, io)) {
            // Only once the vault has opened: a missing vault leaves no run directory behind it.
            runDir = runDir(vaultPath);
            VaultRecord item = lan(() -> item(session, title));
            itemTitle = item.title();
            TrustedDeviceRecord device = lan(() -> Devices.find(session, to));
            try (SharePayload.Prepared prepared = lan(() -> SharePayload.prepare(item))) {
                PrintWriter out = io.out();
                out.println(Messages.SHARE_SUMMARY.text() + Cli.displaySafe(prepared.summary())
                        + Messages.SHARE_WITH.text() + Cli.displaySafe(device.title()) + GAP + device.fingerprint()
                        + Messages.SHARE_FOR.text() + ttlText(ttl));
                out.flush();
                if (!confirmed(io, Messages.SHARE_CONFIRM)) {
                    io.err().println(Messages.SHARE_DENIED.text());
                    return ExitCodes.DENIED;
                }
                audit(vaultPath, "approval", itemTitle, "ALLOWED_ONCE", "pm share");
                TrustedDeviceRecord current = Devices.recordShare(session, device, item.id(), clock.instant())
                        .orElseThrow(() -> new UsageException(Messages.NO_SUCH_DEVICE));
                Local self = local(session);
                // Asked at every connection and before the data goes: a device removed meanwhile,
                // by any pm process, gets nothing (SR-205).
                LanState state = lanState(vaultPath);
                opened = lan(() -> SendWindow.open(self, current, prepared, ttl, clock, bind, state.stillTrusted()));
            }
        } // the vault locks here: the window holds its own copy of the item and of the identity
        try (SendWindow open = opened) {
            Path marker = marker(runDir, open.id(), open::revoke);
            io.out().println(Messages.SHARE_OPEN.text() + open.address());
            io.out().println(Messages.SHARE_ID.text() + open.id());
            io.out().println(Messages.SHARE_EXPIRES.text() + open.expires());
            io.out().println(Messages.SHARE_WAITING.text());
            io.out().flush();
            listening.accept(open.address());
            SendWindow.Outcome outcome = waitFor(open::await, open::revoke, marker);
            deleteMarker(marker);
            if (open.refusals() > 0) {
                io.err().println(Messages.SHARE_REFUSED.text() + open.refusals());
            }
            return finish(outcome, itemTitle, vaultPath, io);
        }
    }

    @SuppressWarnings("PMD.CloseResource") // CE-035: the item record is the session's; the PrintWriter is the ConsoleIo's
    private int shareToBrowser(String title, Duration ttl, InetAddress bind, VaultPort port,
            ConsoleIo io, Path vaultPath) throws UsageException, VaultException {
        BrowserWindow window;
        String itemTitle;
        Path runDir;
        try (Session session = Cli.unlock(port, io)) {
            runDir = runDir(vaultPath);
            VaultRecord item = lan(() -> item(session, title));
            itemTitle = item.title();
            if (SharePayload.kindOf(item) == Message.Kind.PROJECT) {
                throw new UsageException(Messages.NOT_SHAREABLE);
            }
            PrintWriter out = io.out();
            out.println(Messages.BROWSER_HEADER.text());
            BrowserWindow.WARNINGS.forEach(w -> out.println("  - " + w));
            out.println(Messages.SHARE_SUMMARY.text() + Cli.displaySafe(SharePayload.summary(item))
                    + Messages.SHARE_FOR.text() + ttlText(ttl));
            out.flush();
            if (!confirmed(io, Messages.SHARE_CONFIRM)) {
                io.err().println(Messages.SHARE_DENIED.text());
                return ExitCodes.DENIED;
            }
            audit(vaultPath, "approval", itemTitle, "ALLOWED_ONCE", "pm share --browser");
            window = lan(() -> BrowserWindow.open(item, ttl, clock, bind));
        } // the vault locks here: the value now lives only in the sealed share
        try (BrowserWindow open = window) {
            Path marker = marker(runDir, open.id(), open::revoke);
            PrintWriter out = io.out();
            out.println(Messages.BROWSER_URL.text() + open.url());
            out.println(Messages.BROWSER_FINGERPRINT.text() + open.certificateFingerprint());
            out.println(Messages.SHARE_ID.text() + open.id());
            out.println(Messages.SHARE_EXPIRES.text() + open.expires());
            out.flush();
            listening.accept(open.url());
            SendWindow.Outcome outcome = waitFor(open::await, open::revoke, marker);
            deleteMarker(marker);
            if (outcome != SendWindow.Outcome.DELIVERED && open.pageOpened()) {
                io.err().println(Messages.BROWSER_OPENED.text());
            }
            return finish(outcome, itemTitle, vaultPath, io);
        }
    }

    private int finish(SendWindow.Outcome outcome, String itemTitle, Path vaultPath, ConsoleIo io) {
        boolean delivered = outcome == SendWindow.Outcome.DELIVERED;
        // The window has closed: what happened stands whether or not it can be audited.
        boolean audited = auditDone(vaultPath, "share", itemTitle, outcome.name(), "pm share",
                delivered ? Messages.DELIVERED_AUDIT_FAILED : Messages.SHARE_CLOSED_AUDIT_FAILED, io);
        switch (outcome) {
            case DELIVERED -> io.out().println(Messages.SHARE_DELIVERED.text());
            case REVOKED -> io.err().println(Messages.SHARE_REVOKED.text());
            default -> io.err().println(Messages.SHARE_EXPIRED.text());
        }
        if (!delivered) {
            return ExitCodes.NOT_DONE;
        }
        return audited ? ExitCodes.OK : ExitCodes.NOT_AUDITED;
    }

    /** A share window's wait, as the CLI needs it. */
    @FunctionalInterface
    interface Await {
        SendWindow.Outcome await(Duration timeout) throws InterruptedException;
    }

    /**
     * Waits for the window to close. A missing revoke marker, or an interrupt, revokes it: anything
     * that cannot be confirmed as still wanted is cut off (fail closed).
     */
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-037: re-asserting the interrupt flag is not thread creation
    static SendWindow.Outcome waitFor(Await window, Runnable revoke, Path marker) {
        try {
            while (true) {
                SendWindow.Outcome outcome = window.await(POLL);
                if (outcome != SendWindow.Outcome.OPEN) {
                    return outcome;
                }
                if (!Files.exists(marker)) {
                    revoke.run();
                }
            }
        } catch (InterruptedException e) {
            revoke.run();
            Thread.currentThread().interrupt();
            return SendWindow.Outcome.REVOKED;
        }
    }

    /** Creates the revoke marker; if it cannot be created the window is revoked at once. */
    private static Path marker(Path runDir, String id, Runnable revoke) throws UsageException {
        Path marker = runDir.resolve(MARKER_PREFIX + id);
        try {
            Files.createFile(marker);
            return marker;
        } catch (FileAlreadyExistsException e) {
            revoke.run();
            throw new UsageException(Messages.RUN_DIR_UNAVAILABLE);
        } catch (IOException e) {
            revoke.run();
            throw new UsageException(Messages.RUN_DIR_UNAVAILABLE);
        }
    }

    private static void deleteMarker(Path marker) {
        try {
            Files.deleteIfExists(marker);
        } catch (IOException e) {
            // A stale marker names a closed window; pm revoke on it finds nothing to stop.
            Objects.requireNonNull(e);
        }
    }

    /**
     * The LAN state: removed-device markers next to the vault file (so every process of this vault
     * finds them, whatever its environment) and the pairing lockout in the run directory.
     */
    private LanState lanState(Path vaultPath) throws UsageException {
        try {
            return LanState.forVault(vaultPath, RunDir.prepare(RunDir.locate(environment, vaultDirOf(vaultPath))).path());
        } catch (IpcException | IOException e) {
            throw new UsageException(Messages.LAN_STATE_UNAVAILABLE);
        }
    }

    private Path runDir(Path vaultPath) throws UsageException {
        try {
            return RunDir.prepare(RunDir.locate(environment, vaultDirOf(vaultPath))).path();
        } catch (IpcException e) {
            throw new UsageException(Messages.RUN_DIR_UNAVAILABLE);
        }
    }

    private static Path vaultDirOf(Path vaultPath) {
        return Objects.requireNonNull(vaultPath.toAbsolutePath().getParent(), "vault dir");
    }

    /** The item called {@code title}: exactly one, never sharing state. */
    private static VaultRecord item(Session session, String title) throws LanException {
        List<VaultRecord> matches = session.records().stream()
                .filter(r -> !Devices.isInternal(r) && r.title().equals(title)).toList();
        if (matches.size() > ONE) {
            throw new LanException(LanException.Code.AMBIGUOUS_ITEM);
        }
        return matches.stream().findFirst().orElseThrow(() -> new LanException(LanException.Code.NO_SUCH_ITEM));
    }

    // ---- receive -----------------------------------------------------------------------------

    private int receive(Args args, VaultPort port, ConsoleIo io, Path vaultPath)
            throws UsageException, VaultException {
        String address = args.only();
        InetSocketAddress sender = lan(() -> LanAddress.parse(address));
        try (Session session = Cli.unlock(port, io); Local self = local(session)) {
            List<TrustedDeviceRecord> trusted = Devices.trusted(session);
            OfferPrompt prompt = (offer, fingerprint) -> {
                String from = trusted.stream().filter(d -> d.fingerprint().equals(fingerprint)).findFirst()
                        .map(TrustedDeviceRecord::title).orElse("?");
                PrintWriter out = io.out();
                out.println(Messages.RECEIVE_OFFER.text() + Cli.displaySafe(from) + GAP + fingerprint);
                out.println(Messages.RECEIVE_ITEM.text() + Cli.displaySafe(offer.summary()));
                out.println(Messages.RECEIVE_EXPIRES.text() + Instant.ofEpochSecond(offer.expires()));
                out.flush();
                return confirmed(io, Messages.RECEIVE_CONFIRM);
            };
            try {
                // The replay guard comes from the vault and is extended in the same save as the item.
                Message.ShareOffer applied = Receiving.receive(self, sender, trusted, clock,
                        Devices.receivedShares(session, clock.instant()), prompt,
                        (offer, fingerprint, payload) -> SharePayload.apply(session, offer, fingerprint, payload,
                                clock.instant()));
                // Saved already: a failed audit must not claim that nothing happened.
                boolean audited = auditDone(vaultPath, "share", applied.summary(), "RECEIVED", "pm receive",
                        Messages.RECEIVED_AUDIT_FAILED, io);
                io.out().println(Messages.RECEIVED.text() + Cli.displaySafe(applied.summary()));
                return audited ? ExitCodes.OK : ExitCodes.NOT_AUDITED;
            } catch (ShareException e) {
                io.err().println(Messages.RECEIVE_FAILED.text() + e.code().name());
                return e.code() == ShareException.Code.DECLINED ? ExitCodes.DENIED : ExitCodes.NOT_DONE;
            } catch (LanException e) {
                io.err().println(Messages.RECEIVE_UNREACHABLE.text());
                return ExitCodes.NOT_DONE;
            }
        }
    }

    // ---- revoke ------------------------------------------------------------------------------

    private int revoke(Args args, Path vaultPath, ConsoleIo io) throws UsageException {
        String id = args.only().toLowerCase(Locale.ROOT);
        if (!SHARE_ID.matcher(id).matches()) {
            throw new UsageException(Messages.BAD_SHARE_ID);
        }
        Path marker;
        try {
            marker = RunDir.existing(RunDir.locate(environment, vaultDirOf(vaultPath))).path()
                    .resolve(MARKER_PREFIX + id);
        } catch (IpcException e) {
            throw new UsageException(Messages.NO_SUCH_SHARE);
        }
        try {
            if (!Files.deleteIfExists(marker)) {
                throw new UsageException(Messages.NO_SUCH_SHARE);
            }
        } catch (IOException e) {
            throw new UsageException(Messages.RUN_DIR_UNAVAILABLE);
        }
        // The marker is gone, so the window closes: a failed audit must not claim otherwise.
        boolean audited = auditDone(vaultPath, "revoke", id, "REVOKED", "pm revoke", Messages.REVOKED_AUDIT_FAILED,
                io);
        io.out().println(Messages.REVOKED.text());
        return audited ? ExitCodes.OK : ExitCodes.NOT_AUDITED;
    }

    // ---- helpers -----------------------------------------------------------------------------

    private Local local(Session session) throws UsageException, VaultException {
        try {
            String user = Optional.ofNullable(properties.apply("user.name")).orElse("");
            return Devices.local(session, user.isBlank() ? Devices.FALLBACK_NAME : "pm " + user, clock);
        } catch (CryptoException e) {
            throw new UsageException(Messages.LAN_FAILED);
        }
    }

    private static InetAddress bindAddress(Args args) throws UsageException {
        if (args.bind().isEmpty()) {
            return LanAddress.defaultBind();
        }
        try {
            return LanAddress.bind(args.bind().get());
        } catch (LanException e) {
            throw new UsageException(Messages.BAD_BIND);
        }
    }

    /** Reads one line; only exactly {@code y} confirms. End of input or bad text is a no. */
    static boolean confirmed(ConsoleIo io, Messages prompt) {
        try {
            return CONFIRM.equals(Cli.readText(io, prompt));
        } catch (UsageException e) {
            return false;
        }
    }

    /** A step that can fail with a {@link LanException}. */
    @FunctionalInterface
    interface LanStep<T> {
        T get() throws LanException;
    }

    /** Runs {@code step}, turning its failure into the matching catalogue message. */
    static <T> T lan(LanStep<T> step) throws UsageException {
        try {
            return step.get();
        } catch (LanException e) {
            throw new UsageException(messageFor(e.code()));
        }
    }

    static Messages messageFor(LanException.Code code) {
        return switch (code) {
            case NO_SUCH_DEVICE -> Messages.NO_SUCH_DEVICE;
            case AMBIGUOUS_DEVICE -> Messages.AMBIGUOUS_DEVICE;
            case NO_SUCH_ITEM -> Messages.NO_SUCH_ITEM;
            case AMBIGUOUS_ITEM -> Messages.AMBIGUOUS_ITEM;
            case NOT_SHAREABLE -> Messages.NOT_SHAREABLE;
            case BAD_ADDRESS -> Messages.BAD_ADDRESS;
            case BAD_TTL -> Messages.BAD_TTL;
            case BAD_SHARE_ID -> Messages.BAD_SHARE_ID;
            case NO_SUCH_SHARE -> Messages.NO_SUCH_SHARE;
            case NETWORK -> Messages.LAN_FAILED;
        };
    }

    /**
     * Appends to the vault's audit log before an item is released; a failure stops the operation
     * (approval-model §7), and nothing has been exported.
     */
    private void audit(Path vaultPath, String kind, String subject, String decision, String program)
            throws UsageException {
        audit(vaultPath, kind, subject, decision, program, Messages.AUDIT_UNAVAILABLE);
    }

    /** As {@link #audit(Path, String, String, String, String)}, reporting a failure as {@code ifFailed}. */
    private void audit(Path vaultPath, String kind, String subject, String decision, String program,
            Messages ifFailed) throws UsageException {
        try {
            append(vaultPath, kind, subject, decision, program);
        } catch (AuditException e) {
            // A plain I/O failure keeps the caller's text; a broken, busy or unsafe log says so.
            throw e.code() == AuditException.Code.IO ? new UsageException(ifFailed) : UsageException.audit(e);
        }
    }

    /**
     * Appends the entry for a change already made, which a failed audit write cannot undo: the
     * failure is reported as {@code ifFailed}, which says what did happen, the command still
     * prints its result, and it exits {@link ExitCodes#NOT_AUDITED}.
     *
     * @return whether the entry was written
     */
    private boolean auditDone(Path vaultPath, String kind, String subject, String decision, String program,
            Messages ifFailed, ConsoleIo io) {
        try {
            append(vaultPath, kind, subject, decision, program);
            return true;
        } catch (AuditException e) {
            io.err().println(ifFailed.text());
            return false;
        }
    }

    private void append(Path vaultPath, String kind, String subject, String decision, String program)
            throws AuditException {
        AuditLog.append(vaultDirOf(vaultPath).resolve(AuditLog.FILE_NAME), clock, new AuditEvent(kind,
                Optional.empty(), Optional.of("CLI"), Optional.ofNullable(properties.apply("user.name")),
                Optional.of(subject), Optional.empty(), -1, Optional.of(decision), Optional.of(program)));
    }

    /**
     * A share window's time to live as {@code --ttl} spells it: whole hours, else whole minutes,
     * else seconds ({@code 2m}, not the ISO {@code PT2M}).
     */
    static String ttlText(Duration ttl) {
        long seconds = ttl.toSeconds();
        if (seconds % SECONDS_PER_HOUR == 0 && seconds != 0) {
            return seconds / SECONDS_PER_HOUR + "h";
        }
        if (seconds % SECONDS_PER_MINUTE == 0 && seconds != 0) {
            return seconds / SECONDS_PER_MINUTE + "m";
        }
        return seconds + "s";
    }
}
