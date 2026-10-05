package pm.browser.host;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.approval.ApprovalBroker;
import pm.approval.Grant;
import pm.approval.PolicyStore;
import pm.browser.bridge.ApprovalPort;
import pm.browser.bridge.Bridge;
import pm.browser.bridge.Origin;
import pm.browser.bridge.PasskeyPort;
import pm.browser.bridge.PasswordGenerator;
import pm.browser.bridge.VaultPort;
import pm.browser.webauthn.PublicSuffixList;
import pm.browser.webauthn.RpId;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

/**
 * A missing or tampered Public Suffix List refuses WebAuthn requests with {@code PSL_UNAVAILABLE}
 * and nothing else: the host keeps running and answers every other request (SR-116; M6.3 fix
 * round, item 3). The list is read once, on the first WebAuthn request, never at class load.
 */
@Tag("T-PK-01")
final class PslUnavailableHostTest {
    private static final ExtensionAllowlist ALLOW = ExtensionAllowlist.of(List.of(ExtensionAllowlistTest.ID));
    private static final List<String> ARGS = List.of(ExtensionAllowlistTest.ORIGIN);
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-05T12:00:00Z"), ZoneOffset.UTC);
    private static final String ORIGIN = "https://example.com";
    private static final String CDJ = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0";
    private static final String GET = "{\"type\":\"webauthn.get\",\"id\":\"g1\",\"origin\":\"" + ORIGIN
            + "\",\"rpId\":\"example.com\",\"clientDataJSON\":\"" + CDJ
            + "\",\"allowCredentials\":[],\"credential\":null,\"userVerification\":\"preferred\"}";
    private static final String CREATE = "{\"type\":\"webauthn.create\",\"id\":\"c1\",\"origin\":\"" + ORIGIN
            + "\",\"rpId\":\"example.com\",\"clientDataJSON\":\"" + CDJ
            + "\",\"user\":{\"id\":\"dXNlcg\",\"name\":\"alice\",\"displayName\":\"Alice\"},\"algorithms\":[-7],"
            + "\"excludeCredentials\":[],\"userVerification\":\"preferred\"}";
    private static final String LOOKUP = "{\"type\":\"lookup\",\"id\":\"l1\",\"origin\":\"" + ORIGIN + "\"}";

    @Test
    void aDamagedListAnswersWebauthnWithPslUnavailableAndTheHostKeepsServing() throws IOException {
        byte[] tampered = PublicSuffixList.VENDORED.read();
        tampered[0] ^= 1;
        AtomicInteger reads = new AtomicInteger();
        PublicSuffixList.Source damaged = () -> {
            reads.incrementAndGet();
            return tampered.clone();
        };
        PublicSuffixList.Source missing = () -> {
            reads.incrementAndGet();
            throw new FileNotFoundException("public_suffix_list.dat");
        };
        ApprovalBroker broker = new ApprovalBroker(CLOCK, e -> { }, PolicyStore.inMemory(), "alice");
        broker.unlock();
        ApprovalPort approvals = ApprovalPort.inProcess(broker, Duration.ofMillis(1));
        for (PublicSuffixList.Source source : List.of(damaged, missing)) {
            Handler.Factory factory = Bridge.factory(NO_LOGINS, approvals, CLOCK, PasswordGenerator.secure(),
                    PasskeyPort.NONE, RpId.from(source));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] in = Frames.concat(Frames.frame(GET), Frames.frame(CREATE), Frames.frame(LOOKUP),
                    Frames.frame(GET));
            assertEquals(NativeHost.EXIT_OK, NativeHost.run(ARGS, ALLOW, new ByteArrayInputStream(in), out, factory));
            assertEquals(List.of(error("g1"), error("c1"),
                    "{\"type\":\"lookup\",\"id\":\"l1\",\"origin\":\"" + ORIGIN + "\",\"entries\":[]}",
                    error("g1")), Frames.replies(out.toByteArray()));
        }
        assertEquals(2, reads.get());
        assertEquals(List.of(), broker.pending());
    }

    private static String error(String id) {
        return "{\"type\":\"error\",\"id\":\"" + id + "\",\"code\":\"PSL_UNAVAILABLE\"}";
    }

    private static final VaultPort NO_LOGINS = new VaultPort() {
        @Override
        public List<Login> logins() {
            return List.of();
        }

        @Override
        public SecretBytes password(Grant grant, UUID entry) throws HostException {
            throw new HostException(HostException.Code.NOT_FOUND);
        }

        @Override
        public UUID save(Grant grant, Origin origin, String username, SecretChars password) throws HostException {
            throw new HostException(HostException.Code.NOT_FOUND);
        }
    };
}
