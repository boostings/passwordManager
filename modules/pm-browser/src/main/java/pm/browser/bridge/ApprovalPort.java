package pm.browser.bridge;

import java.time.Duration;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.Outcome;

/**
 * Where the bridge asks for approval. The only way to obtain an allowing {@link Outcome} is from
 * the broker, because its {@link pm.approval.Grant} has no public constructor; a port can deny,
 * but cannot invent permission.
 */
public interface ApprovalPort {

    /** True while the vault is unlocked. */
    boolean isUnlocked();

    /** Submits {@code request} and waits for the decision. Never throws for a refusal. */
    Outcome approve(ApprovalRequest request);

    /**
     * The port for a bridge running in the broker's own process: presents the current session
     * token and waits at most {@code wait} for the user (timeouts become
     * {@link pm.approval.Decision#DENIED_TIMEOUT}).
     */
    static ApprovalPort inProcess(ApprovalBroker broker, Duration wait) {
        return new BrokerApproval(broker, wait);
    }
}
