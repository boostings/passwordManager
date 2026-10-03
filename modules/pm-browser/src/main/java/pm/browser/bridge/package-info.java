/**
 * The bridge between the native messaging host and the vault (ADR 0014 §5, §6): canonical
 * {@link pm.browser.bridge.Origin}s with exact matching, the {@link pm.browser.bridge.VaultPort}
 * and {@link pm.browser.bridge.ApprovalPort} the bridge depends on, and the
 * {@link pm.browser.bridge.Bridge} that routes every credential release through the approval
 * broker.
 */
package pm.browser.bridge;
