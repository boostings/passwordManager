/**
 * pm-browser: the Chrome native messaging host and the browser bridge (ADR 0014,
 * docs/security/extension-permissions.md). Tier 1.
 */
module pm.browser {
    requires transitive pm.approval;

    exports pm.browser.host;
    exports pm.browser.bridge;
    exports pm.browser.webauthn;
}
