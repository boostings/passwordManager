/**
 * pm-approval: the approval broker, the single path by which a secret leaves the vault to a
 * process, extension or device (SR-100, ADR 0009, approval-model.md). Tier 1.
 */
module pm.approval {
    requires transitive pm.domain;
    requires jdk.net;

    exports pm.approval;
    exports pm.approval.ipc;
}
