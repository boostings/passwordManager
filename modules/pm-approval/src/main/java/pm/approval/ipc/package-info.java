/**
 * Local IPC to the approval broker (ADR 0009, approval-model.md §5): a Unix domain socket in an
 * owner-only run directory, a 0600 session-token file rotated on every unlock, and length-prefixed
 * deterministic-CBOR frames of at most 64 KiB per request.
 */
package pm.approval.ipc;
