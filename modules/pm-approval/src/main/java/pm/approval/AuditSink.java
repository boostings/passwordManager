package pm.approval;

/** Where the broker writes audit entries; {@code AuditLog} is the file-backed implementation. */
@FunctionalInterface
public interface AuditSink {
    /**
     * Records {@code event}. Must not throw for ordinary I/O trouble: an audit failure is reported
     * through the sink's own channel and never changes a decision to allow.
     */
    void record(AuditEvent event);
}
