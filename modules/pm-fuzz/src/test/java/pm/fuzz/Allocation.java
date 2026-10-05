package pm.fuzz;

import java.lang.management.ManagementFactory;

/**
 * Bounded-allocation oracle for the fuzz harnesses: the bytes the calling thread has allocated so
 * far, from HotSpot's per-thread allocation counter ({@code com.sun.management.ThreadMXBean}). A
 * parser that sizes a buffer from a hostile length shows up as a jump far beyond the input size,
 * even when the heap is large enough for the allocation to succeed.
 */
public final class Allocation {
    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    private Allocation() {
    }

    /** Bytes allocated by the current thread since it started. */
    public static long current() {
        return THREADS.getCurrentThreadAllocatedBytes();
    }
}
