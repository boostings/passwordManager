package pm.tui;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * One LAN step the user started in the TUI (pair, receive, a share window), run by a worker thread
 * ({@link TuiController#background}). The worker asks the user and touches the vault only through
 * {@link #ask} and {@link #onGui}, which hand the work to the GUI thread and wait. Stopping the job
 * (Esc, lock, quit) answers any open question with no, runs the registered closers (listener,
 * share window) and makes every later question a no: the step fails closed.
 */
final class LanJob implements Runnable {
    /** How long a question waits for the user before it counts as no. */
    static final Duration ANSWER_TIMEOUT = Duration.ofMinutes(2);

    private final TuiController controller;
    private final AtomicBoolean stopped = new AtomicBoolean();
    private final List<Runnable> closers = new CopyOnWriteArrayList<>();
    /** Every question asked; answered ones stay (a job asks a handful), a stop answers the rest. */
    private final List<CompletableFuture<Boolean>> waiting = new CopyOnWriteArrayList<>();

    LanJob(TuiController controller) {
        this.controller = Objects.requireNonNull(controller, "controller");
    }

    /** Runs {@code closer} when the job is stopped (at once if it already is). Must not throw. */
    void onStop(Runnable closer) {
        closers.add(Objects.requireNonNull(closer, "closer"));
        if (stopped.get()) {
            closer.run();
        }
    }

    /** Whether the job was stopped. */
    boolean isStopped() {
        return stopped.get();
    }

    /** Stops the job; idempotent. Called on the GUI thread. */
    @Override
    public void run() {
        if (stopped.compareAndSet(false, true)) {
            waiting.forEach(f -> f.complete(false));
            closers.forEach(Runnable::run);
        }
    }

    /**
     * From the worker: shows a question through {@code show} on the GUI thread and waits for the
     * answer. A stop, an interrupt or {@link #ANSWER_TIMEOUT} without an answer is a no.
     *
     * @param show called on the GUI thread with the future its Yes and No buttons complete
     */
    boolean ask(Consumer<CompletableFuture<Boolean>> show) {
        CompletableFuture<Boolean> answer = new CompletableFuture<>();
        controller.post(() -> {
            if (!answer.isDone()) {
                show.accept(answer);
            }
        });
        return await(answer);
    }

    /**
     * From the worker: runs {@code step} on the GUI thread (where the session lives) and waits for
     * its result. A stop or timeout before it ran is false, and the step then never runs.
     */
    boolean onGui(BooleanSupplier step) {
        CompletableFuture<Boolean> result = new CompletableFuture<>();
        controller.post(() -> {
            if (!result.isDone()) {
                result.complete(step.getAsBoolean());
            }
        });
        return await(result);
    }

    @SuppressWarnings("PMD.DoNotUseThreads") // CE-037: re-asserting the interrupt flag is not thread creation
    private boolean await(CompletableFuture<Boolean> answer) {
        waiting.add(answer);
        if (stopped.get()) {
            answer.complete(false);
        }
        try {
            return answer.get(ANSWER_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException | ExecutionException e) {
            answer.complete(false);
            return answer.join();
        } catch (InterruptedException e) {
            answer.complete(false);
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
