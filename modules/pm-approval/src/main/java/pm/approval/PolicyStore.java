package pm.approval;

import java.util.ArrayList;
import java.util.List;

/** Where temporary policies are kept between broker runs (approval-model.md §2: "in vault"). */
public interface PolicyStore {
    /** The stored temporary policies, expired ones included. */
    List<Policy> load();

    /** Replaces the stored temporary policies. */
    void save(List<Policy> policies);

    /** A store that lives only as long as the broker. */
    static PolicyStore inMemory() {
        return new PolicyStore() {
            private List<Policy> held = new ArrayList<>();

            @Override
            public List<Policy> load() {
                return List.copyOf(held);
            }

            @Override
            public void save(List<Policy> policies) {
                held = new ArrayList<>(policies);
            }
        };
    }
}
