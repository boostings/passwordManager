/**
 * pm-domain: environment profiles, the validating environment-variable accessor, the {@code .env}
 * parser, password generation and password health (plan.md §10, Tier 2).
 *
 * <p>{@code java.net.http} is used only by {@code pm.domain.health.BreachClient}, the opt-in
 * k-anonymity breach lookup (ADR 0012).
 */
module pm.domain {
    requires transitive pm.vault;
    requires java.net.http;

    exports pm.domain.env;
    exports pm.domain.generate;
    exports pm.domain.health;
}
