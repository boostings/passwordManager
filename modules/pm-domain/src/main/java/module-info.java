/**
 * pm-domain: environment profiles, the validating environment-variable accessor, the {@code .env}
 * parser, and password generation (plan.md §10, Tier 2).
 */
module pm.domain {
    requires transitive pm.vault;

    exports pm.domain.env;
    exports pm.domain.generate;
}
