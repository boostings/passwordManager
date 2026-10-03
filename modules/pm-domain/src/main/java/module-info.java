/**
 * pm-domain: environment profiles, the validating environment-variable accessor and the
 * {@code .env} parser (plan.md §10, Tier 2).
 */
module pm.domain {
    requires transitive pm.vault;

    exports pm.domain.env;
}
