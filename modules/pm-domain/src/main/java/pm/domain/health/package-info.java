/**
 * Password health (plan.md §13 M4, ADR 0012): {@link pm.domain.health.StrengthMeter} (weak),
 * {@link pm.domain.health.ReuseCheck} (reused, via keyed hashes), {@link pm.domain.health.AgeCheck}
 * (old, against an injected clock), {@link pm.domain.health.HealthCheck} (all three over vault
 * records, entirely offline), and {@link pm.domain.health.BreachClient}, the opt-in k-anonymity
 * range client, which is the only class here that touches the network and only when called.
 */
package pm.domain.health;
