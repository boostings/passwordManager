package pm.domain.health;

/** Coarse strength rating from {@link StrengthMeter}. */
public enum Strength {
    /** Below 30 estimated bits, or a common password: falls to an online guessing attack. */
    VERY_WEAK,
    /** Below 50 estimated bits, or shorter than 10 characters: falls to offline cracking. */
    WEAK,
    /** Below 70 estimated bits. */
    FAIR,
    /** 70 estimated bits or more. */
    STRONG;

    /** Whether the health report flags this rating as weak. */
    public boolean isWeak() {
        return this == VERY_WEAK || this == WEAK;
    }
}
