package dev.tessera.iam.domain.tenancy;

/**
 * A tenant's security profile (ADR-IAM-010 D2): the named set of client requirements every
 * endpoint that authenticates a client enforces for that tenant.
 *
 * <p>Profiles are ordered: a later constant is stricter than an earlier one, so a deployment's
 * minimum can be compared against a tenant's profile with {@link #isBelow(SecurityProfile)}.
 */
public enum SecurityProfile {

    /** The floor every tenant meets. */
    STANDARD("standard"),

    /** The FAPI 2.0 security profile. */
    FAPI2("fapi2");

    private final String wireName;

    SecurityProfile(String wireName) {
        this.wireName = wireName;
    }

    /** The name stored in the registry and used in configuration. */
    public String wireName() {
        return wireName;
    }

    /** Whether this profile is less strict than {@code other}. */
    public boolean isBelow(SecurityProfile other) {
        return compareTo(other) < 0;
    }

    /**
     * Parses a stored or configured profile name.
     *
     * @throws IllegalArgumentException if the name is not a known profile
     */
    public static SecurityProfile fromWireName(String name) {
        for (SecurityProfile profile : values()) {
            if (profile.wireName.equals(name)) {
                return profile;
            }
        }
        throw new IllegalArgumentException("Unknown security profile: " + name);
    }
}
