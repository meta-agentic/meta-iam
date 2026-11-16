package dev.tessera.iam.domain.tenancy;

/**
 * A registered tenant's status (ADR-IAM-003 D1). Only an {@link #ACTIVE} tenant is issued tokens.
 */
public enum TenantStatus {

    /** The tenant is served. */
    ACTIVE("active"),

    /** The tenant is registered but refused. */
    SUSPENDED("suspended");

    private final String wireName;

    TenantStatus(String wireName) {
        this.wireName = wireName;
    }

    /** The name stored in the registry. */
    public String wireName() {
        return wireName;
    }

    /**
     * Parses a stored status name.
     *
     * @throws IllegalArgumentException if the name is not a known status
     */
    public static TenantStatus fromWireName(String name) {
        for (TenantStatus status : values()) {
            if (status.wireName.equals(name)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown tenant status: " + name);
    }
}
