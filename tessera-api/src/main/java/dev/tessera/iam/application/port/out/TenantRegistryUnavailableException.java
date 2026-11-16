package dev.tessera.iam.application.port.out;

/**
 * The tenant registry could not be read. A request that needs it is refused with {@code 503}, never
 * served on a default (ADR-IAM-003 D1 consequence 2).
 */
public final class TenantRegistryUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** @param cause the read failure */
    public TenantRegistryUnavailableException(Throwable cause) {
        super("the tenant registry could not be read", cause);
    }
}
