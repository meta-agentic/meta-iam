package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.util.function.Supplier;

/**
 * Admits a token request only for a tenant the registry holds as active (ADR-IAM-003 D1: a tenant
 * missing from the registry gets no token, and it is not defaulted).
 *
 * <p>It runs before the grant's own work, so a refused request consumes no authorization code and
 * rotates no refresh token. The refusal is {@code invalid_client} with the same description an
 * authentication failure carries, so a caller learns nothing about which tenants are registered;
 * the reason is logged. A registry that cannot be read fails the request with
 * {@link dev.tessera.iam.application.port.out.TenantRegistryUnavailableException}, which the edge
 * answers with {@code 503}.
 */
public final class TenantAdmission {

    private static final System.Logger LOG = System.getLogger(TenantAdmission.class.getName());

    /** The description of a refused request: identical to a failed client authentication. */
    static final String REFUSED = "client authentication failed";

    private final TenantRegistryPort registry;

    /** @param registry the tenant registry (never {@code null}) */
    public TenantAdmission(TenantRegistryPort registry) {
        if (registry == null) {
            throw new IllegalArgumentException("registry must not be null");
        }
        this.registry = registry;
    }

    /**
     * Runs {@code work} if {@code tenant} is registered and active, else answers {@code invalid_client}.
     *
     * @param tenant the tenant the request is for (never {@code null})
     * @param work   the grant's work, subscribed only once the tenant is admitted
     * @return the work's result, or the refusal
     */
    public Uni<TokenResult> admit(TenantId tenant, Supplier<Uni<TokenResult>> work) {
        if (tenant == null) {
            throw new IllegalArgumentException("tenant must not be null");
        }
        return registry.find(tenant).flatMap(found -> {
            if (found.isEmpty()) {
                LOG.log(System.Logger.Level.WARNING,
                        "token request refused: tenant {0} is not in the tenant registry", tenant.value());
                return refused();
            }
            if (!found.get().isActive()) {
                LOG.log(System.Logger.Level.WARNING,
                        "token request refused: tenant {0} is {1}", tenant.value(),
                        found.get().status().wireName());
                return refused();
            }
            return work.get();
        });
    }

    private static Uni<TokenResult> refused() {
        return Uni.createFrom().item(new TokenResult.Failed(AuthorizationError.INVALID_CLIENT, REFUSED));
    }
}
