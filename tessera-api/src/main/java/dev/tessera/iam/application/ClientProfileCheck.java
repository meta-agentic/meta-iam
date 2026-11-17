package dev.tessera.iam.application;

import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientUse;
import dev.tessera.iam.domain.client.ProfileConformance;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Applies {@link ProfileConformance} to a client that just authenticated, with its tenant's profile
 * read from the registry (ADR-IAM-010 D2: enforced at use). Every service that authenticates a
 * client folds this into its authentication result, so a client that does not meet the profile
 * fails exactly as a failed authentication does: {@code invalid_client}, with the reason logged.
 * {@code ClientProfileCheckArchTest} pins that each of them depends on it.
 */
public final class ClientProfileCheck {

    private static final System.Logger LOG = System.getLogger(ClientProfileCheck.class.getName());

    private final TenantRegistryPort registry;

    /** @param registry the tenant registry (never {@code null}) */
    public ClientProfileCheck(TenantRegistryPort registry) {
        if (registry == null) {
            throw new IllegalArgumentException("registry must not be null");
        }
        this.registry = registry;
    }

    /**
     * Folds the profile check into an authentication result.
     *
     * @param authenticated whether the client authenticated; when {@code false} nothing is read
     * @param realm         the realm the client authenticated in (never {@code null})
     * @param client        the authenticated client; may be {@code null} only when not authenticated
     * @param use           what it authenticated for (never {@code null})
     * @return {@code true} only if it authenticated and meets its tenant's profile. An unregistered
     *         tenant is {@code false}. An unreadable registry fails the {@code Uni}.
     */
    public Uni<Boolean> andConforms(boolean authenticated, RealmKey realm, Client client, ClientUse use) {
        if (!authenticated) {
            return Uni.createFrom().item(Boolean.FALSE);
        }
        return registry.find(realm.tenant()).map(found -> {
            if (found.isEmpty()) {
                LOG.log(System.Logger.Level.WARNING,
                        "client {0} refused: tenant {1} is not in the tenant registry",
                        client.id().value(), realm.tenant().value());
                return Boolean.FALSE;
            }
            ProfileConformance.Verdict verdict = ProfileConformance.check(found.get().profile(), client, use);
            if (verdict instanceof ProfileConformance.Verdict.Fails fails) {
                LOG.log(System.Logger.Level.WARNING, "client {0} refused under the {1} profile: {2}",
                        client.id().value(), found.get().profile().wireName(), fails.reason());
                return Boolean.FALSE;
            }
            return Boolean.TRUE;
        });
    }
}
