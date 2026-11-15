package dev.tessera.iam.adapter.persistence.repository;

import dev.tessera.iam.adapter.persistence.entity.ConsentEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.UUID;

/**
 * Tenant-scoped repository for {@link ConsentEntity}.
 *
 * <p>Every operation takes the owning {@code tenantId} and routes all database access
 * through {@link TenantScopedSession#inTenant}, so the {@code consent} row-level-security
 * policy scopes every read and write fail-closed.
 */
@ApplicationScoped
public class ConsentRepository {

    private static final String UPSERT =
            "INSERT INTO consent (id, tenant_id, baseline_id, user_id, client_id, granted_scopes, granted_at, created_at)"
                    + " VALUES (:id, :tid, :bid, :uid, :cid, :scopes, :at, :at)"
                    + " ON CONFLICT ON CONSTRAINT uq_consent_pair"
                    + " DO UPDATE SET granted_scopes = EXCLUDED.granted_scopes, granted_at = EXCLUDED.granted_at";

    @Inject
    TenantScopedSession scoped;

    /**
     * Finds the consent a user granted to a client within the tenant, if any.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param userId   the consenting user id
     * @param clientId the client the consent was granted to
     * @return a {@link Uni} emitting the consent, or {@code null} if none matches
     */
    public Uni<ConsentEntity> findByUserAndClient(UUID tenantId, UUID userId, UUID clientId) {
        return scoped.inTenantRead(tenantId, session ->
                session.createQuery(
                                "from ConsentEntity c where c.userId = :user "
                                        + "and c.clientId = :client",
                                ConsentEntity.class)
                        .setParameter("user", userId)
                        .setParameter("client", clientId)
                        .getSingleResultOrNull());
    }

    /**
     * Records a consent, replacing the scopes and time of any earlier consent the same user gave
     * the same client in the same realm. One statement, so two concurrent grants cannot both
     * insert and trip {@code uq_consent_pair}: the later one wins.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param consent  the consent to record; its id is used only when no row exists yet
     * @return a {@link Uni} completing once the row is written
     */
    public Uni<Void> upsert(UUID tenantId, ConsentEntity consent) {
        return scoped.inTenant(tenantId, session -> session.createNativeQuery(UPSERT)
                .setParameter("id", consent.id)
                .setParameter("tid", consent.tenantId)
                .setParameter("bid", consent.baselineId)
                .setParameter("uid", consent.userId)
                .setParameter("cid", consent.clientId)
                .setParameter("scopes", consent.grantedScopes)
                .setParameter("at", consent.grantedAt)
                .executeUpdate()
                .replaceWithVoid());
    }
}
