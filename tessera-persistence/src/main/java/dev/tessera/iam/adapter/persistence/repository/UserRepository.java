package dev.tessera.iam.adapter.persistence.repository;

import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.UUID;

/**
 * Tenant-scoped repository for {@link UserEntity}.
 *
 * <p>Every operation takes the owning {@code tenantId} and routes all database access
 * through {@link TenantScopedSession#inTenant}, so the {@code iam_user} row-level-security
 * policy scopes every read and write fail-closed: a transaction with no tenant bound
 * sees nothing and may write nothing.
 */
@ApplicationScoped
public class UserRepository {

    @Inject
    TenantScopedSession scoped;

    /**
     * Finds a user by its stable OIDC {@code sub} within one realm. {@code sub} is unique only per
     * {@code (tenant, baseline)}, so the baseline is part of the match: a user of another baseline
     * of the same tenant is never found.
     *
     * @param tenantId   the owning tenant (the RLS scoping key)
     * @param baselineId the realm's baseline
     * @param subjectId  the stable {@code sub} to match
     * @return a {@link Uni} emitting the user, or {@code null} if none matches
     */
    public Uni<UserEntity> findBySubject(UUID tenantId, UUID baselineId, String subjectId) {
        return scoped.inTenantRead(tenantId, session ->
                session.createQuery(
                                "from UserEntity u where u.baselineId = :baseline and u.subjectId = :sub",
                                UserEntity.class)
                        .setParameter("baseline", baselineId)
                        .setParameter("sub", subjectId)
                        .getSingleResultOrNull());
    }

    /**
     * Finds a user by its primary key within the tenant.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param id       the user id
     * @return a {@link Uni} emitting the user, or {@code null} if none matches
     */
    public Uni<UserEntity> findById(UUID tenantId, UUID id) {
        return scoped.inTenantRead(tenantId, session -> session.find(UserEntity.class, id));
    }

    /**
     * Finds a user by its login identifier within one realm. A username is unique per
     * {@code (tenant, baseline)} (V17), so a user of another baseline of the same tenant is never
     * found and cannot sign in there.
     *
     * @param tenantId   the owning tenant (the RLS scoping key)
     * @param baselineId the realm's baseline
     * @param username   the login identifier to match
     * @return a {@link Uni} emitting the user, or {@code null} if none matches
     */
    public Uni<UserEntity> findByUsername(UUID tenantId, UUID baselineId, String username) {
        return scoped.inTenantRead(tenantId, session ->
                session.createQuery(
                                "from UserEntity u where u.baselineId = :baseline and u.username = :username",
                                UserEntity.class)
                        .setParameter("baseline", baselineId)
                        .setParameter("username", username)
                        .getSingleResultOrNull());
    }

    /**
     * Persists a new user.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param user     the entity to persist
     * @return a {@link Uni} emitting the persisted entity
     */
    public Uni<UserEntity> persist(UUID tenantId, UserEntity user) {
        return scoped.inTenant(tenantId, session -> session.persist(user).replaceWith(user));
    }
}
