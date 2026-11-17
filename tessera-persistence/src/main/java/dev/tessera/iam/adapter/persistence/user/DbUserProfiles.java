package dev.tessera.iam.adapter.persistence.user;

import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import dev.tessera.iam.application.port.out.UserProfilePort;
import dev.tessera.iam.domain.authflow.UserProfile;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Persistence-backed {@link UserProfilePort}: the user record of a subject within its realm, read
 * through the tenant-scoped repository (row-level security on the tenant, the baseline matched by
 * the query).
 */
@ApplicationScoped
public class DbUserProfiles implements UserProfilePort {

    @Inject
    UserRepository users;

    @Override
    public Uni<UserProfile> find(RealmKey realm, String subjectId) {
        if (realm == null || subjectId == null) {
            throw new IllegalArgumentException("realm and subjectId must not be null");
        }
        return users.findBySubject(realm.tenant().value(), realm.baseline().value(), subjectId)
                .map(DbUserProfiles::toProfile);
    }

    static UserProfile toProfile(UserEntity user) {
        if (user == null) {
            return UserProfile.EMPTY;
        }
        return new UserProfile(user.email, user.email != null && user.emailVerified, user.name);
    }
}
