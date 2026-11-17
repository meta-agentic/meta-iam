package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.authflow.UserProfile;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Outbound port that reads what a user record says about a person (email, whether it is verified,
 * name), for the ID token's standard claims. Read within the realm, so a user of another tenant or
 * baseline is never found.
 */
public interface UserProfilePort {

    /**
     * Reads a subject's profile.
     *
     * @param realm     the realm the subject signed in to (never {@code null})
     * @param subjectId the subject's {@code sub} (never {@code null})
     * @return a {@link Uni} emitting the profile, or {@link UserProfile#EMPTY} when the subject has
     *         none or is not a user (never {@code null})
     */
    Uni<UserProfile> find(RealmKey realm, String subjectId);
}
