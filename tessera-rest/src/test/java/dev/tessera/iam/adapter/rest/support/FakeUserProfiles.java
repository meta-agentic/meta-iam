package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.application.port.out.UserProfilePort;
import dev.tessera.iam.domain.authflow.UserProfile;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link UserProfilePort}: no subject has a profile unless a test sets one. */
@Mock
@ApplicationScoped
public class FakeUserProfiles implements UserProfilePort {

    private final Map<String, UserProfile> profiles = new ConcurrentHashMap<>();

    /** From now on, {@code subject} has {@code profile}. */
    public void set(String subject, UserProfile profile) {
        profiles.put(subject, profile);
    }

    /** {@code subject} has no profile again. */
    public void clear(String subject) {
        profiles.remove(subject);
    }

    @Override
    public Uni<UserProfile> find(RealmKey realm, String subjectId) {
        return Uni.createFrom().item(profiles.getOrDefault(subjectId, UserProfile.EMPTY));
    }
}
