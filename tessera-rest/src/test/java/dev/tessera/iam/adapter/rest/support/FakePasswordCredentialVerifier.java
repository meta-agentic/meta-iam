package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.application.port.out.PasswordCredentialVerifierPort;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Optional;

/**
 * Test double for {@link PasswordCredentialVerifierPort} (the Argon2id-backed verifier is
 * owned by the persistence layer). Accepts two fixed usernames with one password and resolves each to a
 * fixed subject; rejects everything else, so flow tests can drive both the authenticated and
 * the {@code invalid_credentials} paths.
 */
@Mock
@ApplicationScoped
public class FakePasswordCredentialVerifier implements PasswordCredentialVerifierPort {

    public static final String USERNAME = "alice";
    public static final String CORRECT_PASSWORD = "correct-horse-battery-staple";
    /** A UUID, as a real deployment's subject is, so the signed-in user can hold a refresh-token family. */
    public static final String SUBJECT = "5b0f3c2e-8a4d-4c1b-9e7f-2d6a1c3b4e5f";
    /** A second user, for consent tests: its subject is made strict in {@link FakeConsentStore}. */
    public static final String CONSENT_USERNAME = "bob";
    public static final String CONSENT_SUBJECT = "7c1e2d3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f";

    @Override
    public Uni<Optional<String>> verify(RealmKey realm, String username, String password) {
        if (!CORRECT_PASSWORD.equals(password)) {
            return Uni.createFrom().item(Optional.empty());
        }
        if (USERNAME.equals(username)) {
            return Uni.createFrom().item(Optional.of(SUBJECT));
        }
        return Uni.createFrom().item(CONSENT_USERNAME.equals(username) ? Optional.of(CONSENT_SUBJECT) : Optional.empty());
    }
}
