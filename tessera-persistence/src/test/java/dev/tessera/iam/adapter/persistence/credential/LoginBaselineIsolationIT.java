package dev.tessera.iam.adapter.persistence.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import dev.tessera.iam.adapter.persistence.PostgresIamTestResource;
import dev.tessera.iam.adapter.persistence.consent.PersistentConsentStore;
import dev.tessera.iam.adapter.persistence.entity.CredentialEntity;
import dev.tessera.iam.adapter.persistence.entity.CredentialKind;
import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.repository.CredentialRepository;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Login and consent are scoped to the realm, {@code (tenant, baseline)}, not to the tenant alone.
 * Row-level security keys on the tenant only, so these lookups carry the baseline themselves, and
 * V17 makes a username unique per realm. In the spirit of the no-cross-tenant-leakage test: real
 * PostgreSQL, the production verifier and stores, no fakes.
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("Login and consent — baseline-scoped within one tenant (PostgreSQL integration)")
class LoginBaselineIsolationIT {

    private static final Argon2Function FAST = Argon2Function.getInstance(1024, 1, 1, 32, Argon2.ID);
    private static final String PASSWORD = "correct horse battery staple";

    @Inject
    Argon2PasswordCredentialVerifier verifier;

    @Inject
    UserRepository users;

    @Inject
    CredentialRepository credentials;

    @Inject
    PersistentConsentStore consents;

    private static RealmKey realm(UUID tenant, UUID baseline) {
        return new RealmKey(new TenantId(tenant), new BaselineId(baseline));
    }

    private static UserEntity user(RealmKey realm, String username, String subject) {
        UserEntity user = new UserEntity();
        user.id = UUID.randomUUID();
        user.tenantId = realm.tenant().value();
        user.baselineId = realm.baseline().value();
        user.subjectId = subject;
        user.username = username;
        user.createdAt = Instant.now();
        return user;
    }

    /** Persists a user of {@code realm} with a password credential. */
    private Uni<UserEntity> userWithPassword(RealmKey realm, String username, String subject) {
        UUID tenant = realm.tenant().value();
        UserEntity user = user(realm, username, subject);
        CredentialEntity credential = new CredentialEntity();
        credential.id = UUID.randomUUID();
        credential.tenantId = tenant;
        credential.baselineId = realm.baseline().value();
        credential.userId = user.id;
        credential.kind = CredentialKind.PASSWORD_HASH;
        credential.material = Password.hash(PASSWORD).with(FAST).getResult().getBytes(StandardCharsets.UTF_8);
        credential.label = "test";
        credential.createdAt = Instant.now();
        return users.persist(tenant, user).chain(() -> credentials.persist(tenant, credential)).replaceWith(user);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a user of baseline A cannot sign in at baseline B of the same tenant")
    void userOfOneBaseline_cannotSignInAtAnother(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        RealmKey baselineA = realm(tenant, UUID.randomUUID());
        RealmKey baselineB = realm(tenant, UUID.randomUUID());

        asserter.execute(() -> userWithPassword(baselineA, "alice", "sub-alice"));
        asserter.assertThat(() -> verifier.verify(baselineB, "alice", PASSWORD),
                subject -> assertThat(subject).as("another baseline must not resolve the user").isEmpty());
        asserter.assertThat(() -> verifier.verify(baselineA, "alice", PASSWORD),
                subject -> assertThat(subject).isEqualTo(Optional.of("sub-alice")));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("the same username in two baselines signs in to each one's own user")
    void sameUsername_inTwoBaselines_resolvesPerBaseline(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        RealmKey baselineA = realm(tenant, UUID.randomUUID());
        RealmKey baselineB = realm(tenant, UUID.randomUUID());

        asserter.execute(() -> userWithPassword(baselineA, "bob", "sub-bob-a"));
        asserter.execute(() -> userWithPassword(baselineB, "bob", "sub-bob-b"));
        asserter.assertThat(() -> verifier.verify(baselineA, "bob", PASSWORD),
                subject -> assertThat(subject).isEqualTo(Optional.of("sub-bob-a")));
        asserter.assertThat(() -> verifier.verify(baselineB, "bob", PASSWORD),
                subject -> assertThat(subject).isEqualTo(Optional.of("sub-bob-b")));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a username is unique within one realm")
    void username_isUniquePerRealm(UniAsserter asserter) {
        RealmKey realm = realm(UUID.randomUUID(), UUID.randomUUID());
        UUID tenant = realm.tenant().value();

        asserter.execute(() -> users.persist(tenant, user(realm, "carol", "sub-carol-1")));
        asserter.assertFailedWith(() -> users.persist(tenant, user(realm, "carol", "sub-carol-2")),
                failure -> assertThat(messages(failure)).contains("uq_iam_user_username"));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("consent is scoped by baseline: the same subject in two baselines does not share it, and the lookup stays unique")
    void consent_isScopedByBaseline(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        RealmKey baselineA = realm(tenant, UUID.randomUUID());
        RealmKey baselineB = realm(tenant, UUID.randomUUID());
        ClientId client = ClientId.generate();

        // The same sub in two baselines of one tenant: legal, since sub is unique per (tenant, baseline).
        asserter.execute(() -> users.persist(tenant, user(baselineA, "dave-a", "sub-dave")));
        asserter.execute(() -> users.persist(tenant, user(baselineB, "dave-b", "sub-dave")));
        asserter.execute(() -> consents.grant(baselineA, "sub-dave", client, Set.of("openid")));

        asserter.assertEquals(() -> consents.hasConsent(baselineA, "sub-dave", client, Set.of("openid")), Boolean.TRUE);
        asserter.assertEquals(() -> consents.hasConsent(baselineB, "sub-dave", client, Set.of("openid")), Boolean.FALSE);
    }

    private static String messages(Throwable failure) {
        StringBuilder all = new StringBuilder();
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            all.append(cause.getMessage()).append(' ');
        }
        return all.toString();
    }
}
