package dev.tessera.iam.adapter.persistence.user;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.persistence.PostgresIamTestResource;
import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import dev.tessera.iam.domain.authflow.UserProfile;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The user declaration sets email and name on existing users, and the profile adapter reads them
 * back within the realm only (PostgreSQL, three-role model, no fakes).
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("User profile — declared email and name, read back per realm (PostgreSQL integration)")
class UserProfileIT {

    @Inject
    UserDeclaration declaration;

    @Inject
    DbUserProfiles profiles;

    @Inject
    UserRepository users;

    private static UserEntity user(UUID tenant, UUID baseline, String username, String subject) {
        UserEntity user = new UserEntity();
        user.id = UUID.randomUUID();
        user.tenantId = tenant;
        user.baselineId = baseline;
        user.subjectId = subject;
        user.username = username;
        user.createdAt = Instant.now();
        return user;
    }

    private static String declarationFor(UUID tenant, UUID baseline, String body) {
        return "{\"users\": [{\"tenant\": \"" + tenant + "\", \"baseline\": \"" + baseline + "\", " + body + "}]}";
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a declared email and name are read back, the address verified; another baseline sees nothing")
    void declaredProfile_isReadBackInItsRealmOnly(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID baseline = UUID.randomUUID();
        RealmKey realm = new RealmKey(new TenantId(tenant), new BaselineId(baseline));
        RealmKey otherBaseline = new RealmKey(new TenantId(tenant), new BaselineId(UUID.randomUUID()));

        asserter.execute(() -> users.persist(tenant, user(tenant, baseline, "ada", "sub-ada")));
        asserter.execute(() -> declaration.apply(UserDeclaration.parse(declarationFor(tenant, baseline,
                "\"username\": \"ada\", \"email\": \"ada@example.com\", \"name\": \"Ada Lovelace\""),
                Optional.empty())));
        asserter.assertThat(() -> profiles.find(realm, "sub-ada"),
                profile -> assertThat(profile).isEqualTo(new UserProfile("ada@example.com", true, "Ada Lovelace")));
        asserter.assertThat(() -> profiles.find(otherBaseline, "sub-ada"),
                profile -> assertThat(profile).isEqualTo(UserProfile.EMPTY));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an absent field is kept, an explicit null clears, and a missing user is skipped")
    void statedFieldsOnly(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID baseline = UUID.randomUUID();
        RealmKey realm = new RealmKey(new TenantId(tenant), new BaselineId(baseline));

        asserter.execute(() -> users.persist(tenant, user(tenant, baseline, "bob", "sub-bob")));
        asserter.execute(() -> declaration.apply(UserDeclaration.parse(declarationFor(tenant, baseline,
                "\"username\": \"bob\", \"email\": \"bob@example.com\", \"name\": \"Bob\""), Optional.empty())));
        // name absent: kept. email null: cleared, and with it the verified flag.
        asserter.execute(() -> declaration.apply(UserDeclaration.parse(declarationFor(tenant, baseline,
                "\"username\": \"bob\", \"email\": null"), Optional.empty())));
        asserter.assertThat(() -> profiles.find(realm, "sub-bob"),
                profile -> assertThat(profile).isEqualTo(new UserProfile(null, false, "Bob")));
        // A user that does not exist is a warning, not a failure.
        asserter.execute(() -> declaration.apply(UserDeclaration.parse(declarationFor(tenant, baseline,
                "\"username\": \"nobody\", \"email\": \"n@example.com\""), Optional.empty())));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("the schema refuses an address with white space or no @, and a padded name")
    void schemaRefusesMalformedValues(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID baseline = UUID.randomUUID();
        UserEntity badEmail = user(tenant, baseline, "carol", "sub-carol");
        badEmail.email = "carol at example.com";
        UserEntity badName = user(tenant, baseline, "dave", "sub-dave");
        badName.name = " Dave";
        asserter.assertFailedWith(() -> users.persist(tenant, badEmail),
                failure -> assertThat(messages(failure)).contains("ck_iam_user_email"));
        asserter.assertFailedWith(() -> users.persist(tenant, badName),
                failure -> assertThat(messages(failure)).contains("ck_iam_user_name"));
    }

    private static String messages(Throwable failure) {
        StringBuilder all = new StringBuilder();
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            all.append(cause.getMessage()).append(' ');
        }
        return all.toString();
    }

}
