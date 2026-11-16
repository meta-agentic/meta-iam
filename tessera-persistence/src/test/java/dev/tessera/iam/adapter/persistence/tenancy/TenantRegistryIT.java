package dev.tessera.iam.adapter.persistence.tenancy;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.persistence.PostgresIamTestResource;
import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.SecurityProfile;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.tenancy.TenantStatus;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import jakarta.inject.Inject;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.flywaydb.core.Flyway;
import org.hibernate.reactive.mutiny.Mutiny;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the tenant registry's contract against PostgreSQL under the three-role model
 * (ADR-IAM-003 D1 consequences 3 and 6): the application role reads it and cannot write it, the
 * migration role registers the declared tenants at startup, and the migration that adds it
 * registers every tenant that already had data.
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("Tenant registry — app role read-only, declared tenants registered, upgrade backfill")
class TenantRegistryIT {

    private static final TenantId DECLARED_1 = TenantId.fromString("7e5a0000-0000-4000-a000-000000000001");
    private static final TenantId DECLARED_2 = TenantId.fromString("7e5a0000-0000-4000-a000-000000000002");

    @Inject
    Mutiny.SessionFactory sessionFactory;

    @Inject
    DbTenantRegistry registry;

    @ConfigProperty(name = "quarkus.datasource.jdbc.url")
    String jdbcUrl;

    @Test
    @RunOnVertxContext
    @DisplayName("the declared tenants are registered at startup, standard and active")
    void declaredTenants_areRegistered(UniAsserter asserter) {
        asserter.assertThat(() -> registry.find(DECLARED_1), found -> assertThat(found)
                .contains(new RegisteredTenant(DECLARED_1, SecurityProfile.STANDARD, TenantStatus.ACTIVE)));
        asserter.assertThat(() -> registry.find(DECLARED_2), found -> assertThat(found).isPresent());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a tenant that was never registered is absent, not defaulted")
    void unknownTenant_isAbsent(UniAsserter asserter) {
        asserter.assertThat(() -> registry.find(TenantId.generate()),
                found -> assertThat(found).isEqualTo(Optional.empty()));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("the application role cannot insert into the registry")
    void appRole_cannotInsert(UniAsserter asserter) {
        asserter.assertFailedWith(() -> sessionFactory.withTransaction((session, tx) -> session
                        .createNativeQuery("INSERT INTO tenant (tenant_id) VALUES (:tid)")
                        .setParameter("tid", UUID.randomUUID())
                        .executeUpdate()),
                failure -> assertThat(rootMessage(failure)).containsIgnoringCase("permission denied"));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("the application role cannot update the registry")
    void appRole_cannotUpdate(UniAsserter asserter) {
        asserter.assertFailedWith(() -> sessionFactory.withTransaction((session, tx) -> session
                        .createNativeQuery("UPDATE tenant SET profile = 'fapi2' WHERE tenant_id = :tid")
                        .setParameter("tid", DECLARED_1.value())
                        .executeUpdate()),
                failure -> assertThat(rootMessage(failure)).containsIgnoringCase("permission denied"));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("the application role cannot delete from the registry")
    void appRole_cannotDelete(UniAsserter asserter) {
        asserter.assertFailedWith(() -> sessionFactory.withTransaction((session, tx) -> session
                        .createNativeQuery("DELETE FROM tenant WHERE tenant_id = :tid")
                        .setParameter("tid", DECLARED_2.value())
                        .executeUpdate()),
                failure -> assertThat(rootMessage(failure)).containsIgnoringCase("permission denied"));
    }

    @Test
    @DisplayName("registration as the migration role adds a tenant once and never changes one")
    void registration_isInsertIfAbsent() throws SQLException {
        UUID tenant = UUID.randomUUID();
        try (Connection migrator = DriverManager.getConnection(jdbcUrl, "iam_migrator", "iam_migrator")) {
            assertThat(TenantRegistration.register(migrator, Set.of(tenant))).isEqualTo(1);
            try (Statement suspend = migrator.createStatement()) {
                suspend.executeUpdate("UPDATE tenant SET status = 'suspended' WHERE tenant_id = '" + tenant + "'");
            }
            assertThat(TenantRegistration.register(migrator, Set.of(tenant))).isZero();
            assertThat(statusOf(migrator, tenant)).isEqualTo("suspended");
        }
    }

    @Test
    @DisplayName("the migration that adds the registry registers every tenant that already has data")
    void upgrade_registersExistingTenants() throws SQLException {
        String database = "tenant_backfill_" + UUID.randomUUID().toString().replace("-", "");
        try (Connection admin = DriverManager.getConnection(jdbcUrl, "iam", "iam");
                Statement ddl = admin.createStatement()) {
            ddl.execute("CREATE DATABASE " + database);
        }
        String url = jdbcUrl.replace("/iam_test", "/" + database);
        try (Connection admin = DriverManager.getConnection(url, "iam", "iam");
                Statement grant = admin.createStatement()) {
            grant.execute("GRANT CREATE, USAGE ON SCHEMA public TO iam_migrator");
        }
        Flyway before = Flyway.configure()
                .dataSource(url, "iam_migrator", "iam_migrator")
                .locations("classpath:db/migration")
                .target("15")
                .load();
        before.migrate();

        UUID withKey = UUID.randomUUID();
        UUID withClient = UUID.randomUUID();
        try (Connection migrator = DriverManager.getConnection(url, "iam_migrator", "iam_migrator")) {
            migrator.setAutoCommit(false);
            bind(migrator, withKey);
            try (Statement insert = migrator.createStatement()) {
                insert.executeUpdate("INSERT INTO signing_key (id, tenant_id, kid, algorithm, state, public_jwk,"
                        + " created_at) VALUES (gen_random_uuid(), '" + withKey + "', 'k1', 'EdDSA', 'ACTIVE',"
                        + " '{}', now())");
            }
            bind(migrator, withClient);
            try (Statement insert = migrator.createStatement()) {
                insert.executeUpdate("INSERT INTO oauth_client (id, tenant_id, baseline_id, client_key, client_type,"
                        + " allowed_grants, created_at) VALUES (gen_random_uuid(), '" + withClient + "', gen_random_uuid(), 'c1',"
                        + " 'PUBLIC', 'authorization_code', now())");
            }
            migrator.commit();
        }

        Flyway.configure().dataSource(url, "iam_migrator", "iam_migrator")
                .locations("classpath:db/migration").load().migrate();

        try (Connection migrator = DriverManager.getConnection(url, "iam_migrator", "iam_migrator")) {
            assertThat(statusOf(migrator, withKey)).isEqualTo("active");
            assertThat(statusOf(migrator, withClient)).isEqualTo("active");
            try (Statement check = migrator.createStatement();
                    ResultSet forced = check.executeQuery("SELECT bool_and(relforcerowsecurity) FROM pg_class"
                            + " WHERE relname IN ('signing_key', 'oauth_client', 'iam_user')")) {
                forced.next();
                assertThat(forced.getBoolean(1)).as("row-level security is forced again").isTrue();
            }
        }
    }

    private static void bind(Connection connection, UUID tenant) throws SQLException {
        try (PreparedStatement scope = connection.prepareStatement("SELECT set_config('app.tenant_id', ?, true)")) {
            scope.setString(1, tenant.toString());
            scope.execute();
        }
    }

    private static String statusOf(Connection connection, UUID tenant) throws SQLException {
        try (PreparedStatement read = connection.prepareStatement("SELECT status FROM tenant WHERE tenant_id = ?")) {
            read.setObject(1, tenant);
            try (ResultSet row = read.executeQuery()) {
                return row.next() ? row.getString(1) : null;
            }
        }
    }

    private static String rootMessage(Throwable failure) {
        Throwable cause = failure;
        StringBuilder messages = new StringBuilder();
        while (cause != null) {
            messages.append(cause.getMessage()).append(' ');
            cause = cause.getCause();
        }
        return messages.toString();
    }
}
