package dev.tessera.iam.adapter.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * V19 (ADR-IAM-009 D3) over a database that already holds clients of two tenants: every existing
 * client gets an empty {@code user_audiences} and no {@code resource_identifier}, whatever its
 * tenant, and the refresh family gains a nullable {@code granted_resources}. Row-level security
 * stays forced on both tables.
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("V19 — per-resource audience columns over existing rows of two tenants")
class PerResourceAudienceMigrationIT {

    @ConfigProperty(name = "quarkus.datasource.jdbc.url")
    String jdbcUrl;

    @Test
    @DisplayName("existing clients of every tenant get an empty user_audiences and no resource_identifier")
    void existingClients_ofEveryTenant_getEmptyAudiences() throws SQLException {
        String database = "audience_upgrade_" + UUID.randomUUID().toString().replace("-", "");
        try (Connection admin = DriverManager.getConnection(jdbcUrl, "iam", "iam");
                Statement ddl = admin.createStatement()) {
            ddl.execute("CREATE DATABASE " + database);
        }
        String url = jdbcUrl.replace("/iam_test", "/" + database);
        try (Connection admin = DriverManager.getConnection(url, "iam", "iam");
                Statement grant = admin.createStatement()) {
            grant.execute("GRANT CREATE, USAGE ON SCHEMA public TO iam_migrator");
        }
        Flyway.configure()
                .dataSource(url, "iam_migrator", "iam_migrator")
                .locations("classpath:db/migration")
                .target("18")
                .load()
                .migrate();

        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        try (Connection migrator = DriverManager.getConnection(url, "iam_migrator", "iam_migrator")) {
            migrator.setAutoCommit(false);
            for (UUID tenant : new UUID[] {tenantA, tenantB}) {
                bind(migrator, tenant);
                try (Statement insert = migrator.createStatement()) {
                    insert.executeUpdate("INSERT INTO oauth_client (id, tenant_id, baseline_id, client_key,"
                            + " client_type, allowed_grants, user_scopes, created_at) VALUES (gen_random_uuid(), '"
                            + tenant + "', '00000000-0000-0000-0000-000000000000', 'spa', 'PUBLIC',"
                            + " 'authorization_code', 'profile', now())");
                }
            }
            migrator.commit();
        }

        Flyway.configure().dataSource(url, "iam_migrator", "iam_migrator")
                .locations("classpath:db/migration").load().migrate();

        try (Connection migrator = DriverManager.getConnection(url, "iam_migrator", "iam_migrator")) {
            migrator.setAutoCommit(false);
            for (UUID tenant : new UUID[] {tenantA, tenantB}) {
                bind(migrator, tenant);
                try (Statement read = migrator.createStatement();
                        ResultSet row = read.executeQuery(
                                "SELECT user_audiences, resource_identifier, user_scopes FROM oauth_client")) {
                    assertThat(row.next()).as("tenant %s still sees exactly its client", tenant).isTrue();
                    assertThat(row.getString(1)).isEmpty();
                    assertThat(row.getString(2)).isNull();
                    assertThat(row.getString(3)).as("other columns untouched").isEqualTo("profile");
                    assertThat(row.next()).as("and only its own").isFalse();
                }
            }
            migrator.commit();
            try (Statement check = migrator.createStatement();
                    ResultSet column = check.executeQuery("SELECT is_nullable FROM information_schema.columns"
                            + " WHERE table_name = 'refresh_token_family' AND column_name = 'granted_resources'")) {
                assertThat(column.next()).as("granted_resources exists").isTrue();
                assertThat(column.getString(1)).as("nullable until the cut-over").isEqualTo("YES");
            }
            try (Statement check = migrator.createStatement();
                    ResultSet forced = check.executeQuery("SELECT bool_and(relforcerowsecurity) FROM pg_class"
                            + " WHERE relname IN ('oauth_client', 'refresh_token_family')")) {
                forced.next();
                assertThat(forced.getBoolean(1)).as("row-level security stays forced").isTrue();
            }
        }
    }

    private static void bind(Connection connection, UUID tenant) throws SQLException {
        try (PreparedStatement scope = connection.prepareStatement("SELECT set_config('app.tenant_id', ?, true)")) {
            scope.setString(1, tenant.toString());
            scope.execute();
        }
    }
}
