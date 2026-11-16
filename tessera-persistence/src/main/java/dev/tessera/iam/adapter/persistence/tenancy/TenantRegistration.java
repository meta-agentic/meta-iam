package dev.tessera.iam.adapter.persistence.tenancy;

import io.quarkus.flyway.FlywayConfigurationCustomizer;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.flywaydb.core.api.callback.Callback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.jboss.logging.Logger;

/**
 * Registers the declared tenants in the tenant registry at startup, as the administrative role
 * (ADR-IAM-009 D5, ADR-IAM-010 D2).
 *
 * <p>The application role cannot write the registry (V16), so this step runs on the connection the
 * schema migration runs on: it is a Flyway {@code afterMigrate} callback, executed after every
 * migration run, on the migration's own connection and role. The application's request path never
 * holds that connection.
 *
 * <p>What it registers: every tenant in {@code iam.tenancy.registered-tenants}, and the deployment's
 * fixed tenant ({@code iam.tenancy.fixed-tenant}) in single-tenant mode, since that deployment serves
 * exactly that tenant. A new tenant is registered at the {@code standard} profile and active. A tenant
 * already registered is left as it is: this step never changes a profile or a status. A value that
 * is not a UUID fails startup, so a typo never leaves a tenant silently unregistered.
 */
@ApplicationScoped
public class TenantRegistration implements FlywayConfigurationCustomizer {

    private static final Logger LOG = Logger.getLogger(TenantRegistration.class);

    static final String INSERT_IF_ABSENT =
            "INSERT INTO tenant (tenant_id) VALUES (?) ON CONFLICT (tenant_id) DO NOTHING";

    @Inject
    @ConfigProperty(name = "iam.tenancy.registered-tenants")
    Optional<List<String>> registeredTenants;

    @Inject
    @ConfigProperty(name = "iam.tenancy.fixed-tenant")
    Optional<String> fixedTenant;

    @Override
    public void customize(FluentConfiguration configuration) {
        Set<UUID> declared = declaredTenants(registeredTenants, fixedTenant);
        List<Callback> callbacks = new ArrayList<>(List.of(configuration.getCallbacks()));
        callbacks.add(new RegisterAfterMigrate(declared));
        configuration.callbacks(callbacks.toArray(Callback[]::new));
    }

    /**
     * The tenants to register: the declared list and the fixed tenant, each parsed as a UUID.
     *
     * @throws IllegalStateException if a value is not a UUID
     */
    static Set<UUID> declaredTenants(Optional<List<String>> registered, Optional<String> fixed) {
        Set<UUID> tenants = new LinkedHashSet<>();
        registered.orElse(List.of()).stream()
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .forEach(value -> tenants.add(parse(value, "iam.tenancy.registered-tenants")));
        fixed.map(String::trim)
                .filter(value -> !value.isEmpty())
                .ifPresent(value -> tenants.add(parse(value, "iam.tenancy.fixed-tenant")));
        return tenants;
    }

    private static UUID parse(String value, String property) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(property + " holds a value that is not a tenant UUID", e);
        }
    }

    /** Inserts each declared tenant that is not registered yet, after every migration run. */
    static final class RegisterAfterMigrate implements Callback {

        private final Set<UUID> tenants;

        RegisterAfterMigrate(Set<UUID> tenants) {
            this.tenants = Set.copyOf(tenants);
        }

        @Override
        public boolean supports(Event event, Context context) {
            return event == Event.AFTER_MIGRATE && !tenants.isEmpty();
        }

        @Override
        public boolean canHandleInTransaction(Event event, Context context) {
            return true;
        }

        @Override
        public void handle(Event event, Context context) {
            register(context.getConnection(), tenants);
        }

        @Override
        public String getCallbackName() {
            return "tessera-tenant-registration";
        }
    }

    /** Registers each tenant not registered yet; returns how many rows were added. */
    static int register(Connection connection, Set<UUID> tenants) {
        int added = 0;
        try (PreparedStatement insert = connection.prepareStatement(INSERT_IF_ABSENT)) {
            for (UUID tenant : tenants) {
                insert.setObject(1, tenant);
                int rows = insert.executeUpdate();
                if (rows > 0) {
                    LOG.infof("tenant registry: registered tenant %s at the standard profile", tenant);
                }
                added += rows;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("tenant registry: registering the declared tenants failed", e);
        }
        return added;
    }
}
