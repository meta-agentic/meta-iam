package dev.tessera.iam.launcher.support;

import dev.tessera.iam.adapter.persistence.tenancy.DbTenantRegistry;
import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.SecurityProfile;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.tenancy.TenantStatus;
import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The tenant registry for this module's tests. Under the Docker-free {@code %test} profile there is
 * no datasource, so the registry cannot be read, and the launcher's edge tests (headers, CORS, the
 * sign-in page's policy) would see {@code 503} where they test something else: there every tenant
 * is registered and active. Under {@link dev.tessera.iam.launcher.DatabaseBackedProfile} the
 * datasource is active and every lookup goes to the real {@link DbTenantRegistry}, so those tests
 * keep exercising the registry as deployed.
 */
@Mock
@ApplicationScoped
public class DatasourceFreeTenantRegistry implements TenantRegistryPort {

    @ConfigProperty(name = "quarkus.datasource.active", defaultValue = "true")
    boolean datasourceActive;

    @Inject
    DbTenantRegistry database;

    @Override
    public Uni<Optional<RegisteredTenant>> find(TenantId tenantId) {
        if (datasourceActive) {
            return database.find(tenantId);
        }
        return Uni.createFrom().item(Optional.of(
                new RegisteredTenant(tenantId, SecurityProfile.STANDARD, TenantStatus.ACTIVE)));
    }
}
