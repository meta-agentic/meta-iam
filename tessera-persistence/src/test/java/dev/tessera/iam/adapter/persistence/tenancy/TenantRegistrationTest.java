package dev.tessera.iam.adapter.persistence.tenancy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("TenantRegistration — which tenants a startup registers")
class TenantRegistrationTest {

    private static final UUID A = UUID.fromString("7e5a0000-0000-4000-a000-00000000000a");
    private static final UUID B = UUID.fromString("7e5a0000-0000-4000-a000-00000000000b");

    @Test
    @DisplayName("the declared list and the fixed tenant, trimmed, once each")
    void declaredAndFixed() {
        assertThat(TenantRegistration.declaredTenants(
                Optional.of(List.of(" " + A + " ", "", B.toString())), Optional.of(A.toString())))
                .containsExactly(A, B);
    }

    @Test
    @DisplayName("nothing declared registers nothing")
    void nothingDeclared() {
        assertThat(TenantRegistration.declaredTenants(Optional.empty(), Optional.of("  "))).isEmpty();
    }

    @Test
    @DisplayName("a value that is not a UUID fails startup, naming the property")
    void malformedFails() {
        assertThatThrownBy(() -> TenantRegistration.declaredTenants(Optional.of(List.of("acme")), Optional.empty()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("iam.tenancy.registered-tenants");
        assertThatThrownBy(() -> TenantRegistration.declaredTenants(Optional.empty(), Optional.of("acme")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("iam.tenancy.fixed-tenant");
    }
}
