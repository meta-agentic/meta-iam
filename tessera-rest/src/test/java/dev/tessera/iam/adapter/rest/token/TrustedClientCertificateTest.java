// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("X-Client-Certificate — believed only behind an edge that says it strips it")
class TrustedClientCertificateTest {

    private static final String TENANT = "00000000-0000-0000-0000-000000000001";

    @Test
    @DisplayName("off by default: a spoofed certificate binds nothing")
    void ignoredByDefault() {
        assertThat(new TrustedClientCertificate(false, Optional.empty()).thumbprint(TestClientCertificate.PEM)).isNull();
    }

    @Test
    @DisplayName("turned on, in header mode: the certificate is read")
    void believedWhenTurnedOn() {
        assertThat(new TrustedClientCertificate(true, Optional.empty()).thumbprint(TestClientCertificate.PEM)).isNotBlank();
        assertThat(new TrustedClientCertificate(true, Optional.of("  ")).thumbprint(TestClientCertificate.PEM)).isNotBlank();
    }

    @Test
    @DisplayName("single-tenant mode ignores it whatever the setting, as it ignores the tenant headers")
    void ignoredInFixedTenantMode() {
        assertThat(new TrustedClientCertificate(true, Optional.of(TENANT)).thumbprint(TestClientCertificate.PEM)).isNull();
        assertThat(new TrustedClientCertificate(false, Optional.of(TENANT)).thumbprint(TestClientCertificate.PEM)).isNull();
    }
}
