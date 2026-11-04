// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Decides whether the {@value ClientCertificateThumbprint#HEADER} header is believed. It says which
 * certificate a request presented, and only a TLS-terminating edge that strips any client-supplied
 * value can know that, so it is ignored unless a deployment says it has one
 * ({@code iam.client-certificate.trust-header}, default {@code false}), as {@code X-Subject-Id} is.
 *
 * <p>Believed blindly, any caller could bind a token to any public certificate. A deployment in
 * single-tenant mode ignores the tenant headers because nothing is known to strip them, so it ignores
 * this one too, whatever the setting.
 */
@ApplicationScoped
public class TrustedClientCertificate {

    private final boolean trusted;

    @Inject
    TrustedClientCertificate(
            @ConfigProperty(name = "iam.client-certificate.trust-header", defaultValue = "false") boolean trustHeader,
            @ConfigProperty(name = "iam.tenancy.fixed-tenant") Optional<String> fixedTenant) {
        this.trusted = trustHeader && fixedTenant.map(String::trim).filter(value -> !value.isEmpty()).isEmpty();
    }

    /** For CDI's client proxy. */
    TrustedClientCertificate() {
        this.trusted = false;
    }

    /**
     * The thumbprint of the certificate the edge asserted.
     *
     * @param headerValue the header's value, or {@code null}
     * @return the thumbprint, or {@code null} when the header is not believed, absent or unparseable
     */
    public String thumbprint(String headerValue) {
        return trusted ? ClientCertificateThumbprint.fromHeader(headerValue).orElse(null) : null;
    }
}
