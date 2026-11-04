// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.domain.client;

import static dev.tessera.iam.domain.client.ClientSecretPresentation.BASIC;
import static dev.tessera.iam.domain.client.ClientSecretPresentation.POST;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@DisplayName("Client authentication method — which secret presentation each one accepts")
class ClientAuthMethodTest {

    @Test
    void secretMethods() {
        assertThat(ClientAuthMethod.CLIENT_SECRET_BASIC.acceptsSecret(BASIC)).isTrue();
        assertThat(ClientAuthMethod.CLIENT_SECRET_BASIC.acceptsSecret(POST)).isFalse();
        assertThat(ClientAuthMethod.CLIENT_SECRET_POST.acceptsSecret(POST)).isTrue();
        assertThat(ClientAuthMethod.CLIENT_SECRET_POST.acceptsSecret(BASIC)).isFalse();
        assertThat(ClientAuthMethod.CLIENT_SECRET.acceptsSecret(BASIC)).isTrue();
        assertThat(ClientAuthMethod.CLIENT_SECRET.acceptsSecret(POST)).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = ClientAuthMethod.class, names = {"MTLS", "PRIVATE_KEY_JWT", "WORKLOAD_IDENTITY"})
    @DisplayName("a method that holds no secret accepts none, however it is presented")
    void noSecretMethods(ClientAuthMethod method) {
        assertThat(method.holdsSecret()).isFalse();
        assertThat(method.acceptsSecret(BASIC)).isFalse();
        assertThat(method.acceptsSecret(POST)).isFalse();
    }
}
