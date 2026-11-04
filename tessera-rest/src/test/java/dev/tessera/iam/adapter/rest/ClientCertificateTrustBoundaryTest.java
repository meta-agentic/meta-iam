// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@QuarkusTest
@TestProfile(ClientCertificateTrustBoundaryTest.ProductionDefault.class)
@DisplayName("X-Client-Certificate under the production default — a spoofed certificate binds nothing")
class ClientCertificateTrustBoundaryTest {

    public static class ProductionDefault implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "iam.client-certificate.trust-header", "false",
                    "iam.authflow.require-sender-constraint", "false");
        }
    }

    @Test
    @DisplayName("a client that sends the header gets a token with no cnf")
    void spoofedHeaderIsIgnored() {
        Response response = given()
                .header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .auth().preemptive().basic(FakeClientRepository.MACHINE_CLIENT_ID, FakeClientSecretVerifier.CORRECT_SECRET)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .when().post("/token");
        response.then().statusCode(200);
        String payload = response.jsonPath().getString("access_token").split("\\.")[1];
        assertThat(new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8)).doesNotContain("\"cnf\"");
    }
}
