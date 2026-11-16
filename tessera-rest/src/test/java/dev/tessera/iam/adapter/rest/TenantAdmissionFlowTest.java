package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.FakeTenantRegistry;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import dev.tessera.iam.application.AdmittedClientCredentialsUseCase;
import dev.tessera.iam.application.AdmittedRefreshUseCase;
import dev.tessera.iam.application.AdmittedTokenUseCase;
import dev.tessera.iam.application.port.in.ClientCredentialsUseCase;
import dev.tessera.iam.application.port.in.RefreshUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.arc.ClientProxy;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code POST /token} admits only a tenant the registry holds as active (ADR-IAM-003 D1): an
 * unregistered or suspended tenant gets {@code invalid_client} with nothing that tells it apart from
 * a failed authentication, and an unreadable registry is {@code 503}, never a default.
 */
@QuarkusTest
@DisplayName("POST /token — tenant registry admission")
class TenantAdmissionFlowTest {

    private static final String TENANT = FakeClientRepository.MACHINE_TENANT;

    @Inject
    FakeTenantRegistry registry;

    @Inject
    TokenUseCase tokens;

    @Inject
    RefreshUseCase refresh;

    @Inject
    ClientCredentialsUseCase clientCredentials;

    @AfterEach
    void restore() {
        registry.restore(TenantId.fromString(TENANT));
    }

    private static Response clientCredentialsRequest() {
        String basic = "Basic " + Base64.getEncoder().encodeToString(
                (FakeClientRepository.MACHINE_CLIENT_ID + ":" + FakeClientSecretVerifier.CORRECT_SECRET)
                        .getBytes(StandardCharsets.UTF_8));
        return given()
                .header("X-Tenant-Id", TENANT)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .header("Authorization", basic)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .when().post("/token");
    }

    @Test
    @DisplayName("a registered, active tenant is issued a token")
    void registeredTenant_isIssued() {
        clientCredentialsRequest().then().statusCode(200).body("access_token", Matchers.notNullValue());
    }

    @Test
    @DisplayName("an unregistered tenant gets invalid_client, worded as a failed authentication")
    void unregisteredTenant_isInvalidClient() {
        registry.unregister(TenantId.fromString(TENANT));
        clientCredentialsRequest().then().statusCode(401)
                .header("Cache-Control", "no-store")
                .body("error", Matchers.equalTo("invalid_client"))
                .body("error_description", Matchers.equalTo("client authentication failed"))
                .body("access_token", Matchers.nullValue());
    }

    @Test
    @DisplayName("a suspended tenant gets invalid_client")
    void suspendedTenant_isInvalidClient() {
        registry.suspend(TenantId.fromString(TENANT));
        clientCredentialsRequest().then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));
    }

    @Test
    @DisplayName("an unreadable registry is 503, never a token")
    void unreadableRegistry_is503() {
        registry.failReadsOf(TenantId.fromString(TENANT));
        clientCredentialsRequest().then().statusCode(503)
                .header("Cache-Control", "no-store")
                .body("access_token", Matchers.nullValue());
    }

    @Test
    @DisplayName("every grant that mints a token is wired through the admission")
    void everyMintingGrant_isAdmitted() {
        assertThat(ClientProxy.unwrap(tokens)).isInstanceOf(AdmittedTokenUseCase.class);
        assertThat(ClientProxy.unwrap(refresh)).isInstanceOf(AdmittedRefreshUseCase.class);
        assertThat(ClientProxy.unwrap(clientCredentials)).isInstanceOf(AdmittedClientCredentialsUseCase.class);
    }
}
