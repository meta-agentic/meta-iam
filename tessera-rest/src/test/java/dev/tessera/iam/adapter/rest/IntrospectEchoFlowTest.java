package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The active introspection response echoes {@code iss}, {@code aud}, {@code cnf} and the true
 * {@code token_type} (ADR-IAM-009 D3). A client that is no resource sees its own tokens. The
 * binding itself is not checked at introspection: the call carries no proof (RFC 9449 §6.2).
 */
@QuarkusTest
@DisplayName("POST /introspect — iss, aud, cnf and the true token_type are echoed")
class IntrospectEchoFlowTest {

    private static final String TENANT = FakeClientRepository.MACHINE_TENANT;
    private static final String BASIC = "Basic " + Base64.getEncoder().encodeToString(
            (FakeClientRepository.MACHINE_CLIENT_ID + ":" + FakeClientSecretVerifier.CORRECT_SECRET)
                    .getBytes(StandardCharsets.UTF_8));

    @Test
    @DisplayName("a certificate-bound token is Bearer with cnf.x5t#S256, active to its own client")
    void certificateBoundToken_isEchoed() {
        Response token = given()
                .header("X-Tenant-Id", TENANT)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .header("Authorization", BASIC)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .when().post("/token");
        token.then().statusCode(200);

        given()
                .header("X-Tenant-Id", TENANT)
                .header("Authorization", BASIC)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token.jsonPath().getString("access_token"))
                .when().post("/introspect")
                .then().statusCode(200)
                .body("active", Matchers.is(true))
                .body("token_type", Matchers.equalTo("Bearer"))
                .body("iss", Matchers.equalTo("https://issuer.test.example"))
                .body("aud", Matchers.notNullValue())
                .body("'cnf'.'x5t#S256'", Matchers.notNullValue());
    }
}
