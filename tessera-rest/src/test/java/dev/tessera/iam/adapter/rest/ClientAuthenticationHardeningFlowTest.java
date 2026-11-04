// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * A client authenticates only the way it is registered to, on every endpoint and grant that
 * authenticates one, and a {@code 401} after HTTP Basic says so (RFC 6749 §5.2).
 */
@QuarkusTest
@DisplayName("Client authentication — the registered method is enforced")
class ClientAuthenticationHardeningFlowTest extends AuthorizationCodeFlowSupport {

    private static final String SECRET = FakeClientSecretVerifier.CORRECT_SECRET;

    private static RequestSpecification request(String endpoint) {
        RequestSpecification request = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .contentType("application/x-www-form-urlencoded");
        return "/token".equals(endpoint)
                ? request.formParam("grant_type", "client_credentials")
                : request.formParam("token", "a.b.c");
    }

    private static Response viaBasic(String endpoint, String clientId, String secret) {
        String credentials = Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
        return request(endpoint).header("Authorization", "Basic " + credentials).when().post(endpoint);
    }

    private static Response viaBody(String endpoint, String clientId, String secret) {
        return request(endpoint).formParam("client_id", clientId).formParam("client_secret", secret)
                .when().post(endpoint);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/token", "/introspect", "/revoke"})
    @DisplayName("a client_secret_basic client authenticates by Basic only")
    void basicOnly(String endpoint) {
        viaBasic(endpoint, FakeClientRepository.BASIC_ONLY_CLIENT_ID, SECRET).then().statusCode(200);
        viaBody(endpoint, FakeClientRepository.BASIC_ONLY_CLIENT_ID, SECRET).then().statusCode(401)
                .header("WWW-Authenticate", nullValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/token", "/introspect", "/revoke"})
    @DisplayName("a client_secret_post client authenticates by the body only, and a Basic attempt is challenged")
    void postOnly(String endpoint) {
        viaBody(endpoint, FakeClientRepository.POST_ONLY_CLIENT_ID, SECRET).then().statusCode(200);
        viaBasic(endpoint, FakeClientRepository.POST_ONLY_CLIENT_ID, SECRET).then().statusCode(401)
                .header("WWW-Authenticate", startsWith("Basic"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/token", "/introspect", "/revoke"})
    @DisplayName("an mTLS client never authenticates by a secret, even the right one")
    void mtlsNeverBySecret(String endpoint) {
        viaBasic(endpoint, FakeClientRepository.MTLS_WITH_SECRET_CLIENT_ID, SECRET).then().statusCode(401);
        viaBody(endpoint, FakeClientRepository.MTLS_WITH_SECRET_CLIENT_ID, SECRET).then().statusCode(401);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/token", "/introspect", "/revoke"})
    @DisplayName("a wrong secret by Basic is challenged, and a wrong secret in the body is not")
    void wrongSecret(String endpoint) {
        viaBasic(endpoint, FakeClientRepository.BASIC_ONLY_CLIENT_ID, "wrong")
                .then().statusCode(401).header("WWW-Authenticate", startsWith("Basic"));
        viaBody(endpoint, FakeClientRepository.POST_ONLY_CLIENT_ID, "wrong")
                .then().statusCode(401).header("WWW-Authenticate", nullValue());
    }

    private String codeFor(String client, String verifier) {
        Response authorize = authorize(client, REDIRECT_URI, "openid", "state-hardening", null,
                s256(verifier), "S256", "alice");
        authorize.then().statusCode(302);
        return queryOf(authorize.getHeader("Location")).get("code");
    }

    @Test
    @DisplayName("the authorization_code grant enforces the method too")
    void authorizationCodeGrant() {
        String verifier = newVerifier();
        String code = codeFor(FakeClientRepository.BASIC_ONLY_CLIENT_ID, verifier);
        given().config(noFollow()).header("X-Tenant-Id", TENANT).contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code").formParam("code", code)
                .formParam("redirect_uri", REDIRECT_URI).formParam("code_verifier", verifier)
                .formParam("client_id", FakeClientRepository.BASIC_ONLY_CLIENT_ID).formParam("client_secret", SECRET)
                .when().post("/token").then().statusCode(401);

        String mtlsVerifier = newVerifier();
        String mtlsCode = codeFor(FakeClientRepository.MTLS_WITH_SECRET_CLIENT_ID, mtlsVerifier);
        given().config(noFollow()).header("X-Tenant-Id", TENANT).contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code").formParam("code", mtlsCode)
                .formParam("redirect_uri", REDIRECT_URI).formParam("code_verifier", mtlsVerifier)
                .formParam("client_id", FakeClientRepository.MTLS_WITH_SECRET_CLIENT_ID).formParam("client_secret", SECRET)
                .when().post("/token").then().statusCode(401);
    }
}
