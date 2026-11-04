package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.tessera.iam.adapter.rest.support.DpopTestClient;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.RefreshToken;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.test.junit.QuarkusMock;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import io.smallrye.mutiny.Uni;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Reproduces the refresh downgrade over HTTP: a sender-constrained client's first access token
 * carries {@code cnf}, and the token a refresh mints for it does not.
 *
 * <p><strong>This test pins a defect. It asserts today's wrong behaviour, and ADR-IAM-009 removes
 * that behaviour.</strong> It passes only while the defect exists, so the change that implements
 * ADR-IAM-009 D2 makes it fail. That change deletes this class and replaces it with tests of the
 * rule: a refresh without the proof the family's binding requires is refused, and the rotated
 * token keeps the binding. Nothing here describes behaviour to preserve.
 */
@QuarkusTest
@DisplayName("Refresh downgrade probe: pins the defect ADR-IAM-009 removes")
class RefreshBindingDowngradeProbeTest {

    private static final String TOKEN_ENDPOINT = "https://issuer.test.example/token";
    private static final String ISSUER = "https://issuer.test.example";
    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final String MTLS_BOUND_CLIENT = "probe-confidential-with-refresh";
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The shared fake has no confidential client with the refresh grant; this one adds it. */
    public static class ProbeClients extends FakeClientRepository {
        @Override
        public Uni<Client> findByClientId(RealmKey realm, String clientId) {
            if (MTLS_BOUND_CLIENT.equals(clientId)) {
                return Uni.createFrom().item(new ConfidentialClient(
                        FakeClientRepository.CONFIDENTIAL_IDENTITY, realm,
                        Set.of(new AuthorizationCode(), new RefreshToken()),
                        ClientAuthMethod.CLIENT_SECRET_POST, Set.of(REDIRECT_URI)));
            }
            return super.findByClientId(realm, clientId);
        }
    }

    @BeforeEach
    void addTheConfidentialClient() {
        QuarkusMock.installMockForType(new ProbeClients(), ClientRepositoryPort.class);
    }

    @Test
    @DisplayName("mTLS-bound confidential client: the refreshed token has no cnf, with or without the certificate")
    void certificateBoundConfidentialClientIsDowngradedAtRefresh() {
        String tenant = UUID.randomUUID().toString();
        String verifier = newVerifier();
        Response first = request(tenant)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .formParam("grant_type", "authorization_code")
                .formParam("code", authorizeCode(tenant, MTLS_BOUND_CLIENT, verifier))
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", MTLS_BOUND_CLIENT)
                .formParam("client_secret", FakeClientSecretVerifier.CORRECT_SECRET)
                .formParam("code_verifier", verifier)
                .when().post("/token");
        first.then().statusCode(200);
        assertThat(cnfOf(first)).containsEntry("x5t#S256", TestClientCertificate.X5T_S256);

        // The certificate is presented again: nothing reads it, and the token is still unbound.
        Response withCertificate = refreshConfidential(tenant, first.jsonPath().getString("refresh_token"))
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .when().post("/token");
        withCertificate.then().statusCode(200);
        assertDowngraded(withCertificate);

        // No certificate at all: a holder of the refresh token and the secret needs nothing else.
        Response withoutCertificate =
                refreshConfidential(tenant, withCertificate.jsonPath().getString("refresh_token"))
                        .when().post("/token");
        withoutCertificate.then().statusCode(200);
        assertDowngraded(withoutCertificate);
    }

    @Test
    @DisplayName("DPoP-bound public client: the refreshed token has no cnf, and no proof or key is checked")
    void dpopBoundPublicClientIsDowngradedAtRefresh() {
        String tenant = UUID.randomUUID().toString();
        String client = FakeClientRepository.REFRESH_CLIENT_ID;
        DpopTestClient holder = new DpopTestClient();
        String verifier = newVerifier();
        Response first = request(tenant)
                .header("DPoP", holder.proof(TOKEN_ENDPOINT))
                .formParam("grant_type", "authorization_code")
                .formParam("code", authorizeCode(tenant, client, verifier))
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", client)
                .formParam("code_verifier", verifier)
                .when().post("/token");
        first.then().statusCode(200);
        assertThat(first.jsonPath().getString("token_type")).isEqualTo("DPoP");
        assertThat(cnfOf(first)).containsEntry("jkt", holder.jkt());

        // No proof at all: the refresh token alone is enough (RFC 9449 section 5 requires the same key).
        Response noProof = refreshPublic(tenant, client, first.jsonPath().getString("refresh_token"))
                .when().post("/token");
        noProof.then().statusCode(200);
        assertDowngraded(noProof);

        // A proof for another key: the holder of a stolen refresh token, with a key of its own.
        Response otherKey = refreshPublic(tenant, client, noProof.jsonPath().getString("refresh_token"))
                .header("DPoP", new DpopTestClient().proof(TOKEN_ENDPOINT))
                .when().post("/token");
        otherKey.then().statusCode(200);
        assertDowngraded(otherKey);
    }

    /** What a refresh mints today: Bearer, no {@code cnf}, no scope, no realm claims, {@code aud} the issuer. */
    private static void assertDowngraded(Response refreshed) {
        assertThat(refreshed.jsonPath().getString("token_type")).isEqualTo("Bearer");
        Map<String, Object> claims = accessTokenClaims(refreshed);
        assertThat(claims).doesNotContainKey("cnf").doesNotContainKey("realm_tenant");
        assertThat(claims.get("scope")).isEqualTo("");
        assertThat(claims.get("aud")).isEqualTo(ISSUER);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cnfOf(Response token) {
        Object cnf = accessTokenClaims(token).get("cnf");
        assertThat(cnf).as("cnf of the first access token").isInstanceOf(Map.class);
        return (Map<String, Object>) cnf;
    }

    private static Map<String, Object> accessTokenClaims(Response token) {
        String accessToken = token.jsonPath().getString("access_token");
        try {
            return JSON.readValue(B64URL_DEC.decode(accessToken.split("\\.")[1]), new TypeReference<>() { });
        } catch (Exception e) {
            throw new IllegalStateException("access token payload is not JSON", e);
        }
    }

    private static RequestSpecification refreshConfidential(String tenant, String refreshToken) {
        return refreshPublic(tenant, MTLS_BOUND_CLIENT, refreshToken)
                .formParam("client_secret", FakeClientSecretVerifier.CORRECT_SECRET);
    }

    private static RequestSpecification refreshPublic(String tenant, String client, String refreshToken) {
        assertThat(refreshToken).as("refresh token").isNotBlank();
        return request(tenant)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("client_id", client);
    }

    private static RequestSpecification request(String tenant) {
        return given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded");
    }

    private static String authorizeCode(String tenant, String client, String verifier) {
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                // A refresh family anchors on a UUID subject (TokenService#isUuid).
                .header("X-Subject-Id", UUID.randomUUID().toString())
                .queryParam("response_type", "code")
                .queryParam("client_id", client)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid offline_access")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("nonce", "no-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        authorize.then().statusCode(302);
        String query = URI.create(authorize.getHeader("Location")).getQuery();
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if ("code".equals(pair.substring(0, eq))) {
                return java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        throw new IllegalStateException("no code in redirect: " + query);
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }

    private static String newVerifier() {
        byte[] bytes = new byte[48];
        new java.security.SecureRandom().nextBytes(bytes);
        return B64URL.encodeToString(bytes);
    }

    private static String s256(String verifier) {
        try {
            return B64URL.encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
