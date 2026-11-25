package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.tessera.iam.adapter.rest.support.DpopTestClient;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.token.JwsTokenSignerAdapter;
import dev.tessera.iam.domain.token.ClaimSet;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * ADR-IAM-003 D4b: every access token carries the realm it was minted in ({@code realm_tenant},
 * {@code realm_baseline}), on the code grant and on refresh as on {@code client_credentials}, and
 * introspection reports it active only in that realm. The signer refuses an access token without
 * them, so a mint path that skipped the stamp fails instead of issuing one.
 */
@QuarkusTest
@DisplayName("Realm claims on every access token, compared at introspection (ADR-IAM-003 D4b)")
class RealmClaimsFlowTest {

    private static final String TOKEN_ENDPOINT = "https://issuer.test.example/token";
    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final String CLIENT = FakeClientRepository.REFRESH_CLIENT_ID;
    private static final String ZERO = new UUID(0L, 0L).toString();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper JSON = new ObjectMapper();

    private final String tenant = UUID.randomUUID().toString();

    @Inject
    JwsTokenSignerAdapter signer;

    @Test
    @DisplayName("a code-grant access token names its realm, and so does the refreshed one")
    void bothMintPaths_stampTheRealm() throws Exception {
        Response token = codeGrantToken();
        assertRealm(token);

        Response refreshed = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", token.jsonPath().getString("refresh_token"))
                .formParam("client_id", CLIENT)
                .when().post("/token");
        refreshed.then().statusCode(200);
        assertRealm(refreshed);
    }

    @Test
    @DisplayName("the code-grant token is active in its realm and inactive at another baseline of the tenant")
    void introspection_comparesTheFullRealm() {
        String accessToken = codeGrantToken().jsonPath().getString("access_token");

        introspect(accessToken, ZERO).then().statusCode(200).body("active", Matchers.equalTo(true));
        introspect(accessToken, UUID.randomUUID().toString()).then().statusCode(200)
                .body("active", Matchers.equalTo(false));
    }

    @Test
    @DisplayName("the signer refuses an access token whose claims do not name the realm it is signed in")
    void signer_refusesAnUnstampedAccessToken() {
        RealmKey realm = new RealmKey(new TenantId(UUID.fromString(tenant)), new BaselineId(new UUID(0L, 0L)));
        ClaimSet unstamped = new ClaimSet(Map.of("sub", "s", "client_id", CLIENT));
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> signer.sign(realm, "at+jwt", unstamped))
                .isInstanceOf(IllegalStateException.class);
        ClaimSet otherBaseline = new ClaimSet(Map.of("sub", "s",
                "realm_tenant", tenant, "realm_baseline", UUID.randomUUID().toString()));
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> signer.sign(realm, "at+jwt", otherBaseline))
                .isInstanceOf(IllegalStateException.class);
    }

    private void assertRealm(Response token) throws Exception {
        String access = token.jsonPath().getString("access_token");
        JsonNode payload = JSON.readTree(Base64.getUrlDecoder().decode(access.split("\\.")[1]));
        assertThat(payload.path("realm_tenant").asText()).isEqualTo(tenant);
        assertThat(payload.path("realm_baseline").asText()).isEqualTo(ZERO);
    }

    private Response codeGrantToken() {
        String verifier = newVerifier();
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("X-Subject-Id", UUID.randomUUID().toString())
                .queryParam("response_type", "code")
                .queryParam("client_id", CLIENT)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid offline_access")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        authorize.then().statusCode(302);
        String code = null;
        for (String pair : URI.create(authorize.getHeader("Location")).getRawQuery().split("&")) {
            if (pair.startsWith("code=")) {
                code = URLDecoder.decode(pair.substring(5), StandardCharsets.UTF_8);
            }
        }
        Response token = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("DPoP", new DpopTestClient().proof(TOKEN_ENDPOINT))
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", CLIENT)
                .formParam("code_verifier", verifier)
                .when().post("/token");
        token.then().statusCode(200);
        return token;
    }

    private Response introspect(String token, String baseline) {
        return given()
                .header("X-Tenant-Id", tenant)
                .header("X-Baseline-Id", baseline)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token)
                .formParam("client_id", FakeClientRepository.CONFIDENTIAL_CLIENT_ID)
                .formParam("client_secret", FakeClientSecretVerifier.CORRECT_SECRET)
                .when().post("/introspect");
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }

    private static String newVerifier() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
        return B64URL.encodeToString(bytes);
    }

    private static String s256(String verifier) {
        try {
            return B64URL.encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
