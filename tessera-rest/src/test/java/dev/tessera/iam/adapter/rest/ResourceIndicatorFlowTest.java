package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.tessera.iam.adapter.rest.support.DpopTestClient;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Per-resource access-token audience over HTTP (ADR-IAM-009 D3, RFC 8707): {@code resource} at
 * {@code /authorize} and {@code /token}, rule A1 on the code grant, rule A2 on refresh, and the
 * issuer never in {@code aud}.
 */
@QuarkusTest
@DisplayName("RFC 8707 resource indicators — aud names the resource, never the issuer")
class ResourceIndicatorFlowTest {

    private static final String ISSUER = "https://issuer.test.example";
    private static final String TOKEN_ENDPOINT = ISSUER + "/token";
    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final String TWO = FakeClientRepository.TWO_RESOURCE_CLIENT_ID;
    private static final String A = FakeClientRepository.API_A;
    private static final String B = FakeClientRepository.API_B;
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper JSON = new ObjectMapper();

    private final String tenant = UUID.randomUUID().toString();

    // ------------------------------------------------------------------ rule A1, code grant

    @Test
    @DisplayName("a client with two resources gets the one it names at /token")
    void twoResources_namedAtToken() throws Exception {
        Code code = authorize(TWO, List.of());
        Response token = token(TWO, code, List.of(B));
        token.then().statusCode(200);
        assertThat(aud(token)).containsExactly(B);
    }

    @Test
    @DisplayName("a client with two resources naming none at /token is refused, not given the first")
    void twoResources_noneNamed_isInvalidTarget() {
        Code code = authorize(TWO, List.of());
        token(TWO, code, List.of()).then().statusCode(400)
                .body("error", Matchers.equalTo("invalid_target"))
                .body("access_token", Matchers.nullValue());
    }

    @Test
    @DisplayName("a grant narrowed to one resource at /authorize needs no name at /token")
    void narrowedAtAuthorize_singleCandidate() throws Exception {
        Code code = authorize(TWO, List.of(A));
        Response token = token(TWO, code, List.of());
        token.then().statusCode(200);
        assertThat(aud(token)).containsExactly(A);
    }

    @Test
    @DisplayName("a client with one registered resource gets it with no resource parameter")
    void oneResource_default() throws Exception {
        String client = FakeClientRepository.REFRESH_CLIENT_ID;
        Code code = authorize(client, List.of());
        Response token = token(client, code, List.of());
        token.then().statusCode(200);
        assertThat(aud(token)).containsExactly(FakeClientRepository.USER_API).doesNotContain(ISSUER);
    }

    @Test
    @DisplayName("a resource the grant does not hold is invalid_target at /token")
    void notGranted_atToken_isInvalidTarget() {
        Code code = authorize(TWO, List.of(A));
        token(TWO, code, List.of(B)).then().statusCode(400).body("error", Matchers.equalTo("invalid_target"));
    }

    @Test
    @DisplayName("more than one resource at /token is invalid_target")
    void twoNamedAtToken_isInvalidTarget() {
        Code code = authorize(TWO, List.of());
        token(TWO, code, List.of(A, B)).then().statusCode(400).body("error", Matchers.equalTo("invalid_target"));
    }

    // ------------------------------------------------------------------ /authorize

    @Test
    @DisplayName("an unregistered resource at /authorize is redirected back as invalid_target, with iss and state")
    void unregistered_atAuthorize_isInvalidTarget() {
        Response response = authorizeRequest(TWO, List.of("https://other.example")).when().get("/authorize");
        response.then().statusCode(302);
        Map<String, String> query = queryOf(response.getHeader("Location"));
        assertThat(query).containsEntry("error", "invalid_target").containsEntry("iss", ISSUER)
                .containsKey("state").doesNotContainKey("code");
    }

    @Test
    @DisplayName("a client registered for no resource obtains no token for a person")
    void noRegisteredResource_isInvalidTarget() {
        Response response = authorizeRequest(FakeClientRepository.NO_AUDIENCE_CLIENT_ID, List.of())
                .when().get("/authorize");
        response.then().statusCode(302);
        assertThat(queryOf(response.getHeader("Location")))
                .containsEntry("error", "invalid_target").doesNotContainKey("code");
    }

    // ------------------------------------------------------------------ rule A2, refresh

    @Test
    @DisplayName("a refresh names one granted resource; naming none with two is refused without spending the token")
    void refresh_choosesWithinTheGrant() throws Exception {
        Code code = authorize(TWO, List.of());
        Response first = token(TWO, code, List.of(A));
        first.then().statusCode(200);
        String refreshToken = first.jsonPath().getString("refresh_token");
        assertThat(refreshToken).isNotBlank();

        refresh(TWO, refreshToken, List.of()).then().statusCode(400).body("error", Matchers.equalTo("invalid_target"));
        refresh(TWO, refreshToken, List.of("https://other.example")).then().statusCode(400)
                .body("error", Matchers.equalTo("invalid_target"));

        Response refreshed = refresh(TWO, refreshToken, List.of(B));
        refreshed.then().statusCode(200);
        assertThat(aud(refreshed)).as("any resource of the original grant, never the issuer").containsExactly(B);
    }

    @Test
    @DisplayName("a refresh of a grant narrowed to one resource keeps that one")
    void refresh_neverWidens() throws Exception {
        Code code = authorize(TWO, List.of(A));
        Response first = token(TWO, code, List.of());
        first.then().statusCode(200);
        String refreshToken = first.jsonPath().getString("refresh_token");

        refresh(TWO, refreshToken, List.of(B)).then().statusCode(400).body("error", Matchers.equalTo("invalid_target"));
        Response refreshed = refresh(TWO, refreshToken, List.of());
        refreshed.then().statusCode(200);
        assertThat(aud(refreshed)).containsExactly(A);
    }

    // ------------------------------------------------------------------ helpers

    private record Code(String code, String verifier) {
    }

    private RequestSpecification authorizeRequest(String clientId, List<String> resources) {
        String verifier = newVerifier();
        RequestSpecification request = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("X-Subject-Id", UUID.randomUUID().toString())
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid offline_access")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256");
        for (String resource : resources) {
            request.queryParam("resource", resource);
        }
        return request;
    }

    private Code authorize(String clientId, List<String> resources) {
        String verifier = newVerifier();
        RequestSpecification request = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("X-Subject-Id", UUID.randomUUID().toString())
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid offline_access")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256");
        for (String resource : resources) {
            request.queryParam("resource", resource);
        }
        Response response = request.when().get("/authorize");
        response.then().statusCode(302);
        String code = queryOf(response.getHeader("Location")).get("code");
        assertThat(code).as("authorization code").isNotBlank();
        return new Code(code, verifier);
    }

    private Response token(String clientId, Code code, List<String> resources) {
        RequestSpecification request = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("DPoP", new DpopTestClient().proof(TOKEN_ENDPOINT))
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code.code())
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", clientId)
                .formParam("code_verifier", code.verifier());
        for (String resource : resources) {
            request.formParam("resource", resource);
        }
        return request.when().post("/token");
    }

    private Response refresh(String clientId, String refreshToken, List<String> resources) {
        RequestSpecification request = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("client_id", clientId);
        for (String resource : resources) {
            request.formParam("resource", resource);
        }
        return request.when().post("/token");
    }

    private static List<String> aud(Response token) throws Exception {
        String access = token.jsonPath().getString("access_token");
        JsonNode payload = JSON.readTree(Base64.getUrlDecoder().decode(access.split("\\.")[1]));
        JsonNode aud = payload.get("aud");
        if (aud.isTextual()) {
            return List.of(aud.asText());
        }
        return JSON.convertValue(aud, JSON.getTypeFactory().constructCollectionType(List.class, String.class));
    }

    private static Map<String, String> queryOf(String location) {
        Map<String, String> query = new HashMap<>();
        for (String pair : URI.create(location).getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            query.put(pair.substring(0, eq), URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return query;
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
