package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.DpopTestClient;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.FakeTenantRegistry;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A suspended tenant (ADR-IAM-003 D1 consequence 2; ADR-IAM-011 D5, the suspended row): its tokens
 * introspect as inactive, its refreshes fail, {@code /authorize} and the sign-in pages answer a
 * {@code 403} page with no redirect, {@code /revoke} stays accepted and discovery stays up. An
 * unreadable registry is {@code 503} at each of these endpoints, never a default.
 */
@QuarkusTest
@DisplayName("A suspended tenant — introspection, refresh, sign-in")
class SuspendedTenantFlowTest {

    private static final String MACHINE_TENANT = FakeClientRepository.MACHINE_TENANT;
    private static final String REFRESH_CLIENT = FakeClientRepository.REFRESH_CLIENT_ID;
    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Inject
    FakeTenantRegistry registry;

    private final List<TenantId> touched = new ArrayList<>();

    @AfterEach
    void restore() {
        touched.forEach(registry::restore);
        touched.clear();
    }

    private void suspend(String tenant) {
        TenantId id = TenantId.fromString(tenant);
        touched.add(id);
        registry.suspend(id);
    }

    private void failReadsOf(String tenant) {
        TenantId id = TenantId.fromString(tenant);
        touched.add(id);
        registry.failReadsOf(id);
    }

    // ------------------------------------------------------------------ introspection and revocation

    @Test
    @DisplayName("an access token of a suspended tenant introspects as inactive")
    void accessToken_ofSuspendedTenant_isInactive() {
        String accessToken = machineAccessToken();
        introspect(accessToken).then().statusCode(200).body("active", Matchers.equalTo(true));

        suspend(MACHINE_TENANT);
        introspect(accessToken).then().statusCode(200)
                .header("Cache-Control", "no-store")
                .body("active", Matchers.equalTo(false))
                .body("sub", Matchers.nullValue())
                .body("client_id", Matchers.nullValue());
    }

    @Test
    @DisplayName("an unreadable registry at /introspect is 503, never an answer")
    void introspect_unreadableRegistry_is503() {
        String accessToken = machineAccessToken();
        failReadsOf(MACHINE_TENANT);
        introspect(accessToken).then().statusCode(503).body("active", Matchers.nullValue());
    }

    @Test
    @DisplayName("/revoke stays accepted for a suspended tenant")
    void revoke_ofSuspendedTenant_isAccepted() {
        String accessToken = machineAccessToken();
        suspend(MACHINE_TENANT);
        machineCall("/revoke", accessToken).then().statusCode(200);
    }

    // ------------------------------------------------------------------ refresh

    @Test
    @DisplayName("the refresh grant fails for a suspended tenant")
    void refresh_ofSuspendedTenant_isInvalidClient() {
        String tenant = UUID.randomUUID().toString();
        String refreshToken = initialRefreshToken(tenant);

        suspend(tenant);
        refresh(tenant, refreshToken).then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"))
                .body("access_token", Matchers.nullValue());
    }

    // ------------------------------------------------------------------ authorize and sign-in

    @Test
    @DisplayName("/authorize answers a suspended tenant with a 403 page and no redirect")
    void authorize_ofSuspendedTenant_is403PageWithoutRedirect() {
        String tenant = UUID.randomUUID().toString();
        suspend(tenant);
        Response response = authorize(tenant, UUID.randomUUID().toString());
        assertSuspendedPage(response);
    }

    @Test
    @DisplayName("/authorize for a suspended tenant shows the page before any sign-in")
    void authorize_ofSuspendedTenant_withoutSession_is403Page() {
        String tenant = UUID.randomUUID().toString();
        suspend(tenant);
        assertSuspendedPage(authorize(tenant, null));
    }

    @Test
    @DisplayName("the sign-in, login and consent pages answer a suspended tenant with the 403 page")
    void signInPages_ofSuspendedTenant_are403Page() {
        String tenant = UUID.randomUUID().toString();
        suspend(tenant);
        assertSuspendedPage(given().config(noFollow()).header("X-Tenant-Id", tenant)
                .queryParam("tx", "anything").when().get("/signin"));
        for (String path : new String[] {"/signin", "/signin/consent", "/login", "/consent"}) {
            assertSuspendedPage(given().config(noFollow()).header("X-Tenant-Id", tenant)
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("x", "y")
                    .when().post(path));
        }
    }

    @Test
    @DisplayName("an unreadable registry at /authorize is 503, never a redirect")
    void authorize_unreadableRegistry_is503() {
        String tenant = UUID.randomUUID().toString();
        failReadsOf(tenant);
        Response response = authorize(tenant, UUID.randomUUID().toString());
        response.then().statusCode(503);
        assertThat(response.getHeader("Location")).isNull();
    }

    @Test
    @DisplayName("an active tenant is unaffected at /authorize")
    void authorize_ofActiveTenant_redirects() {
        String tenant = UUID.randomUUID().toString();
        authorize(tenant, UUID.randomUUID().toString()).then().statusCode(302);
    }

    @Test
    @DisplayName("an unregistered tenant passes the sign-in check (refused at /token; 404 comes with the realm registry)")
    void authorize_ofUnregisteredTenant_isNotTheSuspendedPage() {
        String tenant = UUID.randomUUID().toString();
        TenantId id = TenantId.fromString(tenant);
        touched.add(id);
        registry.unregister(id);
        authorize(tenant, UUID.randomUUID().toString()).then().statusCode(302);
    }

    @Test
    @DisplayName("discovery and the key set keep answering a suspended tenant")
    void discoveryAndJwks_ofSuspendedTenant_are200() {
        String tenant = UUID.randomUUID().toString();
        suspend(tenant);
        given().header("X-Tenant-Id", tenant).when().get("/.well-known/openid-configuration")
                .then().statusCode(200);
        given().header("X-Tenant-Id", tenant).when().get("/jwks").then().statusCode(200);
    }

    // ------------------------------------------------------------------ helpers

    private static void assertSuspendedPage(Response response) {
        response.then().statusCode(403)
                .contentType(Matchers.startsWith("text/html"))
                .header("Cache-Control", "no-store")
                .header("Content-Security-Policy", Matchers.containsString("default-src 'none'"))
                .body(Matchers.containsString("Sign-in is unavailable"));
        assertThat(response.getHeader("Location")).as("no redirect to the client").isNull();
    }

    private static Response authorize(String tenant, String subject) {
        var request = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .queryParam("response_type", "code")
                .queryParam("client_id", REFRESH_CLIENT)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid offline_access")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("nonce", "no-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(newVerifier()))
                .queryParam("code_challenge_method", "S256");
        if (subject != null) {
            request.header("X-Subject-Id", subject);
        }
        return request.when().get("/authorize");
    }

    private static String initialRefreshToken(String tenant) {
        String verifier = newVerifier();
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("X-Subject-Id", UUID.randomUUID().toString())
                .queryParam("response_type", "code")
                .queryParam("client_id", REFRESH_CLIENT)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid offline_access")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("nonce", "no-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        authorize.then().statusCode(302);
        String code = codeOf(authorize.getHeader("Location"));
        Response token = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("DPoP", new DpopTestClient().proof("https://issuer.test.example/token"))
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", REFRESH_CLIENT)
                .formParam("code_verifier", verifier)
                .when().post("/token");
        token.then().statusCode(200);
        String refresh = token.jsonPath().getString("refresh_token");
        assertThat(refresh).as("initial refresh token").isNotBlank();
        return refresh;
    }

    private static Response refresh(String tenant, String refreshToken) {
        return given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("client_id", REFRESH_CLIENT)
                .when().post("/token");
    }

    private static String machineAccessToken() {
        String basic = "Basic " + Base64.getEncoder().encodeToString(
                (FakeClientRepository.MACHINE_CLIENT_ID + ":" + FakeClientSecretVerifier.CORRECT_SECRET)
                        .getBytes(StandardCharsets.UTF_8));
        Response token = given()
                .header("X-Tenant-Id", MACHINE_TENANT)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .header("Authorization", basic)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .when().post("/token");
        token.then().statusCode(200);
        return token.jsonPath().getString("access_token");
    }

    private static Response introspect(String token) {
        return machineCall("/introspect", token);
    }

    private static Response machineCall(String endpoint, String token) {
        return given()
                .header("X-Tenant-Id", MACHINE_TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token)
                .auth().preemptive().basic(FakeClientRepository.MACHINE_CLIENT_ID,
                        FakeClientSecretVerifier.CORRECT_SECRET)
                .when().post(endpoint);
    }

    private static String codeOf(String location) {
        for (String pair : URI.create(location).getQuery().split("&")) {
            int eq = pair.indexOf('=');
            if ("code".equals(pair.substring(0, eq))) {
                return URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        throw new IllegalStateException("no code in redirect: " + location);
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
