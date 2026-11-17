package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeUserProfiles;
import dev.tessera.iam.domain.authflow.UserProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The ID token carries {@code email}, {@code email_verified} and {@code name} exactly when the
 * granted scopes release them and the user record has them (OIDC Core §5.4), and discovery lists the
 * claims an ID token can carry.
 */
@QuarkusTest
@DisplayName("ID token — email, email_verified and name under the email and profile scopes")
class IdTokenProfileClaimsTest extends AuthorizationCodeFlowSupport {

    private static final String SUBJECT = "user-sub-profile";

    @Inject
    FakeUserProfiles profiles;

    @AfterEach
    void forget() {
        profiles.clear(SUBJECT);
    }

    private Map<String, Object> idTokenClaims(String scope) {
        String verifier = newVerifier();
        Response authorize = authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, scope, "state-1",
                null, s256(verifier), "S256", SUBJECT);
        authorize.then().statusCode(302);
        String code = queryOf(authorize.getHeader("Location")).get("code");
        Response token = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .header("DPoP", dpop.proof(TOKEN_ENDPOINT))
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", FakeClientRepository.PUBLIC_CLIENT_ID)
                .formParam("code_verifier", verifier)
                .when().post("/token");
        token.then().statusCode(200);
        return jsonPart(token.jsonPath().getString("id_token"), 1);
    }

    @Test
    @DisplayName("email and profile granted: email, email_verified and name are in the ID token")
    void bothScopes_releaseAllThree() {
        profiles.set(SUBJECT, new UserProfile("ada@example.com", true, "Ada Lovelace"));
        assertThat(idTokenClaims("openid email profile"))
                .containsEntry("email", "ada@example.com")
                .containsEntry("email_verified", true)
                .containsEntry("name", "Ada Lovelace")
                .containsKey("realm_tenant");
    }

    @Test
    @DisplayName("only email granted: no name; only profile granted: no email")
    void eachScope_releasesOnlyItsClaims() {
        profiles.set(SUBJECT, new UserProfile("ada@example.com", true, "Ada Lovelace"));
        assertThat(idTokenClaims("openid email"))
                .containsEntry("email", "ada@example.com").doesNotContainKey("name");
        assertThat(idTokenClaims("openid profile"))
                .containsEntry("name", "Ada Lovelace").doesNotContainKeys("email", "email_verified");
    }

    @Test
    @DisplayName("no email or profile scope, or no value on the user: the claims are absent, never empty")
    void absentScopeOrValue_leavesClaimsOut() {
        profiles.set(SUBJECT, new UserProfile("ada@example.com", true, "Ada Lovelace"));
        assertThat(idTokenClaims("openid")).doesNotContainKeys("email", "email_verified", "name");

        profiles.set(SUBJECT, UserProfile.EMPTY);
        assertThat(idTokenClaims("openid email profile")).doesNotContainKeys("email", "email_verified", "name");
    }

    @Test
    @DisplayName("discovery lists exactly the claims an ID token can carry")
    void discovery_listsTheClaims() {
        given().header("X-Tenant-Id", TENANT)
                .when().get("/.well-known/openid-configuration")
                .then().statusCode(200)
                .body("claims_supported", Matchers.equalTo(List.of(
                        "iss", "sub", "aud", "iat", "exp", "nonce", "realm_tenant", "realm_baseline",
                        "email", "email_verified", "name")));
    }
}
