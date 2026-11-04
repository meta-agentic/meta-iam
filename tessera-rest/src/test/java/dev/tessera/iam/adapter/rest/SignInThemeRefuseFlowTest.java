// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;

import dev.tessera.iam.adapter.rest.signin.SignInCookies;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@QuarkusTest
@TestProfile(SignInThemeRefuseFlowTest.Refuse.class)
@DisplayName("Sign-in themes — iam.signin.themes.unthemed=refuse shows no form")
class SignInThemeRefuseFlowTest extends AuthorizationCodeFlowSupport {

    public static class Refuse implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("iam.signin.themes.unthemed", "refuse");
        }
    }

    @Test
    @DisplayName("a client with no theme gets a 503 that says it is a setup problem, with no form and no token")
    void refuses() {
        Response authorize = authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid",
                "state-refuse", null, s256(newVerifier()), "S256", null);
        URI location = URI.create(authorize.getHeader("Location"));
        String page = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .cookie(SignInCookies.NAME, authorize.getCookie(SignInCookies.NAME))
                .when().get(location.getPath() + "?" + location.getRawQuery())
                .then().statusCode(503)
                .header("Content-Security-Policy", containsString("form-action 'none'"))
                .extract().asString();
        assertThat(page).contains("Sign-in is unavailable", "operator").doesNotContain("<form", "csrf", "expired");
    }
}
