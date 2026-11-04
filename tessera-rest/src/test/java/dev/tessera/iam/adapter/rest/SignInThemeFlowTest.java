// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

import dev.tessera.iam.adapter.rest.signin.SignInCookies;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import java.net.URI;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@QuarkusTest
@DisplayName("Sign-in themes — the page shows the theme its client names, and no other")
class SignInThemeFlowTest extends AuthorizationCodeFlowSupport {

    private static final String ACME = "assets/themes/acme/theme.css";
    private static final String ZENITH = "assets/themes/zenith/theme.css";

    private Response pageFor(String clientId, String extraQuery) {
        String verifier = newVerifier();
        Response authorize = authorize(clientId, REDIRECT_URI, "openid", "state-theme", null,
                s256(verifier), "S256", null);
        authorize.then().statusCode(303);
        URI location = URI.create(authorize.getHeader("Location"));
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .cookie(SignInCookies.NAME, authorize.getCookie(SignInCookies.NAME))
                .when().get(location.getPath() + "?" + location.getRawQuery() + extraQuery);
    }

    @Test
    @DisplayName("a client gets the theme it names, and not another client's")
    void clientGetsItsOwnTheme() {
        String acme = pageFor(FakeClientRepository.ACME_THEME_CLIENT_ID, "").then().statusCode(200)
                .extract().asString();
        assertThat(acme).contains(ACME, "assets/signin.css").doesNotContain(ZENITH);
        String zenith = pageFor(FakeClientRepository.ZENITH_THEME_CLIENT_ID, "").then().statusCode(200)
                .extract().asString();
        assertThat(zenith).contains(ZENITH).doesNotContain(ACME);
    }

    @Test
    @DisplayName("a theme parameter on the request has no effect")
    void requestCannotChooseATheme() {
        String page = pageFor(FakeClientRepository.ACME_THEME_CLIENT_ID, "&theme=zenith").then().statusCode(200)
                .extract().asString();
        assertThat(page).contains(ACME).doesNotContain(ZENITH);
        String unthemed = pageFor(FakeClientRepository.PUBLIC_CLIENT_ID, "&theme=zenith").then().statusCode(200)
                .extract().asString();
        assertThat(unthemed).doesNotContain("assets/themes/");
    }

    @Test
    @DisplayName("a client with no theme, or one the deployment lacks, gets a working neutral page")
    void neutralPage() {
        for (String client : new String[] {
                FakeClientRepository.PUBLIC_CLIENT_ID, FakeClientRepository.MISSING_THEME_CLIENT_ID}) {
            String page = pageFor(client, "").then().statusCode(200).extract().asString();
            assertThat(page).contains("assets/signin.css", "name=\"csrf\"").doesNotContain("assets/themes/");
        }
    }

    @Test
    @DisplayName("a page with no known client is the neutral page")
    void noKnownClient() {
        String page = given().header("X-Tenant-Id", TENANT).when().get("/signin").then().statusCode(400)
                .extract().asString();
        assertThat(page).doesNotContain("assets/themes/");
    }

    @Test
    @DisplayName("the form's policy allows same-origin fonts and images, and adds nothing else")
    void policy() {
        pageFor(FakeClientRepository.ACME_THEME_CLIENT_ID, "").then()
                .header("Content-Security-Policy", equalTo(
                        "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'"
                                + "; font-src 'self'; img-src 'self'; form-action 'self' https://client.example"));
    }

    @Test
    @DisplayName("a theme's files are served from memory with their types; nothing else is")
    void assets() {
        given().when().get("/assets/themes/acme/theme.css").then().statusCode(200)
                .contentType(startsWith("text/css")).body(containsString("acme test theme"));
        given().when().get("/assets/themes/acme/mark.png").then().statusCode(200).contentType("image/png");
        given().when().get("/assets/themes/acme/fonts/test.woff2").then().statusCode(200).contentType("font/woff2");
        given().when().get("/assets/themes/acme/absent.css").then().statusCode(404);
        given().when().get("/assets/themes/gone/theme.css").then().statusCode(404);
        given().urlEncodingEnabled(false).when().get("/assets/themes/acme/..%2f..%2f..%2fapplication.properties")
                .then().statusCode(404);
        given().urlEncodingEnabled(false).when().get("/assets/themes/acme/%2e%2e/%2e%2e/%2e%2e/application.properties")
                .then().statusCode(404);
    }
}
