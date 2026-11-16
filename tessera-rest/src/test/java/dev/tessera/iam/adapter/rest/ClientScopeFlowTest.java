// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A client may ask a person only for the scopes it registered for the authorization-code grant,
 * besides {@code openid}. Anything else is refused at {@code /authorize} as {@code invalid_scope},
 * redirected to the client (its redirect URI is validated by then), before any sign-in or consent.
 */
@QuarkusTest
@DisplayName("/authorize — a client gets only the scopes it registered (invalid_scope otherwise)")
class ClientScopeFlowTest extends AuthorizationCodeFlowSupport {

    private static void assertInvalidScope(Response response, String state) {
        response.then().statusCode(302);
        String location = response.getHeader("Location");
        assertThat(location).startsWith(REDIRECT_URI + "?");
        Map<String, String> query = queryOf(location);
        assertThat(query).containsEntry("error", "invalid_scope")
                .containsEntry("state", state)
                .containsEntry("iss", ISSUER)
                .doesNotContainKey("code");
    }

    @Test
    @DisplayName("signed out: an unregistered scope is redirected as invalid_scope instead of reaching the sign-in page")
    void signedOutUnregisteredScope() {
        Response response = authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid admin.all",
                "state-out", null, s256(newVerifier()), "S256", null);
        assertInvalidScope(response, "state-out");
    }

    @Test
    @DisplayName("signed in: an unregistered scope is redirected as invalid_scope, with no code")
    void signedInUnregisteredScope() {
        Response response = authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid profile admin.all",
                "state-in", null, s256(newVerifier()), "S256", "user-sub-scope");
        assertInvalidScope(response, "state-in");
    }

    @Test
    @DisplayName("registered scopes and openid alone still reach a code")
    void registeredScopesPass() {
        authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid profile email", "state-ok", null,
                s256(newVerifier()), "S256", "user-sub-scope").then().statusCode(302);
        Response openidOnly = authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid", "state-oid",
                null, s256(newVerifier()), "S256", "user-sub-scope");
        assertThat(queryOf(openidOnly.getHeader("Location"))).containsKey("code");
    }

    @Test
    @DisplayName("an unregistered redirect URI is still a 400, never a redirect, whatever the scope")
    void redirectCheckComesFirst() {
        authorize(FakeClientRepository.PUBLIC_CLIENT_ID, "https://evil.example/cb", "openid admin.all", "state-evil",
                null, s256(newVerifier()), "S256", null)
                .then().statusCode(400).header("Location", org.hamcrest.Matchers.nullValue());
    }
}
