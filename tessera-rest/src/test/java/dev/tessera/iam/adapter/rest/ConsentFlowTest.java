// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

import dev.tessera.iam.adapter.rest.session.SessionCookies;
import dev.tessera.iam.adapter.rest.signin.SignInCookies;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeConsentStore;
import dev.tessera.iam.adapter.rest.support.FakePasswordCredentialVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.net.URI;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Consent is enforced at {@code /authorize} for every client: a code is issued only for a user who
 * consented to the client for every requested scope. Without it, the hosted page asks under the
 * same transaction; allow records the consent and answers with a code, deny answers with
 * {@code access_denied}. Covers both ways in: signing in on the page, and arriving signed in.
 */
@QuarkusTest
@DisplayName("Consent — no code without the user's consent to the client and every requested scope")
class ConsentFlowTest extends AuthorizationCodeFlowSupport {

    private static final Pattern CSRF = Pattern.compile("name=\"csrf\" value=\"([^\"]+)\"");

    @Inject
    FakeConsentStore consents;

    private record Started(String transactionId, String binding, String verifier) {
    }

    @BeforeEach
    void strictConsent() {
        consents.requireConsent(FakePasswordCredentialVerifier.CONSENT_SUBJECT);
        consents.forget(FakePasswordCredentialVerifier.CONSENT_SUBJECT);
    }

    private Started park(Response authorize, String verifier) {
        authorize.then().statusCode(303).header("Cache-Control", "no-store");
        URI location = URI.create(authorize.getHeader("Location"));
        assertThat(location.getPath()).isEqualTo("/signin");
        return new Started(queryOf(location.toString()).get("txn"), authorize.getCookie(SignInCookies.NAME), verifier);
    }

    /** /authorize with no signed-in user: parked for sign-in. */
    private Started startSignedOut(String scope, String state) {
        String verifier = newVerifier();
        return park(authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, scope, state, null,
                s256(verifier), "S256", null), verifier);
    }

    private Response page(Started started) {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .cookie(SignInCookies.NAME, started.binding())
                .queryParam("txn", started.transactionId())
                .when().get("/signin");
    }

    private static String csrfOf(Response page) {
        Matcher m = CSRF.matcher(page.asString());
        assertThat(m.find()).as("the page carries a synchronizer token").isTrue();
        return m.group(1);
    }

    private Response signInAsConsentUser(Started started) {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .header("Sec-Fetch-Site", "same-origin")
                .cookie(SignInCookies.NAME, started.binding())
                .contentType("application/x-www-form-urlencoded")
                .formParam("txn", started.transactionId())
                .formParam("csrf", csrfOf(page(started)))
                .formParam("username", FakePasswordCredentialVerifier.CONSENT_USERNAME)
                .formParam("password", FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .when().post("/signin");
    }

    private Response answer(Started started, String binding, String csrf, String fetchSite, String decision) {
        var req = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("txn", started.transactionId())
                .formParam("decision", decision);
        if (binding != null) {
            req.cookie(SignInCookies.NAME, binding);
        }
        if (csrf != null) {
            req.formParam("csrf", csrf);
        }
        if (fetchSite != null) {
            req.header("Sec-Fetch-Site", fetchSite);
        }
        return req.when().post("/signin/consent");
    }

    @Test
    @DisplayName("sign in without consent: the page asks instead of redirecting; allow returns a code that redeems")
    void signInAskThenAllow() {
        Started started = startSignedOut("openid", "state-allow");

        Response asked = signInAsConsentUser(started);

        asked.then().statusCode(200)
                .contentType(containsString("text/html"))
                .header("Cache-Control", "no-store")
                .header("Content-Security-Policy", org.hamcrest.Matchers.endsWith("form-action 'self' https://client.example"))
                .body(containsString("action=\"signin/consent\""))
                .body(containsString(FakeClientRepository.PUBLIC_CLIENT_ID))
                .body(containsString("<li>openid</li>"))
                .body(not(containsString("code=")));
        assertThat(asked.getCookie(SessionCookies.NAME)).as("the sign-in itself succeeded").isNotBlank();

        Response allowed = answer(started, started.binding(), csrfOf(asked), "same-origin", "allow");

        allowed.then().statusCode(303);
        Map<String, String> query = queryOf(allowed.getHeader("Location"));
        assertThat(allowed.getHeader("Location")).startsWith(REDIRECT_URI + "?");
        assertThat(query).containsEntry("state", "state-allow").containsEntry("iss", ISSUER).containsKey("code");
        assertThat(allowed.getDetailedCookie(SignInCookies.NAME).getMaxAge()).isZero();
        tokenWithDpop(FakeClientRepository.PUBLIC_CLIENT_ID, query.get("code"), REDIRECT_URI,
                started.verifier(), dpop.proof(TOKEN_ENDPOINT))
                .then().statusCode(200);

        // Remembered: the same user and scopes get a code straight away next time.
        authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid", "state-again", null,
                s256(newVerifier()), "S256", FakePasswordCredentialVerifier.CONSENT_SUBJECT)
                .then().statusCode(302);
    }

    @Test
    @DisplayName("deny returns access_denied with state and iss, issues no code and records nothing")
    void signInAskThenDeny() {
        Started started = startSignedOut("openid email", "state-deny");
        Response asked = signInAsConsentUser(started);

        Response denied = answer(started, started.binding(), csrfOf(asked), "same-origin", "deny");

        denied.then().statusCode(303);
        Map<String, String> query = queryOf(denied.getHeader("Location"));
        assertThat(query).containsEntry("error", "access_denied")
                .containsEntry("state", "state-deny")
                .containsEntry("iss", ISSUER)
                .doesNotContainKey("code");
        // Nothing recorded: the next request for those scopes is asked again.
        park(authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid email", "state-after", null,
                s256(newVerifier()), "S256", FakePasswordCredentialVerifier.CONSENT_SUBJECT), newVerifier());
    }

    @Test
    @DisplayName("arriving signed in without consent: sent to the consent step, no code; a wider scope asks again")
    void signedInIsAskedAndWiderScopeAsksAgain() {
        String subject = UUID.randomUUID().toString();
        consents.requireConsent(subject);
        String verifier = newVerifier();

        Started started = park(authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid",
                "state-session", null, s256(verifier), "S256", subject), verifier);
        Response asked = page(started);
        asked.then().statusCode(200).body(containsString("action=\"signin/consent\""))
                .body(not(containsString("name=\"password\"")));
        answer(started, started.binding(), csrfOf(asked), "same-origin", "allow").then().statusCode(303);

        authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid", "state-same", null,
                s256(newVerifier()), "S256", subject).then().statusCode(302);
        park(authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid email", "state-wider", null,
                s256(newVerifier()), "S256", subject), newVerifier());
    }

    @Test
    @DisplayName("an answer without the token, with a forged one, without the binding or cross-site is refused and uses nothing up")
    void answerIsBoundToThePage() {
        Started started = startSignedOut("openid", "state-csrf");
        String csrf = csrfOf(signInAsConsentUser(started));

        answer(started, started.binding(), null, "same-origin", "allow").then().statusCode(400);
        answer(started, started.binding(), "forged", "same-origin", "allow").then().statusCode(400);
        answer(started, null, csrf, "same-origin", "allow").then().statusCode(400);
        answer(started, "another-browser", csrf, "same-origin", "allow").then().statusCode(400);
        answer(started, started.binding(), csrf, "cross-site", "allow").then().statusCode(403);
        answer(started, started.binding(), csrf, "same-origin", "maybe").then().statusCode(400);

        Response allowed = answer(started, started.binding(), csrf, "same-origin", "allow");
        allowed.then().statusCode(303);
        assertThat(queryOf(allowed.getHeader("Location"))).containsKey("code");
        // Answered once only.
        answer(started, started.binding(), csrf, "same-origin", "allow").then().statusCode(400);
    }

    @Test
    @DisplayName("an allow posted before anyone signed in is refused: the consent step needs a signed-in user")
    void allowBeforeSignInIsRefused() {
        Started started = startSignedOut("openid", "state-early");
        String csrf = csrfOf(page(started));

        answer(started, started.binding(), csrf, "same-origin", "allow")
                .then().statusCode(400)
                .header("Location", org.hamcrest.Matchers.nullValue());
        // The sign-in form still works for this transaction.
        page(started).then().statusCode(200).body(containsString("name=\"password\""));
    }
}
