// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.CLUSTER;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.CLUSTER_WORKLOAD;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.GOOGLE;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.GOOGLE_WORKLOAD;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.OTHER_GOOGLE_WORKLOAD;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.OVERSIZED;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.OVERSIZED_WORKLOAD;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.PER_REQUEST;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.PER_REQUEST_WORKLOAD;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.REDIRECTING;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.REDIRECTING_WORKLOAD;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.UNLISTED;
import static dev.tessera.iam.adapter.rest.support.FakeWorkloads.UNLISTED_WORKLOAD;
import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.JWTClaimsSet;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeWorkloads.Workload;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import dev.tessera.iam.adapter.rest.token.StubIssuer;
import dev.tessera.iam.adapter.rest.token.StubIssuerJwks;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.UnaryOperator;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code POST /token} for keyless (workload-identity) clients, end to end over HTTP: a workload
 * presents the token its platform issued it as a JWT client assertion (RFC 7523 §2.2) on the
 * {@code client_credentials} grant, and tessera verifies it with the key set it fetches, over TLS,
 * from the issuer's configured URL. Two platform shapes: a Google ID token (no {@code jti}, one hour)
 * and a Kubernetes projected service-account token (with a {@code jti}, reused until it expires).
 *
 * <p>The issuers are a {@link StubIssuer} on the loopback interface; which issuers are trusted, their
 * key-set URLs, lifetimes and {@code jti} rules are configuration ({@link Profile}), as in production.
 */
@QuarkusTest
@TestProfile(KeylessClientAuthenticationFlowTest.Profile.class)
@DisplayName("POST /token — keyless workload-identity clients, key sets fetched over TLS (RFC 7523)")
class KeylessClientAuthenticationFlowTest extends AuthorizationCodeFlowSupport {

    private static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** Trusts the stub's issuers (never {@link dev.tessera.iam.adapter.rest.support.FakeWorkloads#UNLISTED}). */
    public static class Profile implements QuarkusTestProfile {

        @Override
        public Set<Class<?>> getEnabledAlternatives() {
            return Set.of(StubIssuerJwks.class);
        }

        @Override
        public Map<String, String> getConfigOverrides() {
            Map<String, String> config = new HashMap<>();
            trust(config, "google", GOOGLE, false, false);
            trust(config, "cluster", CLUSTER, false, false);
            trust(config, "per-request", PER_REQUEST, true, true);
            trust(config, "redirecting", REDIRECTING, false, false);
            trust(config, "oversized", OVERSIZED, false, false);
            config.put("iam.client-assertion.jwks-min-refresh-interval", "PT5S");
            return config;
        }

        private static void trust(Map<String, String> config, String name, String issuer, boolean requireJti,
                boolean singleUse) {
            String prefix = "iam.client-assertion.trusted-issuers." + name + ".";
            config.put(prefix + "issuer", issuer);
            config.put(prefix + "jwks-uri", StubIssuer.jwksUriFor(issuer));
            config.put(prefix + "max-lifetime", "PT1H");
            config.put(prefix + "require-jti", Boolean.toString(requireJti));
            config.put(prefix + "enforce-single-use", Boolean.toString(singleUse));
        }
    }

    /** What a platform issues its workload: one hour, tessera's issuer as the audience. */
    private static JWTClaimsSet.Builder platformToken(String issuer, String subject) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(ISSUER)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofHours(1))));
    }

    /** A Google ID token for a service account: no {@code jti}; {@code azp} and {@code email} as Google sets them. */
    private static String googleIdToken(Workload workload, UnaryOperator<JWTClaimsSet.Builder> claims) {
        return StubIssuer.get().sign(GOOGLE, claims.apply(platformToken(GOOGLE, workload.subject())
                .claim("azp", workload.subject())
                .claim("email", "orders@project.iam.gserviceaccount.com")
                .claim("email_verified", true)).build());
    }

    /** A Kubernetes projected service-account token: a {@code jti}, and the {@code kubernetes.io} claim. */
    private static String projectedToken(Workload workload) {
        return StubIssuer.get().sign(CLUSTER, platformToken(CLUSTER, workload.subject())
                .jwtID(UUID.randomUUID().toString())
                .claim("kubernetes.io", Map.of("namespace", "orders",
                        "serviceaccount", Map.of("name", "billing", "uid", UUID.randomUUID().toString())))
                .build());
    }

    private static String tokenOf(Workload workload) {
        return StubIssuer.get().sign(workload.issuer(), platformToken(workload.issuer(), workload.subject())
                .jwtID(UUID.randomUUID().toString()).build());
    }

    private static Response present(Workload client, String token) {
        return given().config(noFollow())
                .header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .formParam("client_id", client.clientId())
                .formParam("client_assertion_type", JWT_BEARER)
                .formParam("client_assertion", token)
                .when().post("/token");
    }

    private static void issued(Response response, Workload client) {
        response.then().statusCode(200).body("token_type", Matchers.equalTo("Bearer"));
        assertThat(jsonPart(response.jsonPath().getString("access_token"), 1))
                .containsEntry("sub", client.clientId()).containsEntry("client_id", client.clientId());
    }

    @Test
    @DisplayName("a Google ID token for the registered service account gets a token, and again while it lives")
    void googleIdToken() {
        String token = googleIdToken(GOOGLE_WORKLOAD, c -> c);
        issued(present(GOOGLE_WORKLOAD, token), GOOGLE_WORKLOAD);
        issued(present(GOOGLE_WORKLOAD, token), GOOGLE_WORKLOAD);
        assertThat(StubIssuer.get().fetches(GOOGLE)).as("fetched over TLS").isPositive();
    }

    @Test
    @DisplayName("a Kubernetes projected token for the registered service account gets a token, and again while it lives")
    void kubernetesProjectedToken() {
        String token = projectedToken(CLUSTER_WORKLOAD);
        issued(present(CLUSTER_WORKLOAD, token), CLUSTER_WORKLOAD);
        issued(present(CLUSTER_WORKLOAD, token), CLUSTER_WORKLOAD);
        assertThat(StubIssuer.get().fetches(CLUSTER)).as("fetched over TLS").isPositive();
    }

    @Test
    @DisplayName("a bad signature, wrong sub, aud or iss, an expired token, an unlisted issuer, a replayed single-use jti and another workload's token answer alike")
    void refusalsLookAlike() {
        Instant past = Instant.now().minus(Duration.ofHours(2));
        String perRequest = tokenOf(PER_REQUEST_WORKLOAD);
        issued(present(PER_REQUEST_WORKLOAD, perRequest), PER_REQUEST_WORKLOAD);

        Map<String, Response> refusals = new LinkedHashMap<>();
        refusals.put("wrong sub", present(GOOGLE_WORKLOAD, googleIdToken(GOOGLE_WORKLOAD, c -> c.subject("999"))));
        refusals.put("wrong aud", present(GOOGLE_WORKLOAD,
                googleIdToken(GOOGLE_WORKLOAD, c -> c.audience("https://elsewhere.example"))));
        refusals.put("two aud", present(GOOGLE_WORKLOAD,
                googleIdToken(GOOGLE_WORKLOAD, c -> c.audience(List.of(ISSUER, "https://elsewhere.example")))));
        refusals.put("wrong iss", present(GOOGLE_WORKLOAD,
                googleIdToken(GOOGLE_WORKLOAD, c -> c.issuer(CLUSTER))));
        refusals.put("expired", present(GOOGLE_WORKLOAD, googleIdToken(GOOGLE_WORKLOAD, c -> c
                .issueTime(Date.from(past)).expirationTime(Date.from(past.plus(Duration.ofHours(1)))))));
        refusals.put("over the issuer's lifetime", present(GOOGLE_WORKLOAD, googleIdToken(GOOGLE_WORKLOAD,
                c -> c.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(61)))))));
        refusals.put("unlisted issuer", present(UNLISTED_WORKLOAD, tokenOf(UNLISTED_WORKLOAD)));
        refusals.put("replayed single-use jti", present(PER_REQUEST_WORKLOAD, perRequest));
        refusals.put("another workload's token", present(GOOGLE_WORKLOAD, googleIdToken(OTHER_GOOGLE_WORKLOAD, c -> c)));
        String valid = googleIdToken(GOOGLE_WORKLOAD, c -> c);
        String[] parts = valid.split("\\.");
        String foreignSignature = googleIdToken(OTHER_GOOGLE_WORKLOAD, c -> c).split("\\.")[2];
        refusals.put("bad signature under the right kid", present(GOOGLE_WORKLOAD,
                parts[0] + "." + parts[1] + "." + foreignSignature));
        refusals.put("signed by another issuer's key", present(GOOGLE_WORKLOAD,
                StubIssuer.get().sign(CLUSTER, platformToken(GOOGLE, GOOGLE_WORKLOAD.subject()).build())));

        String first = refusals.values().iterator().next().asString();
        refusals.forEach((reason, refusal) -> {
            assertThat(refusal.statusCode()).as(reason).isEqualTo(401);
            assertThat(refusal.asString()).as(reason).isEqualTo(first);
        });
        assertThat(first).contains("invalid_client");
        assertThat(StubIssuer.get().fetches(UNLISTED)).as("an unlisted issuer is never fetched").isZero();
    }

    @Test
    @DisplayName("the other workload's own token still works: the refusal above is about the client, not the token")
    void otherWorkloadAuthenticatesAsItself() {
        issued(present(OTHER_GOOGLE_WORKLOAD, googleIdToken(OTHER_GOOGLE_WORKLOAD, c -> c)), OTHER_GOOGLE_WORKLOAD);
    }

    @Test
    @DisplayName("a key set behind a redirect, or over the size limit, is never used")
    void fetchLimits() {
        present(REDIRECTING_WORKLOAD, tokenOf(REDIRECTING_WORKLOAD)).then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
        assertThat(StubIssuer.get().fetches(REDIRECTING)).as("asked, and the redirect not followed").isPositive();
        present(OVERSIZED_WORKLOAD, tokenOf(OVERSIZED_WORKLOAD)).then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
        assertThat(StubIssuer.get().fetches(OVERSIZED)).isPositive();
    }

    @Test
    @DisplayName("after the issuer rotates its key, an unknown kid makes one rate-limited refresh and the new key verifies")
    void keyRotation() {
        issued(present(CLUSTER_WORKLOAD, projectedToken(CLUSTER_WORKLOAD)), CLUSTER_WORKLOAD);
        String beforeRotation = projectedToken(CLUSTER_WORKLOAD);
        StubIssuer.get().rotate(CLUSTER);
        int fetched = StubIssuer.get().fetches(CLUSTER);

        // Within the refresh interval of the last fetch, the unknown kid fetches nothing and is refused.
        present(CLUSTER_WORKLOAD, projectedToken(CLUSTER_WORKLOAD)).then().statusCode(401);
        assertThat(StubIssuer.get().fetches(CLUSTER)).isEqualTo(fetched);

        StubIssuer.get().advance(Duration.ofSeconds(6));
        issued(present(CLUSTER_WORKLOAD, projectedToken(CLUSTER_WORKLOAD)), CLUSTER_WORKLOAD);
        assertThat(StubIssuer.get().fetches(CLUSTER)).as("one refresh").isEqualTo(fetched + 1);
        present(CLUSTER_WORKLOAD, beforeRotation).then().statusCode(401);
    }
}
