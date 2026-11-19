package dev.tessera.iam.domain.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ResourceIndicators — ADR-IAM-009 D3 audience rules")
class ResourceIndicatorsTest {

    private static final String ISSUER = "https://iam.example";
    private static final String A = "https://a.api.example";
    private static final String B = "https://b.api.example";

    private static Set<String> granted(ResourceIndicators.Outcome outcome) {
        assertThat(outcome).isInstanceOf(ResourceIndicators.Outcome.Granted.class);
        return ((ResourceIndicators.Outcome.Granted) outcome).resources();
    }

    @Test
    @DisplayName("a resource identifier is an absolute URI with no fragment")
    void resourceIdentifier() {
        assertThat(ResourceIndicators.isResourceIdentifier("https://api.example/v1")).isTrue();
        assertThat(ResourceIndicators.isResourceIdentifier("urn:example:api")).isTrue();
        assertThat(ResourceIndicators.isResourceIdentifier("/relative")).isFalse();
        assertThat(ResourceIndicators.isResourceIdentifier("https://api.example/#frag")).isFalse();
        assertThat(ResourceIndicators.isResourceIdentifier("https://api.example/ x")).isFalse();
        assertThat(ResourceIndicators.isResourceIdentifier("")).isFalse();
        assertThat(ResourceIndicators.isResourceIdentifier(null)).isFalse();
    }

    @Test
    @DisplayName("at /authorize: the named resources, or the whole list when none is named")
    void grantSet() {
        assertThat(granted(ResourceIndicators.grantSet(Set.of(), Set.of(A, B)))).containsExactlyInAnyOrder(A, B);
        assertThat(granted(ResourceIndicators.grantSet(Set.of(A), Set.of(A, B)))).containsExactly(A);
        assertThat(ResourceIndicators.grantSet(Set.of("https://other.example"), Set.of(A, B)))
                .isInstanceOf(ResourceIndicators.Outcome.Refused.class);
        assertThat(ResourceIndicators.grantSet(Set.of(), Set.of()))
                .as("an empty list obtains no token for a person")
                .isInstanceOf(ResourceIndicators.Outcome.Refused.class);
    }

    @Test
    @DisplayName("at /token: one candidate is used, several need a name, a name must be a candidate")
    void audience() {
        assertThat(granted(ResourceIndicators.audience(Set.of(A), Set.of(A, B), List.of(), ISSUER))).containsExactly(A);
        assertThat(granted(ResourceIndicators.audience(Set.of(A, B), Set.of(A, B), List.of(B), ISSUER)))
                .containsExactly(B);
        assertThat(ResourceIndicators.audience(Set.of(A, B), Set.of(A, B), List.of(), ISSUER))
                .as("several candidates and none named: list order never decides")
                .isInstanceOf(ResourceIndicators.Outcome.Refused.class);
        assertThat(ResourceIndicators.audience(Set.of(A), Set.of(A, B), List.of(B), ISSUER))
                .as("a registered resource the grant did not include")
                .isInstanceOf(ResourceIndicators.Outcome.Refused.class);
        assertThat(ResourceIndicators.audience(Set.of(A, B), Set.of(A, B), List.of(A, B), ISSUER))
                .as("more than one named")
                .isInstanceOf(ResourceIndicators.Outcome.Refused.class);
    }

    @Test
    @DisplayName("an audience removed from the client leaves the grant; one added later never enters it")
    void currentListIsIntersected() {
        assertThat(granted(ResourceIndicators.audience(Set.of(A, B), Set.of(A), List.of(), ISSUER))).containsExactly(A);
        assertThat(ResourceIndicators.audience(Set.of(A), Set.of(), List.of(), ISSUER))
                .isInstanceOf(ResourceIndicators.Outcome.Refused.class);
        assertThat(ResourceIndicators.audience(Set.of(A), Set.of(A, B), List.of(B), ISSUER))
                .isInstanceOf(ResourceIndicators.Outcome.Refused.class);
    }

    @Test
    @DisplayName("the issuer is never an audience")
    void issuerIsNeverAnAudience() {
        assertThat(ResourceIndicators.audience(Set.of(ISSUER), Set.of(ISSUER), List.of(), ISSUER))
                .isInstanceOf(ResourceIndicators.Outcome.Refused.class);
        assertThat(ResourceIndicators.audience(Set.of(ISSUER), Set.of(ISSUER), List.of(ISSUER), ISSUER))
                .isInstanceOf(ResourceIndicators.Outcome.Refused.class);
    }
}
