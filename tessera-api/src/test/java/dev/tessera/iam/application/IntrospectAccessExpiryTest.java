// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.in.IntrospectUseCase.IntrospectionResult;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort.VerifiedAccessToken;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Access-token introspection: a verified token is active only while its exp lies ahead")
class IntrospectAccessExpiryTest {

    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");

    private static IntrospectionResult introspect(Long exp) {
        return IntrospectService.introspectAccess(Optional.of(new VerifiedAccessToken(
                "user-1", "client-1", "openid", "jti-1", NOW.getEpochSecond() - 10, exp)), NOW);
    }

    @Test
    @DisplayName("a token with no exp is inactive")
    void noExpIsInactive() {
        assertThat(introspect(null)).isInstanceOf(IntrospectionResult.Inactive.class);
    }

    @Test
    @DisplayName("a token whose exp has passed is inactive")
    void expiredIsInactive() {
        assertThat(introspect(NOW.getEpochSecond() - 1)).isInstanceOf(IntrospectionResult.Inactive.class);
    }

    @Test
    @DisplayName("a token whose exp is exactly now is inactive")
    void expiringNowIsInactive() {
        assertThat(introspect(NOW.getEpochSecond())).isInstanceOf(IntrospectionResult.Inactive.class);
    }

    @Test
    @DisplayName("a token whose exp lies ahead is active")
    void liveIsActive() {
        assertThat(introspect(NOW.getEpochSecond() + 60)).isInstanceOf(IntrospectionResult.Active.class);
    }
}
