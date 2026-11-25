// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.in.IntrospectUseCase.IntrospectionResult;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort.VerifiedAccessToken;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Access-token introspection: active only in the realm the token's own claims name (ADR-IAM-003 D4b)")
class IntrospectRealmClaimsTest {

    private static final Instant NOW = Instant.parse("2026-11-25T12:00:00Z");
    private static final TenantId TENANT = new TenantId(UUID.randomUUID());
    private static final RealmKey REALM = new RealmKey(TENANT, new BaselineId(new UUID(0L, 0L)));

    private static IntrospectionResult introspect(RealmKey at, String tenantClaim, String baselineClaim) {
        return IntrospectService.introspectAccess(at, Optional.of(new VerifiedAccessToken(
                "user-1", "client-1", "openid", "jti-1", NOW.getEpochSecond() - 10, NOW.getEpochSecond() + 60,
                tenantClaim, baselineClaim)), NOW);
    }

    private static String tenant(RealmKey realm) {
        return realm.tenant().value().toString();
    }

    private static String baseline(RealmKey realm) {
        return realm.baseline().value().toString();
    }

    @Test
    @DisplayName("a token that names this realm is active")
    void sameRealm_isActive() {
        assertThat(introspect(REALM, tenant(REALM), baseline(REALM))).isInstanceOf(IntrospectionResult.Active.class);
    }

    @Test
    @DisplayName("a token with no realm claims is inactive, not grandfathered")
    void noRealmClaims_isInactive() {
        assertThat(introspect(REALM, null, null)).isInstanceOf(IntrospectionResult.Inactive.class);
        assertThat(introspect(REALM, tenant(REALM), null)).isInstanceOf(IntrospectionResult.Inactive.class);
        assertThat(introspect(REALM, null, baseline(REALM))).isInstanceOf(IntrospectionResult.Inactive.class);
    }

    @Test
    @DisplayName("a token of another tenant is inactive, even if a key verified it")
    void otherTenant_isInactive() {
        RealmKey other = new RealmKey(new TenantId(UUID.randomUUID()), REALM.baseline());
        assertThat(introspect(REALM, tenant(other), baseline(other))).isInstanceOf(IntrospectionResult.Inactive.class);
    }

    @Test
    @DisplayName("a token of the same tenant's other baseline is inactive: the full realm is compared")
    void otherBaseline_isInactive() {
        RealmKey otherBaseline = new RealmKey(TENANT, new BaselineId(UUID.randomUUID()));
        assertThat(introspect(REALM, tenant(otherBaseline), baseline(otherBaseline)))
                .isInstanceOf(IntrospectionResult.Inactive.class);
    }
}
