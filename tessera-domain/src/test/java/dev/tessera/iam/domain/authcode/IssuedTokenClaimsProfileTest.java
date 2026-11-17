package dev.tessera.iam.domain.authcode;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.domain.authflow.UserProfile;
import dev.tessera.iam.domain.oidc.OidcCapabilities;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.token.ClaimSet;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("IssuedTokenClaims.withProfile — the scopes release the user's claims, OIDC Core §5.4")
class IssuedTokenClaimsProfileTest {

    private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z");
    private static final UserProfile ADA = new UserProfile("ada@example.com", true, "Ada Lovelace");

    private static ClaimSet base() {
        return IssuedTokenClaims.idToken("https://issuer.example", "sub-1", "client-1", null, T0, T0.plusSeconds(300));
    }

    @Test
    @DisplayName("email releases email and email_verified; profile releases name")
    void scopesRelease() {
        assertThat(IssuedTokenClaims.withProfile(base(), ADA, Set.of("openid", "email", "profile")).claims())
                .containsEntry("email", "ada@example.com")
                .containsEntry("email_verified", true)
                .containsEntry("name", "Ada Lovelace");
        assertThat(IssuedTokenClaims.withProfile(base(), ADA, Set.of("openid")).claims())
                .doesNotContainKeys("email", "email_verified", "name");
    }

    @Test
    @DisplayName("an unset value is left out, never sent empty")
    void unsetLeftOut() {
        assertThat(IssuedTokenClaims.withProfile(base(), UserProfile.EMPTY, Set.of("email", "profile")).claims())
                .doesNotContainKeys("email", "email_verified", "name");
    }

    @Test
    @DisplayName("the realm claims are applied last and stay the realm's")
    void realmLast() {
        RealmKey realm = new RealmKey(TenantId.generate(), new BaselineId(new UUID(0L, 0L)));
        ClaimSet claims = IssuedTokenClaims.withRealm(
                IssuedTokenClaims.withProfile(base(), ADA, Set.of("profile")), realm);
        assertThat(claims.claims()).containsEntry("realm_tenant", realm.tenant().value().toString())
                .containsEntry("name", "Ada Lovelace");
    }

    @Test
    @DisplayName("every claim withProfile can add is in discovery's claims_supported")
    void discoveryCoversTheProfileClaims() {
        assertThat(OidcCapabilities.ID_TOKEN_CLAIMS).containsAll(IssuedTokenClaims.PROFILE_CLAIMS);
    }
}
