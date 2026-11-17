package dev.tessera.iam.application;

import dev.tessera.iam.application.port.out.UserProfilePort;
import dev.tessera.iam.domain.authcode.IssuedTokenClaims;
import dev.tessera.iam.domain.authflow.UserProfile;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.token.ClaimSet;
import io.smallrye.mutiny.Uni;
import java.time.Instant;
import java.util.Set;

/**
 * Assembles an ID token's claims for a person, the same way on every path that issues one (the
 * code grant and the refresh grant): the registered claims, then the profile claims the granted
 * scopes release, then the realm claims last. The user record is read only when the {@code email}
 * or {@code profile} scope was granted.
 */
final class ProfileClaims {

    private ProfileClaims() {
    }

    static Uni<ClaimSet> idToken(
            UserProfilePort profiles, String issuer, String subjectId, String clientId, String nonce,
            Instant issuedAt, Instant expiresAt, RealmKey realm, Set<String> scopes) {
        ClaimSet base = IssuedTokenClaims.idToken(issuer, subjectId, clientId, nonce, issuedAt, expiresAt);
        Uni<UserProfile> profile = scopes.contains("email") || scopes.contains("profile")
                ? profiles.find(realm, subjectId)
                : Uni.createFrom().item(UserProfile.EMPTY);
        return profile.map(found -> IssuedTokenClaims.withRealm(
                IssuedTokenClaims.withProfile(base, found == null ? UserProfile.EMPTY : found, scopes), realm));
    }
}
