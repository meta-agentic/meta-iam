package dev.tessera.iam.domain.client;

import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A public client — one that cannot keep a secret (SPAs, native apps)
 *.
 *
 * <p>There is <strong>no secret field</strong> and no {@link ClientAuthMethod}:
 * the design makes a public client PKCE-S256 + DPoP-bound <em>by construction</em>,
 * so the type itself precludes a "public client with a secret" mistake.
 *
 * @param id            stable internal identity (never {@code null})
 * @param realm         owning realm/tenant key (never {@code null})
 * @param allowedGrants permitted grants; defensively copied and exposed unmodifiable
 *                      (never {@code null} or empty)
 * @param redirectUris  registered redirect URIs (exact-match allow-list); defensively
 *                      copied and exposed unmodifiable (never {@code null}, may be empty)
 * @param postLogoutRedirectUris registered post-logout redirect URIs (exact-match allow-list
 *                      for the end-session endpoint); defensively copied and exposed
 *                      unmodifiable (never {@code null}, may be empty)
 * @param signInTheme   the theme its sign-in page shows ({@code null} when it names none)
 * @param userScopes    the scopes it may request for a person, besides {@code openid}
 * @param userAudiences the resources a token issued for a person may name (ADR-IAM-009 D3); each
 *                      an absolute URI with no fragment (never {@code null}, may be empty: such a
 *                      client obtains no token for a person)
 */
public record PublicClient(
        ClientId id,
        RealmKey realm,
        Set<GrantType> allowedGrants,
        Set<String> redirectUris,
        Set<String> postLogoutRedirectUris,
        SignInTheme signInTheme,
        Set<String> userScopes,
        Set<String> userAudiences) implements Client {

    /** A client with no resource registered for tokens issued for a person. */
    public PublicClient(
            ClientId id,
            RealmKey realm,
            Set<GrantType> allowedGrants,
            Set<String> redirectUris,
            Set<String> postLogoutRedirectUris,
            SignInTheme signInTheme,
            Set<String> userScopes) {
        this(id, realm, allowedGrants, redirectUris, postLogoutRedirectUris, signInTheme, userScopes, Set.of());
    }

    /** A client with no scopes registered for tokens issued for a person: it may ask only for {@code openid}. */
    public PublicClient(
            ClientId id,
            RealmKey realm,
            Set<GrantType> allowedGrants,
            Set<String> redirectUris,
            Set<String> postLogoutRedirectUris,
            SignInTheme signInTheme) {
        this(id, realm, allowedGrants, redirectUris, postLogoutRedirectUris, signInTheme, Set.of());
    }

    /** A client whose registration names no sign-in theme. */
    public PublicClient(
            ClientId id,
            RealmKey realm,
            Set<GrantType> allowedGrants,
            Set<String> redirectUris,
            Set<String> postLogoutRedirectUris) {
        this(id, realm, allowedGrants, redirectUris, postLogoutRedirectUris, null);
    }

    /** A client with no post-logout redirect URI registered. */
    public PublicClient(ClientId id, RealmKey realm, Set<GrantType> allowedGrants, Set<String> redirectUris) {
        this(id, realm, allowedGrants, redirectUris, Set.of());
    }

    public PublicClient {
        if (id == null) {
            throw new IllegalArgumentException("PublicClient id must not be null");
        }
        if (realm == null) {
            throw new IllegalArgumentException("PublicClient realm must not be null");
        }
        if (allowedGrants == null || allowedGrants.isEmpty()) {
            throw new IllegalArgumentException("PublicClient allowedGrants must not be empty");
        }
        if (redirectUris == null) {
            throw new IllegalArgumentException("PublicClient redirectUris must not be null");
        }
        if (postLogoutRedirectUris == null) {
            throw new IllegalArgumentException("PublicClient postLogoutRedirectUris must not be null");
        }
        if (userScopes == null) {
            throw new IllegalArgumentException("PublicClient userScopes must not be null");
        }
        for (String scope : userScopes) {
            if (scope == null || scope.isBlank() || scope.chars().anyMatch(Character::isWhitespace)) {
                throw new IllegalArgumentException("PublicClient userScopes holds an invalid scope: " + scope);
            }
        }
        // Defensive copy + unmodifiable view: the record stays immutable even if the
        // caller mutates the set it passed in.
        allowedGrants = Collections.unmodifiableSet(new HashSet<>(allowedGrants));
        redirectUris = Collections.unmodifiableSet(new LinkedHashSet<>(redirectUris));
        postLogoutRedirectUris = Collections.unmodifiableSet(new LinkedHashSet<>(postLogoutRedirectUris));
        if (userAudiences == null) {
            throw new IllegalArgumentException("PublicClient userAudiences must not be null");
        }
        for (String audience : userAudiences) {
            if (!ResourceIndicators.isResourceIdentifier(audience)) {
                throw new IllegalArgumentException("PublicClient userAudiences holds an invalid resource: " + audience);
            }
        }
        userScopes = Collections.unmodifiableSet(new LinkedHashSet<>(userScopes));
        userAudiences = Collections.unmodifiableSet(new LinkedHashSet<>(userAudiences));
    }
}
