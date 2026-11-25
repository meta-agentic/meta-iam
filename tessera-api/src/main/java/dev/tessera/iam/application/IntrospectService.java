package dev.tessera.iam.application;

import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientUse;
import dev.tessera.iam.application.port.in.IntrospectUseCase;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort.VerifiedAccessToken;
import dev.tessera.iam.application.port.out.ClientAssertionVerifierPort;
import dev.tessera.iam.application.port.out.ClientAssertionVerifierPort.ReplayBudget;
import dev.tessera.iam.application.port.out.ClientKeySourcePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.refresh.RefreshTokenCodec;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Application service for token introspection ({@code POST /introspect}, RFC 7662).
 *
 * <p>Framework-free; the reactive fold is the only control flow. The caller is authenticated first
 * (its failure is the only surfaced error), and only a confidential client authenticated with the
 * method it is registered for may introspect: RFC 7662 §4 requires the endpoint to be protected so
 * it cannot be used to probe tokens, and a public client's {@code client_id} is no secret. The caller
 * presents a secret or a JWT client assertion ({@code private_key_jwt} or workload identity), verified
 * exactly as at the token endpoint ({@link ClientAuthentication}). Then the
 * token is classified and evaluated strictly within the caller's own realm:
 * <ul>
 *   <li><strong>Opaque refresh token</strong> (parses via {@link RefreshTokenCodec}) — active iff its
 *       family is visible in the caller's realm, not revoked, not expired, and the presented secret
 *       is the family's <em>current</em> (live) token hash. A superseded token is inactive.</li>
 *   <li><strong>JWT access token</strong> — verified via {@link AccessTokenIntrospectorPort} against
 *       the realm's published keys; active iff it verifies, names this realm in its
 *       {@code realm_tenant} and {@code realm_baseline} claims (ADR-IAM-003 D4b), and has not
 *       expired.</li>
 * </ul>
 * A token of a tenant the registry does not hold as active is inactive, whatever its state.
 * Every negative outcome (unknown, malformed, expired, superseded, foreign-tenant) collapses to
 * {@link IntrospectionResult.Inactive} — the non-oracle guarantee. Realm-binding is header-bound like
 * revocation, never resolved from server state: introspection must not leak across tenants.
 *
 * <p><strong>Access-token active-state is signature + expiry, not a revocation list.</strong> A
 * self-contained JWT access token reports {@code active} until its {@code exp} regardless of any later
 * revocation of the session or refresh-token family it was minted from — this is inherent to stateless
 * bearer JWTs (their short TTL bounds the exposure). Refresh-token introspection, by contrast, does
 * reflect revocation and single-use rotation. A relying party that needs immediate revocation of
 * access must use short access-token lifetimes rather than assume introspection catches it.
 */
public final class IntrospectService implements IntrospectUseCase {

    private final ClientProfileCheck profiles;
    private final ClientRepositoryPort clients;
    private final ClientSecretVerifierPort secretVerifier;
    private final ClientKeySourcePort keySource;
    private final ClientAssertionVerifierPort assertionVerifier;
    private final RefreshTokenStorePort refreshStore;
    private final AccessTokenIntrospectorPort accessTokens;
    private final Clock clock;
    private final String issuer;

    public IntrospectService(
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            ClientKeySourcePort keySource,
            ClientAssertionVerifierPort assertionVerifier,
            RefreshTokenStorePort refreshStore,
            AccessTokenIntrospectorPort accessTokens,
            Clock clock,
            ClientProfileCheck profiles,
            String issuer) {
        if (profiles == null) {
            throw new IllegalArgumentException("profiles must not be null");
        }
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("issuer must not be blank");
        }
        this.issuer = issuer;
        this.profiles = profiles;
        this.clients = requireNonNull(clients, "clients");
        this.secretVerifier = requireNonNull(secretVerifier, "secretVerifier");
        this.keySource = requireNonNull(keySource, "keySource");
        this.assertionVerifier = requireNonNull(assertionVerifier, "assertionVerifier");
        this.refreshStore = requireNonNull(refreshStore, "refreshStore");
        this.accessTokens = requireNonNull(accessTokens, "accessTokens");
        this.clock = requireNonNull(clock, "clock");
    }

    @Override
    public Uni<IntrospectionResult> introspect(IntrospectCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        // Authenticate the caller within its own realm, at the same cost whatever the outcome;
        // an unknown client, a public client, a failed secret and a failed assertion all collapse
        // to invalid_client, the endpoint's only surfaced failure.
        return clients.findByClientId(command.realm(), command.clientId())
                .flatMap(client -> ClientAuthentication.authenticate(secretVerifier, keySource,
                                assertionVerifier, ReplayBudget.INTROSPECTION_AND_REVOCATION, command.realm(), command.clientId(), client,
                                command.clientSecret(), command.secretPresentation(), command.clientAssertion(), false)
                        .flatMap(authenticated -> profiles.andConforms(
                                authenticated, command.realm(), client, ClientUse.ACTS_FOR_ITSELF))
                        .flatMap(ok -> ok ? servedOrInactive(command, client) : authFailed()));
    }

    // A suspended tenant's tokens are reported inactive, after its caller authenticated
    // (ADR-IAM-003 D1 consequence 2; ADR-IAM-011 D5's suspended row), so suspension bites at once
    // for every resource server that introspects, not only once the token expires.
    private Uni<IntrospectionResult> servedOrInactive(IntrospectCommand command, Client caller) {
        return profiles.isServed(command.realm())
                .flatMap(served -> served ? classify(command, caller) : Uni.createFrom().item(inactive()));
    }

    private Uni<IntrospectionResult> classify(IntrospectCommand command, Client caller) {
        Instant now = clock.instant();
        // An opaque refresh token has exactly one '.' and a 16-byte family id; a JWT (two '.') never
        // parses here, so the ordering unambiguously routes each kind.
        Optional<RefreshTokenCodec.Parsed> refresh = RefreshTokenCodec.parse(command.token());
        if (refresh.isPresent()) {
            return introspectRefresh(command.realm(), refresh.get(), caller, now);
        }
        return accessTokens.verify(command.realm(), command.token())
                .map(verified -> introspectAccess(command.realm(), issuer, caller, command.clientId(), verified, now));
    }

    private Uni<IntrospectionResult> introspectRefresh(
            RealmKey realm, RefreshTokenCodec.Parsed parsed, Client caller, Instant now) {
        return refreshStore.find(parsed.id(), realm).map(family -> {
            // Realm-equality is explicit (belt-and-braces): the store scopes by tenant, but the
            // isolation unit is (tenant, baseline) — never report a same-tenant/other-baseline family.
            if (family == null || !family.realm().equals(realm)) {
                return inactive();
            }
            // ADR-IAM-009 D3: a refresh token has no aud, so it is active only to the client it was
            // issued to. A public client cannot introspect, so its refresh tokens are inactive to all.
            if (!family.clientId().equals(caller.id())) {
                return inactive();
            }
            if (family.reused() || family.isExpired(now)) {
                return inactive();
            }
            // Only the family's current (live) token is active; a superseded token is inactive.
            if (!RefreshTokenCodec.matches(parsed.secret(), family.currentTokenHash())) {
                return inactive();
            }
            return active(refreshClaims(family));
        });
    }

    static IntrospectionResult introspectAccess(RealmKey realm, Optional<VerifiedAccessToken> verified, Instant now) {
        return introspectAccess(realm, null, null, null, verified, now);
    }

    /**
     * @param issuer         this realm's issuer; a token whose {@code iss} differs is inactive.
     *                       {@code null} skips the iss and audience checks (the realm-only overload)
     * @param caller         the authenticated introspecting client
     * @param callerClientId its wire {@code client_id}
     */
    static IntrospectionResult introspectAccess(RealmKey realm, String issuer, Client caller, String callerClientId,
            Optional<VerifiedAccessToken> verified, Instant now) {
        if (verified.isEmpty()) {
            return inactive();
        }
        VerifiedAccessToken v = verified.get();
        // ADR-IAM-003 D4b: the token must name, in its own claims, the realm it is introspected in.
        // This is the second boundary beside the per-tenant keys: a token with no realm claims, or
        // another tenant's or another baseline's, is inactive whatever key verified it.
        if (!v.mintedIn(realm)) {
            return inactive();
        }
        // Verified signature under the realm's keys; the active decision is expiry, evaluated here.
        // A token without exp has no lifetime to bound it, so it is never active.
        if (v.expiresAt() == null || now.getEpochSecond() >= v.expiresAt()) {
            return inactive();
        }
        if (issuer != null) {
            // ADR-IAM-003 D4b: the token's iss must be this realm's issuer.
            if (!sameText(issuer, v.issuer())) {
                return inactive();
            }
            // ADR-IAM-009 D3 (RFC 7662 §4): active only to the token's audience, or to the client it
            // was issued to. A caller that is no resource sees only its own tokens. The binding is not
            // checked here; the call carries no proof (RFC 9449 §6.2), so the resource server checks
            // cnf and token_type against its own request.
            boolean audience = caller.resourceIdentifier() != null
                    && v.audience().stream().anyMatch(aud -> sameText(caller.resourceIdentifier(), aud));
            boolean issuedToCaller = sameText(callerClientId, v.clientId());
            if (!audience && !issuedToCaller) {
                return inactive();
            }
            return active(new ActiveToken(v.scope(), v.clientId(), v.subject(), v.tokenType(), v.expiresAt(),
                    v.issuedAt(), v.jti(), v.issuer(), v.audience(), v.confirmation()));
        }
        return active(new ActiveToken(
                v.scope(), v.clientId(), v.subject(), "Bearer", v.expiresAt(), v.issuedAt(), v.jti()));
    }

    private static ActiveToken refreshClaims(RefreshTokenFamily family) {
        Long exp = family.expiresAt() == null ? null : family.expiresAt().getEpochSecond();
        Long iat = family.createdAt() == null ? null : family.createdAt().getEpochSecond();
        // A refresh family stores the client's SURROGATE id (a ClientId UUID), not the wire
        // client_id, and there is no reverse lookup — so client_id is omitted rather than exposing
        // the internal surrogate (RFC 7662's client_id means the wire identifier). scope, token_type,
        // and jti are likewise not carried by a refresh family. Only sub and the timestamps are echoed.
        return new ActiveToken(null, null, family.userId(), null, exp, iat, null);
    }


    private static IntrospectionResult active(ActiveToken token) {
        return new IntrospectionResult.Active(token);
    }

    private static IntrospectionResult inactive() {
        return new IntrospectionResult.Inactive();
    }

    private static Uni<IntrospectionResult> authFailed() {
        return Uni.createFrom().item(new IntrospectionResult.ClientAuthenticationFailed());
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }

    /**
     * Exact string equality without an early exit, as every comparison in this class is
     * ({@code ConstantTimeComparisonArchTest}); {@code null} never matches.
     */
    private static boolean sameText(String expected, String presented) {
        return expected != null && presented != null
                && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                        presented.getBytes(StandardCharsets.UTF_8));
    }
}
