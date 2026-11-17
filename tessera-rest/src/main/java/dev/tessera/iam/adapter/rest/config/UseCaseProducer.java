package dev.tessera.iam.adapter.rest.config;

import dev.tessera.iam.adapter.rest.login.LoginConfig;
import dev.tessera.iam.application.AuthorizationService;
import dev.tessera.iam.application.AdmittedClientCredentialsUseCase;
import dev.tessera.iam.application.AdmittedRefreshUseCase;
import dev.tessera.iam.application.AdmittedTokenUseCase;
import dev.tessera.iam.application.ClientCredentialsService;
import dev.tessera.iam.application.ClientProfileCheck;
import dev.tessera.iam.application.ConsentService;
import dev.tessera.iam.application.EndSessionService;
import dev.tessera.iam.application.IntrospectService;
import dev.tessera.iam.application.LoginService;
import dev.tessera.iam.application.RefreshService;
import dev.tessera.iam.application.RegisteredClientClaimSource;
import dev.tessera.iam.application.RevokeService;
import dev.tessera.iam.application.SessionService;
import dev.tessera.iam.application.SignInService;
import dev.tessera.iam.application.TenantAdmission;
import dev.tessera.iam.application.TokenService;
import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.in.ClientCredentialsUseCase;
import dev.tessera.iam.application.port.in.ConsentUseCase;
import dev.tessera.iam.application.port.in.EndSessionUseCase;
import dev.tessera.iam.application.port.in.IntrospectUseCase;
import dev.tessera.iam.application.port.in.LoginUseCase;
import dev.tessera.iam.application.port.in.RefreshUseCase;
import dev.tessera.iam.application.port.in.RevokeUseCase;
import dev.tessera.iam.application.port.in.SessionUseCase;
import dev.tessera.iam.application.port.in.SignInUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort;
import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.application.port.out.ClientAssertionVerifierPort;
import dev.tessera.iam.application.port.out.ClientKeySourcePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.application.port.out.DpopProofValidatorPort;
import dev.tessera.iam.application.port.out.IdTokenHintVerifierPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.PasswordCredentialVerifierPort;
import dev.tessera.iam.application.port.out.PendingAuthorizationStorePort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.port.out.RefreshTokenTenantResolverPort;
import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.application.port.out.TokenSignerPort;
import dev.tessera.iam.application.port.out.UserProfilePort;
import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import java.time.Clock;
import java.util.Base64;

/**
 * CDI wiring for the application use cases.
 *
 * <p>The application services are framework-free (no CDI annotations), so the adapter
 * constructs each from its injected outbound ports, configuration and a {@link Clock}, and
 * exposes it as a bean. This is the single composition seam between the framework-free core
 * and the adapter shell for the Authorization Code + PKCE flow and the login/consent surface.
 */
@ApplicationScoped
public class UseCaseProducer {

    @Produces
    @ApplicationScoped
    Clock systemClock() {
        return Clock.systemUTC();
    }

    @Produces
    @ApplicationScoped
    AuthorizeUseCase authorizeUseCase(
            ClientRepositoryPort clients,
            ConsentStorePort consents,
            AuthorizationCodeStorePort codeStore,
            OpaqueIdentifierPort identifiers,
            Clock clock,
            AuthFlowConfig authFlow) {
        return new AuthorizationService(clients, consents, codeStore, identifiers, clock, authFlow.codeTtl());
    }

    @Produces
    @ApplicationScoped
    SignInUseCase signInUseCase(
            ClientRepositoryPort clients,
            ConsentStorePort consents,
            AuthorizeUseCase authorize,
            LoginUseCase login,
            PendingAuthorizationStorePort pending,
            OpaqueIdentifierPort identifiers,
            Clock clock,
            AuthFlowConfig authFlow) {
        return new SignInService(
                clients, consents, authorize, login, pending, identifiers, clock, authFlow.signInTtl());
    }

    /**
     * The one tenant admission every token-minting grant goes through (ADR-IAM-003 D1): the three
     * grant producers below wrap their service in it, and {@code TenantAdmissionFlowTest} pins that.
     */
    @Produces
    @ApplicationScoped
    @Startup
    TenantAdmission tenantAdmission(TenantRegistryPort registry, SecurityConfig security) {
        // Created at startup, so a minimum profile that cannot be served refuses to boot.
        return new TenantAdmission(registry, security.minimum());
    }

    /**
     * The one profile check every service that authenticates a client folds into its result
     * (ADR-IAM-010 D2); {@code ClientProfileCheckArchTest} pins that each one depends on it.
     */
    @Produces
    @ApplicationScoped
    ClientProfileCheck clientProfileCheck(TenantRegistryPort registry) {
        return new ClientProfileCheck(registry);
    }

    @Produces
    @ApplicationScoped
    TokenUseCase tokenUseCase(
            UserProfilePort userProfiles,
            ClientProfileCheck profiles,
            TenantAdmission admission,
            ClientRepositoryPort clients,
            AuthorizationCodeStorePort codeStore,
            ClientSecretVerifierPort secretVerifier,
            TokenSignerPort signer,
            DpopProofValidatorPort dpop,
            OpaqueIdentifierPort identifiers,
            RefreshTokenStorePort refreshStore,
            Clock clock,
            OidcDiscoveryConfig oidc,
            AuthFlowConfig authFlow,
            RefreshConfig refresh) {
        return new AdmittedTokenUseCase(admission, new TokenService(
                clients,
                codeStore,
                secretVerifier,
                signer,
                dpop,
                identifiers,
                refreshStore,
                clock,
                oidc.issuer(),
                tokenEndpoint(oidc.issuer()),
                authFlow.accessTokenTtl(),
                authFlow.idTokenTtl(),
                refresh.refreshTokenTtl(),
                refresh.enabled(),
                authFlow.requireSenderConstraint(), userProfiles, profiles));
    }

    /**
     * The token endpoint URL a DPoP proof's {@code htu} must match (RFC 9449 §4.2). Derived
     * from the configured issuer — never from the request Host — so a client cannot bind a
     * proof to a foreign authority. Mirrors how OIDC discovery derives endpoint URLs.
     */
    private static String tokenEndpoint(String issuer) {
        return issuer.replaceAll("/+$", "") + "/token";
    }

    @Produces
    @ApplicationScoped
    @Startup
    RefreshUseCase refreshUseCase(
            UserProfilePort userProfiles,
            ClientProfileCheck profiles,
            TenantAdmission admission,
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            TokenSignerPort signer,
            OpaqueIdentifierPort identifiers,
            RefreshTokenStorePort refreshStore,
            RefreshTokenTenantResolverPort tenantResolver,
            Clock clock,
            OidcDiscoveryConfig oidc,
            AuthFlowConfig authFlow,
            RefreshConfig refresh) {
        return new AdmittedRefreshUseCase(admission, new RefreshService(
                clients,
                secretVerifier,
                signer,
                identifiers,
                refreshStore,
                tenantResolver,
                clock,
                oidc.issuer(),
                authFlow.accessTokenTtl(),
                authFlow.idTokenTtl(),
                refresh.enabled(),
                refresh.reuseGrace(),
                successorKey(refresh), userProfiles, profiles));
    }

    /**
     * The decoded successor key, or {@code null} when no reuse grace is configured. A positive grace
     * without a usable key fails here, at start-up, rather than on the first refresh.
     */
    private static byte[] successorKey(RefreshConfig refresh) {
        if (refresh.reuseGrace().isZero()) {
            return null;
        }
        byte[] key;
        try {
            key = refresh.successorKey()
                    .filter(k -> !k.isBlank())
                    .map(k -> Base64.getDecoder().decode(k.trim()))
                    .orElse(null);
        } catch (IllegalArgumentException notBase64) {
            throw new IllegalStateException("iam.refresh.successor-key is not valid base64");
        }
        if (key == null || key.length < 32) {
            throw new IllegalStateException("iam.refresh.reuse-grace is " + refresh.reuseGrace()
                    + " but iam.refresh.successor-key is missing or shorter than 32 bytes");
        }
        return key;
    }

    @Produces
    @ApplicationScoped
    ClientCredentialsUseCase clientCredentialsUseCase(
            ClientProfileCheck profiles,
            TenantAdmission admission,
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            ClientKeySourcePort keySource,
            ClientAssertionVerifierPort assertionVerifier,
            TokenSignerPort signer,
            OpaqueIdentifierPort identifiers,
            Clock clock,
            OidcDiscoveryConfig oidc,
            AuthFlowConfig authFlow,
            ClientCredentialsConfig clientCredentials) {
        return new AdmittedClientCredentialsUseCase(admission, new ClientCredentialsService(
                clients,
                secretVerifier,
                keySource,
                assertionVerifier,
                new RegisteredClientClaimSource(clients),
                signer,
                identifiers,
                clock,
                oidc.issuer(),
                clientCredentials.accessTokenTtl(),
                authFlow.requireSenderConstraint(), profiles));
    }

    @Produces
    @ApplicationScoped
    RevokeUseCase revokeUseCase(
            ClientProfileCheck profiles,
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            ClientKeySourcePort keySource,
            ClientAssertionVerifierPort assertionVerifier,
            RefreshTokenStorePort refreshStore) {
        // The same key source and assertion verifier (and so the same replay store) as the token
        // endpoint: an assertion is single use across /token, /introspect and /revoke.
        return new RevokeService(clients, secretVerifier, keySource, assertionVerifier, refreshStore, profiles);
    }

    @Produces
    @ApplicationScoped
    IntrospectUseCase introspectUseCase(
            ClientProfileCheck profiles,
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            ClientKeySourcePort keySource,
            ClientAssertionVerifierPort assertionVerifier,
            RefreshTokenStorePort refreshStore,
            AccessTokenIntrospectorPort accessTokens,
            Clock clock) {
        return new IntrospectService(
                clients, secretVerifier, keySource, assertionVerifier, refreshStore, accessTokens, clock, profiles);
    }

    @Produces
    @ApplicationScoped
    LoginUseCase loginUseCase(
            PasswordCredentialVerifierPort credentials, SessionStorePort sessions, LoginConfig login) {
        return new LoginService(credentials, sessions, login.sessionTtl());
    }

    @Produces
    @ApplicationScoped
    SessionUseCase sessionUseCase(SessionStorePort sessions) {
        return new SessionService(sessions);
    }

    @Produces
    @ApplicationScoped
    EndSessionUseCase endSessionUseCase(
            ClientRepositoryPort clients,
            IdTokenHintVerifierPort idTokens,
            SessionStorePort sessions,
            RefreshTokenStorePort refreshStore,
            OidcDiscoveryConfig oidc,
            Clock clock,
            LoginConfig login) {
        return new EndSessionService(
                clients, idTokens, sessions, refreshStore, oidc.issuer(), clock, login.sessionTtl());
    }

    @Produces
    @ApplicationScoped
    ConsentUseCase consentUseCase(ConsentStorePort consents) {
        return new ConsentService(consents);
    }
}
