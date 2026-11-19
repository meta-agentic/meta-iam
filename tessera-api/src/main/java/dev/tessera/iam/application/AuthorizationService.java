package dev.tessera.iam.application;


import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ResourceIndicators;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/**
 * Application service for the authorization endpoint: validates an authorization request
 * against the registered client and mints a single-use, tenant-scoped authorization code.
 *
 * <p>Framework-free (no CDI annotations): an adapter constructs it from the outbound ports
 * and a {@link Clock} and exposes it as a bean. All reactivity is in the {@link Uni} fold;
 * the security-relevant decisions (registered redirect URI, allowed grant) are made by
 * {@link ClientRequestCheck}, which the sign-in path applies too, and the
 * code/clock/randomness effects are confined to the injected ports.
 *
 * <p>A code is issued only for a subject who consented to the client for every requested
 * scope ({@link ConsentStorePort}). Every client is asked, first-party ones included; nothing
 * marks a client as pre-consented. Without consent the result is
 * {@link AuthorizeResult.ConsentRequired} and no code exists.
 */
public final class AuthorizationService implements AuthorizeUseCase {

    private final ClientRepositoryPort clients;
    private final ConsentStorePort consents;
    private final AuthorizationCodeStorePort codeStore;
    private final OpaqueIdentifierPort identifiers;
    private final Clock clock;
    private final Duration codeTtl;

    public AuthorizationService(
            ClientRepositoryPort clients,
            ConsentStorePort consents,
            AuthorizationCodeStorePort codeStore,
            OpaqueIdentifierPort identifiers,
            Clock clock,
            Duration codeTtl) {
        this.clients = requireNonNull(clients, "clients");
        this.consents = requireNonNull(consents, "consents");
        this.codeStore = requireNonNull(codeStore, "codeStore");
        this.identifiers = requireNonNull(identifiers, "identifiers");
        this.clock = requireNonNull(clock, "clock");
        this.codeTtl = requireNonNull(codeTtl, "codeTtl");
        if (codeTtl.isZero() || codeTtl.isNegative()) {
            throw new IllegalArgumentException("codeTtl must be positive");
        }
    }

    @Override
    public Uni<AuthorizeResult> authorize(AuthorizationRequest request, String subjectId) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        if (subjectId == null || subjectId.isBlank()) {
            throw new IllegalArgumentException("subjectId must not be blank");
        }

        return clients.findByClientId(request.realm(), request.clientId())
                .flatMap(client -> {
                    AuthorizeResult.Failed refusal = ClientRequestCheck.refusal(client, request);
                    if (refusal != null) {
                        return Uni.createFrom().item((AuthorizeResult) refusal);
                    }
                    return consents.hasConsent(request.realm(), subjectId, client.id(), request.scopes())
                            .flatMap(consented -> consented
                                    ? issueCode(request, client, subjectId)
                                    : Uni.createFrom().item((AuthorizeResult) new AuthorizeResult.ConsentRequired()));
                });
    }

    private Uni<AuthorizeResult> issueCode(AuthorizationRequest request, Client client, String subjectId) {
        Instant now = clock.instant();
        AuthorizationGrant grant = new AuthorizationGrant(
                request.realm(),
                client.id(),
                subjectId,
                request.redirectUri(),
                request.scopes(),
                request.nonce(),
                request.codeChallenge(),
                now,
                now.plus(codeTtl),
                grantSet(request, client));
        String code = identifiers.newAuthorizationCode();
        return codeStore.store(code, grant)
                .replaceWith(success(code, request.state()));
    }

    /**
     * The grant's resource set (ADR-IAM-009 D3): the named resources, or the client's whole list.
     * {@link ClientRequestCheck} has already refused a request for which there is none.
     */
    private static Set<String> grantSet(AuthorizationRequest request, Client client) {
        return switch (ResourceIndicators.grantSet(request.resources(), client.userAudiences())) {
            case ResourceIndicators.Outcome.Granted granted -> granted.resources();
            case ResourceIndicators.Outcome.Refused refused ->
                    throw new IllegalStateException("a refused request reached code issuance: " + refused.description());
        };
    }

    private static Uni<AuthorizeResult> success(String code, String state) {
        return Uni.createFrom().item(new AuthorizeResult.Issued(code, state));
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }
}
