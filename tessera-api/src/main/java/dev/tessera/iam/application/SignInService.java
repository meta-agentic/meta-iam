// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.in.AuthorizeUseCase.AuthorizeResult;
import dev.tessera.iam.application.port.in.LoginUseCase;
import dev.tessera.iam.application.port.in.LoginUseCase.LoginResult;
import dev.tessera.iam.application.port.in.SignInUseCase;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.PendingAuthorizationStorePort;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.authcode.PendingAuthorization;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

/**
 * Application service for the hosted sign-in page. Framework-free, wired by the adapter like
 * the other services.
 *
 * <p>It adds no second path to an authorization code: once the user has signed in it hands the
 * parked request to {@link AuthorizeUseCase}, which validates the client again and mints the
 * code exactly as it does for a request that arrived signed in.
 *
 * <p>The order of {@link #submit} is part of its security. The transaction, its browser binding
 * and the synchronizer token are checked before the credential, so a post that did not come
 * from the browser holding the form never reaches password verification. The transaction is
 * consumed only after the credential verifies, so a mistyped password can be retried, and
 * consumed atomically, so one sign-in answers the request at most once.
 *
 * <p>When the user has not consented to the client for every requested scope,
 * {@link AuthorizeUseCase} issues no code. The request then waits at the consent step under the
 * same transaction, now carrying the signed-in subject, and {@link #decide} answers it: allow
 * records the consent and goes through {@link AuthorizeUseCase} again, deny answers with
 * {@code access_denied}. The subject is never read from a post; it is the one that signed in,
 * or the one {@code /authorize} found in the session.
 */
public final class SignInService implements SignInUseCase {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final ClientRepositoryPort clients;
    private final ConsentStorePort consents;
    private final AuthorizeUseCase authorize;
    private final LoginUseCase login;
    private final PendingAuthorizationStorePort pending;
    private final OpaqueIdentifierPort identifiers;
    private final Clock clock;
    private final Duration lifetime;

    public SignInService(
            ClientRepositoryPort clients,
            ConsentStorePort consents,
            AuthorizeUseCase authorize,
            LoginUseCase login,
            PendingAuthorizationStorePort pending,
            OpaqueIdentifierPort identifiers,
            Clock clock,
            Duration lifetime) {
        this.clients = requireNonNull(clients, "clients");
        this.consents = requireNonNull(consents, "consents");
        this.authorize = requireNonNull(authorize, "authorize");
        this.login = requireNonNull(login, "login");
        this.pending = requireNonNull(pending, "pending");
        this.identifiers = requireNonNull(identifiers, "identifiers");
        this.clock = requireNonNull(clock, "clock");
        this.lifetime = requireNonNull(lifetime, "lifetime");
        if (lifetime.isZero() || lifetime.isNegative()) {
            throw new IllegalArgumentException("lifetime must be positive");
        }
    }

    @Override
    public Uni<BeginResult> begin(AuthorizationRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        return clients.findByClientId(request.realm(), request.clientId())
                .flatMap(client -> {
                    AuthorizeResult.Failed refusal = ClientRequestCheck.refusal(client, request);
                    if (refusal != null) {
                        return Uni.createFrom().item(
                                (BeginResult) new BeginResult.Refused(refusal.error(), refusal.description(), refusal.redirectable()));
                    }
                    return park(request, null);
                });
    }

    @Override
    public Uni<BeginResult> beginConsent(AuthorizationRequest request, String subjectId) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        if (isBlank(subjectId)) {
            throw new IllegalArgumentException("subjectId must not be blank");
        }
        return clients.findByClientId(request.realm(), request.clientId())
                .flatMap(client -> {
                    AuthorizeResult.Failed refusal = ClientRequestCheck.refusal(client, request);
                    if (refusal != null) {
                        return Uni.createFrom().item(
                                (BeginResult) new BeginResult.Refused(refusal.error(), refusal.description(), refusal.redirectable()));
                    }
                    return park(request, subjectId);
                });
    }

    private Uni<BeginResult> park(AuthorizationRequest request, String subjectId) {
        Instant now = clock.instant();
        String binding = identifiers.newSignInSecret();
        PendingAuthorization entry = new PendingAuthorization(
                identifiers.newSignInSecret(),
                request,
                identifiers.newSignInSecret(),
                hash(binding),
                now,
                now.plus(lifetime),
                subjectId);
        return pending.store(entry)
                .replaceWith(new BeginResult.Started(entry.transactionId(), binding, lifetime));
    }

    @Override
    public Uni<FormResult> show(RealmKey realm, String transactionId, String binding) {
        if (realm == null || isBlank(transactionId) || isBlank(binding)) {
            return Uni.createFrom().item(new FormResult.Unavailable());
        }
        return pending.find(realm, transactionId)
                .flatMap(entry -> {
                    if (entry == null || !bound(entry, binding) || entry.isExpired(clock.instant())) {
                        return Uni.createFrom().item((FormResult) new FormResult.Unavailable());
                    }
                    return entry.awaitsConsent()
                            ? consentForm(entry).map(form -> (FormResult) new FormResult.ConsentShown(form))
                            : form(entry).map(form -> (FormResult) new FormResult.Shown(form));
                });
    }

    @Override
    public Uni<SubmitResult> submit(Submission submission) {
        if (submission == null) {
            throw new IllegalArgumentException("submission must not be null");
        }
        RealmKey realm = submission.realm();
        if (realm == null || isBlank(submission.transactionId()) || isBlank(submission.binding())
                || isBlank(submission.csrfToken())) {
            return unavailable();
        }
        return pending.find(realm, submission.transactionId()).flatMap(entry -> {
            if (entry == null
                    || entry.isExpired(clock.instant())
                    || !bound(entry, submission.binding())
                    || !sameSecret(entry.csrfToken(), submission.csrfToken())) {
                return unavailable();
            }
            if (isBlank(submission.username()) || isBlank(submission.password())) {
                return denied(entry);
            }
            return login.login(realm, submission.username(), submission.password())
                    .flatMap(result -> switch (result) {
                        case LoginResult.Denied denied -> denied(entry);
                        case LoginResult.Authenticated authenticated -> answer(realm, entry, authenticated);
                    });
        });
    }

    private Uni<SubmitResult> answer(
            RealmKey realm, PendingAuthorization entry, LoginResult.Authenticated authenticated) {
        return pending.consume(realm, entry.transactionId()).flatMap(consumed -> {
            if (consumed == null) {
                // Another post of the same form won the consume.
                return unavailable();
            }
            AuthorizationRequest request = consumed.request();
            return authorize.authorize(request, authenticated.subjectId())
                    .flatMap(result -> switch (result) {
                        case AuthorizeResult.Issued issued -> Uni.createFrom().item(
                                (SubmitResult) new SubmitResult.Completed(request.redirectUri(), issued.code(),
                                        issued.state(), authenticated.sessionId()));
                        case AuthorizeResult.Failed failed -> Uni.createFrom().item(
                                (SubmitResult) new SubmitResult.Refused(failed.error(), failed.description()));
                        case AuthorizeResult.ConsentRequired required -> {
                            // Park the same request again, now for this user's consent: same
                            // transaction, token, binding and expiry, so the browser holding the
                            // form is the only one that can answer.
                            PendingAuthorization waiting = consumed.awaitingConsentOf(authenticated.subjectId());
                            yield pending.store(waiting)
                                    .chain(() -> consentForm(waiting))
                                    .map(form -> (SubmitResult) new SubmitResult.ConsentNeeded(
                                            form, authenticated.sessionId()));
                        }
                    });
        });
    }

    @Override
    public Uni<DecisionResult> decide(Decision decision) {
        if (decision == null) {
            throw new IllegalArgumentException("decision must not be null");
        }
        RealmKey realm = decision.realm();
        if (realm == null || isBlank(decision.transactionId()) || isBlank(decision.binding())
                || isBlank(decision.csrfToken())) {
            return Uni.createFrom().item(new DecisionResult.Unavailable());
        }
        return pending.find(realm, decision.transactionId()).flatMap(entry -> {
            if (entry == null
                    || entry.isExpired(clock.instant())
                    || !entry.awaitsConsent()
                    || !bound(entry, decision.binding())
                    || !sameSecret(entry.csrfToken(), decision.csrfToken())) {
                return Uni.createFrom().item((DecisionResult) new DecisionResult.Unavailable());
            }
            return pending.consume(realm, entry.transactionId()).flatMap(consumed -> {
                if (consumed == null) {
                    // Another post of the same answer won the consume.
                    return Uni.createFrom().item((DecisionResult) new DecisionResult.Unavailable());
                }
                AuthorizationRequest request = consumed.request();
                if (!decision.allow()) {
                    return Uni.createFrom().item(
                            (DecisionResult) new DecisionResult.Declined(request.redirectUri(), request.state()));
                }
                return allow(consumed);
            });
        });
    }

    private Uni<DecisionResult> allow(PendingAuthorization consumed) {
        AuthorizationRequest request = consumed.request();
        String subject = consumed.subjectId();
        return clients.findByClientId(request.realm(), request.clientId()).flatMap(client -> {
            AuthorizeResult.Failed refusal = ClientRequestCheck.refusal(client, request);
            if (refusal != null) {
                return Uni.createFrom().item(
                        (DecisionResult) new DecisionResult.Refused(refusal.error(), refusal.description()));
            }
            // Record first, then answer through the one path that issues codes, which checks
            // the consent again: nothing here mints a code by itself.
            return consents.grant(request.realm(), subject, client.id(), request.scopes())
                    .flatMap(recorded -> authorize.authorize(request, subject))
                    .map(result -> switch (result) {
                        case AuthorizeResult.Issued issued ->
                                (DecisionResult) new DecisionResult.Completed(
                                        request.redirectUri(), issued.code(), issued.state());
                        case AuthorizeResult.Failed failed ->
                                new DecisionResult.Refused(failed.error(), failed.description());
                        case AuthorizeResult.ConsentRequired required ->
                                new DecisionResult.Refused(AuthorizationError.ACCESS_DENIED,
                                        "the consent could not be recorded");
                    });
        });
    }

    /** The consent step for a request waiting for consent; the theme is read now, as for the form. */
    private Uni<ConsentForm> consentForm(PendingAuthorization entry) {
        AuthorizationRequest request = entry.request();
        return clients.findByClientId(request.realm(), request.clientId())
                .map(client -> new ConsentForm(entry.transactionId(), entry.csrfToken(), request.redirectUri(),
                        client == null || client.signInTheme() == null ? null : client.signInTheme().value(),
                        request.clientId(), List.copyOf(request.scopes())));
    }

    private Uni<SubmitResult> denied(PendingAuthorization entry) {
        return form(entry).map(SubmitResult.Denied::new);
    }

    /**
     * The form for a parked request. The theme is read from the client's registration now, not
     * parked with the request, so the page never shows a theme the registration no longer names.
     */
    private Uni<Form> form(PendingAuthorization entry) {
        AuthorizationRequest request = entry.request();
        return clients.findByClientId(request.realm(), request.clientId())
                .map(client -> new Form(entry.transactionId(), entry.csrfToken(), request.redirectUri(),
                        client == null || client.signInTheme() == null ? null : client.signInTheme().value()));
    }

    private static boolean bound(PendingAuthorization entry, String binding) {
        return sameSecret(entry.bindingHash(), hash(binding));
    }

    /** Constant-time comparison, so a guess learns nothing from how long the check took. */
    private static boolean sameSecret(String expected, String presented) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII), presented.getBytes(StandardCharsets.US_ASCII));
    }

    private static String hash(String secret) {
        try {
            return B64URL.encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(secret.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static Uni<SubmitResult> unavailable() {
        return Uni.createFrom().item(new SubmitResult.Unavailable());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }
}
