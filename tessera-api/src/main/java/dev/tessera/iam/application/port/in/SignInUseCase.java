// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application.port.in;

import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.time.Duration;
import java.util.List;

/**
 * Inbound port for tessera's hosted sign-in page: the step between an authorization request
 * that arrives with no signed-in user and the code it is answered with.
 *
 * <p>The flow has three steps, one per method:
 * <ol>
 *   <li>{@link #begin}: {@code /authorize} hands over a request with no subject. The client and
 *       redirect URI are validated first, so the sign-in page is never shown for a request
 *       that could not be answered, and the request is parked under a transaction id.</li>
 *   <li>{@link #show}: the sign-in page reads the parked request to render its form.</li>
 *   <li>{@link #submit}: the form is posted. Once the browser binding, the synchronizer token
 *       and the credential all verify, the parked request is consumed and answered with a
 *       code, exactly as {@link AuthorizeUseCase} answers one that arrived signed in.</li>
 *   <li>{@link #decide}: when the signed-in user has not consented to the client for every
 *       requested scope, the request waits at the consent step instead of being answered. The
 *       user allows or denies; allow records the consent and answers with a code, deny answers
 *       with {@code access_denied}. {@link #beginConsent} parks a request for that step when
 *       it arrived at {@code /authorize} already signed in.</li>
 * </ol>
 *
 * <p>The browser binding is a secret the adapter keeps in a cookie on the browser that started
 * the flow. A transaction id alone, copied into another browser, is worth nothing.
 */
public interface SignInUseCase {

    /**
     * Validates an authorization request that carries no subject and parks it for sign-in.
     *
     * @param request the structurally valid authorization request (never {@code null})
     * @return {@link BeginResult.Started} with the secrets the browser needs, or
     *         {@link BeginResult.Refused} when the client or redirect URI does not validate
     */
    Uni<BeginResult> begin(AuthorizationRequest request);

    /**
     * Parks a request whose user is already signed in but has not consented to the client for
     * every requested scope, so the hosted page can ask. The client and redirect URI are
     * validated again first.
     *
     * @param request   the structurally valid authorization request (never {@code null})
     * @param subjectId the signed-in user (never {@code null} or blank)
     * @return {@link BeginResult.Started}, or {@link BeginResult.Refused} as for {@link #begin}
     */
    Uni<BeginResult> beginConsent(AuthorizationRequest request, String subjectId);

    /**
     * Reads a parked request for the sign-in form.
     *
     * @param realm         the realm of the request
     * @param transactionId the transaction id from the sign-in URL (may be {@code null})
     * @param binding       the browser-binding secret from the cookie (may be {@code null})
     * @return the {@link Form} to render, or {@link FormResult.Unavailable} when the transaction
     *         is unknown, expired or bound to another browser
     */
    Uni<FormResult> show(RealmKey realm, String transactionId, String binding);

    /**
     * Verifies a posted sign-in form and, on success, answers the parked request.
     *
     * @param submission the posted values (never {@code null}; its fields may be {@code null})
     * @return the outcome
     */
    Uni<SubmitResult> submit(Submission submission);

    /**
     * Applies the user's answer at the consent step. The transaction, its browser binding and
     * the synchronizer token are checked first, then the transaction is consumed, so one answer
     * is applied at most once.
     *
     * @param decision the posted answer (never {@code null}; its fields may be {@code null})
     * @return the outcome
     */
    Uni<DecisionResult> decide(Decision decision);

    /**
     * What the sign-in form needs: where it posts its transaction and token, and the redirect
     * URI the browser will be sent to once it succeeds (the page's policy must allow it).
     *
     * @param transactionId the transaction id
     * @param csrfToken     the synchronizer token the form carries
     * @param redirectUri   the client's validated redirect URI
     * @param theme         the theme the client's registration names, or {@code null} when it
     *                      names none; whether the image holds it is the adapter's to decide
     */
    record Form(String transactionId, String csrfToken, String redirectUri, String theme) {
    }

    /**
     * What the consent step needs: the same transaction and token as the sign-in form, which
     * client asks, and for which scopes.
     *
     * @param transactionId the transaction id
     * @param csrfToken     the synchronizer token the form carries
     * @param redirectUri   the client's validated redirect URI
     * @param theme         the theme the client's registration names, or {@code null}
     * @param clientId      the client asking, as the request named it
     * @param scopes        the requested scopes, in request order (may be empty)
     */
    record ConsentForm(
            String transactionId, String csrfToken, String redirectUri, String theme, String clientId,
            List<String> scopes) {

        public ConsentForm {
            scopes = scopes == null ? List.of() : List.copyOf(scopes);
        }
    }

    /**
     * A posted answer at the consent step.
     *
     * @param realm         the realm of the request
     * @param transactionId the posted transaction id
     * @param binding       the browser-binding secret from the cookie
     * @param csrfToken     the posted synchronizer token
     * @param allow         {@code true} to allow, {@code false} to deny
     */
    record Decision(RealmKey realm, String transactionId, String binding, String csrfToken, boolean allow) {
    }

    /**
     * A posted sign-in form, as the browser sent it.
     *
     * @param realm         the realm of the request
     * @param transactionId the posted transaction id
     * @param binding       the browser-binding secret from the cookie
     * @param csrfToken     the posted synchronizer token
     * @param username      the posted username
     * @param password      the posted password
     */
    record Submission(
            RealmKey realm,
            String transactionId,
            String binding,
            String csrfToken,
            String username,
            String password) {

        @Override
        public String toString() {
            // Never render the password, should a submission ever reach a log line.
            return "Submission[realm=" + realm + ", transactionId=" + transactionId + "]";
        }
    }

    /** The outcome of {@link #begin}. */
    sealed interface BeginResult permits BeginResult.Started, BeginResult.Refused {

        /**
         * The request is parked: send the browser to the sign-in page with
         * {@code transactionId}, and give it {@code binding} in a cookie that lives as long as
         * the transaction.
         *
         * @param transactionId the transaction id for the sign-in URL
         * @param binding       the browser-binding secret, for the cookie only
         * @param lifetime      how long the transaction stays usable
         */
        record Started(String transactionId, String binding, Duration lifetime) implements BeginResult {
        }

        /**
         * The request cannot be answered: an unknown client, a client not allowed the code
         * grant, or an unregistered redirect URI. Never redirected.
         *
         * @param error       the OAuth error
         * @param description a non-sensitive description
         */
        record Refused(AuthorizationError error, String description) implements BeginResult {
        }
    }

    /** The outcome of {@link #show}. */
    sealed interface FormResult permits FormResult.Shown, FormResult.ConsentShown, FormResult.Unavailable {

        /** @param form the form to render */
        record Shown(Form form) implements FormResult {
        }

        /** The user signed in and the request waits for consent. @param form the consent step */
        record ConsentShown(ConsentForm form) implements FormResult {
        }

        /** Unknown, expired or bound to another browser; the user starts again at the client. */
        record Unavailable() implements FormResult {
        }
    }

    /** The outcome of {@link #submit}. */
    sealed interface SubmitResult
            permits SubmitResult.Completed, SubmitResult.ConsentNeeded, SubmitResult.Denied,
                    SubmitResult.Unavailable, SubmitResult.Refused {

        /**
         * Signed in, but the user has not consented to the client for every requested scope.
         * No code was issued; the request now waits at the consent step under the same
         * transaction. The sign-in established {@code sessionId}.
         *
         * @param form      the consent step to render
         * @param sessionId the session the sign-in established
         */
        record ConsentNeeded(ConsentForm form, SessionId sessionId) implements SubmitResult {
        }

        /**
         * Signed in and answered: redirect to {@code redirectUri} with {@code code} and
         * {@code state}. The sign-in also established {@code sessionId}.
         *
         * @param redirectUri the client's validated redirect URI
         * @param code        the issued authorization code
         * @param state       the client's {@code state}
         * @param sessionId   the session the sign-in established
         */
        record Completed(String redirectUri, String code, String state, SessionId sessionId)
                implements SubmitResult {
        }

        /**
         * The credential did not verify. The transaction stays usable, so the form is shown
         * again. Unknown username and wrong password are not told apart.
         *
         * @param form the form to render again
         */
        record Denied(Form form) implements SubmitResult {
        }

        /**
         * The transaction is unknown, expired, already used, bound to another browser, or the
         * synchronizer token does not match. No credential was checked.
         */
        record Unavailable() implements SubmitResult {
        }

        /**
         * The user signed in, but the request could no longer be answered (the client changed
         * meanwhile). Never redirected.
         *
         * @param error       the OAuth error
         * @param description a non-sensitive description
         */
        record Refused(AuthorizationError error, String description) implements SubmitResult {
        }
    }

    /** The outcome of {@link #decide}. */
    sealed interface DecisionResult
            permits DecisionResult.Completed, DecisionResult.Declined, DecisionResult.Unavailable,
                    DecisionResult.Refused {

        /**
         * Allowed: the consent is recorded; redirect to {@code redirectUri} with {@code code}.
         *
         * @param redirectUri the client's validated redirect URI
         * @param code        the issued authorization code
         * @param state       the client's {@code state}
         */
        record Completed(String redirectUri, String code, String state) implements DecisionResult {
        }

        /**
         * Denied: nothing is recorded; redirect to {@code redirectUri} with
         * {@code error=access_denied} (RFC 6749 §4.1.2.1).
         *
         * @param redirectUri the client's validated redirect URI
         * @param state       the client's {@code state}
         */
        record Declined(String redirectUri, String state) implements DecisionResult {
        }

        /**
         * The transaction is unknown, expired, already answered, not waiting for consent, bound
         * to another browser, or the synchronizer token does not match.
         */
        record Unavailable() implements DecisionResult {
        }

        /**
         * The request could no longer be answered (the client changed meanwhile). Never
         * redirected.
         *
         * @param error       the OAuth error
         * @param description a non-sensitive description
         */
        record Refused(AuthorizationError error, String description) implements DecisionResult {
        }
    }
}
