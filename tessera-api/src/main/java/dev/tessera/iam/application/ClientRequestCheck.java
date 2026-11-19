// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.AuthorizeUseCase.AuthorizeResult;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ResourceIndicators;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.GrantType;

/**
 * The checks an authorization request must pass against its registered client before anything
 * happens on its behalf: a code is minted, or the browser is sent to the sign-in page.
 *
 * <p>Shared by {@link AuthorizationService} and {@link SignInService} so the two paths cannot
 * drift apart. A refusal before the client and its redirect URI are validated is
 * non-redirectable, because the redirect target is itself untrusted. A scope the client is not
 * registered for is checked last, once the redirect URI is known to be the client's, so it is
 * redirected as {@code invalid_scope} (RFC 6749 §4.1.2.1), and refused before any consent is
 * asked: a person is never asked for a scope the client may not have.
 */
final class ClientRequestCheck {

    private static final GrantType AUTHORIZATION_CODE = new AuthorizationCode();
    /** Always allowed: it asks for sign-in itself, not for access to anything. */
    private static final String OPENID = "openid";

    private ClientRequestCheck() {
    }

    /**
     * @param client  the client the request names, or {@code null} if none is registered
     * @param request the authorization request
     * @return the refusal, or {@code null} when the request may proceed
     */
    static AuthorizeResult.Failed refusal(Client client, AuthorizationRequest request) {
        if (client == null) {
            return new AuthorizeResult.Failed(AuthorizationError.INVALID_REQUEST, "unknown client", false);
        }
        if (!client.allowedGrants().contains(AUTHORIZATION_CODE)) {
            return new AuthorizeResult.Failed(AuthorizationError.UNAUTHORIZED_CLIENT,
                    "client may not use the authorization_code grant", false);
        }
        if (!client.redirectUris().contains(request.redirectUri())) {
            // Exact match. Delivering anything to an unregistered URI would be an open redirect.
            return new AuthorizeResult.Failed(AuthorizationError.INVALID_REQUEST,
                    "redirect_uri is not registered for this client", false);
        }
        for (String scope : request.scopes()) {
            if (!OPENID.equals(scope) && !client.userScopes().contains(scope)) {
                return new AuthorizeResult.Failed(AuthorizationError.INVALID_SCOPE,
                        "a requested scope is not registered for this client", true);
            }
        }
        // ADR-IAM-009 D3: every named resource must be registered for tokens issued for a person,
        // and a client with none registered obtains no such token (RFC 8707 §2, invalid_target).
        if (ResourceIndicators.grantSet(request.resources(), client.userAudiences())
                instanceof ResourceIndicators.Outcome.Refused refused) {
            return new AuthorizeResult.Failed(AuthorizationError.INVALID_TARGET, refused.description(), true);
        }
        return null;
    }
}
