// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.authcode.CodeChallenge;
import dev.tessera.iam.domain.authcode.PendingAuthorization;
import dev.tessera.iam.domain.authcode.PkceMethod;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;

/**
 * The wire form of a {@link PendingAuthorization} on the shared cache: a flat JSON projection,
 * for the reasons {@code StoredGrant} gives for authorization codes. An entry lives for minutes,
 * so it never has to survive a schema change across a rolling upgrade; one that does not decode
 * is a miss and the user starts the sign-in again. {@code resources} carries the request's RFC 8707
 * values; an entry without it, written before they were recorded, is such a miss.
 */
record StoredPendingAuthorization(
        String transactionId,
        String tenantId,
        String baselineId,
        String clientId,
        String redirectUri,
        List<String> scopes,
        String state,
        String nonce,
        String codeChallengeMethod,
        String codeChallengeValue,
        String csrfToken,
        String bindingHash,
        long createdAtEpochSecond,
        int createdAtNano,
        long expiresAtEpochSecond,
        int expiresAtNano,
        String subjectId,
        List<String> resources) {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static String encode(PendingAuthorization pending) {
        AuthorizationRequest request = pending.request();
        StoredPendingAuthorization stored = new StoredPendingAuthorization(
                pending.transactionId(),
                request.realm().tenant().value().toString(),
                request.realm().baseline().value().toString(),
                request.clientId(),
                request.redirectUri(),
                List.copyOf(request.scopes()),
                request.state(),
                request.nonce(),
                request.codeChallenge().method().name(),
                request.codeChallenge().value(),
                pending.csrfToken(),
                pending.bindingHash(),
                pending.createdAt().getEpochSecond(),
                pending.createdAt().getNano(),
                pending.expiresAt().getEpochSecond(),
                pending.expiresAt().getNano(),
                pending.subjectId(),
                List.copyOf(request.resources()));
        try {
            return MAPPER.writeValueAsString(stored);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("could not encode pending authorization", e);
        }
    }

    /** @return the pending request, or {@code null} if the value does not decode into one */
    static PendingAuthorization decode(String json) {
        StoredPendingAuthorization stored;
        try {
            stored = MAPPER.readValue(json, StoredPendingAuthorization.class);
        } catch (JsonProcessingException e) {
            return null;
        }
        try {
            AuthorizationRequest request = new AuthorizationRequest(
                    new RealmKey(
                            new TenantId(UUID.fromString(stored.tenantId)),
                            new BaselineId(UUID.fromString(stored.baselineId))),
                    stored.clientId,
                    stored.redirectUri,
                    new LinkedHashSet<>(stored.scopes),
                    stored.state,
                    stored.nonce,
                    new CodeChallenge(PkceMethod.valueOf(stored.codeChallengeMethod), stored.codeChallengeValue),
                    // An entry written before resources were recorded has none: it does not decode
                    // (a NullPointerException here), so the user signs in again (ADR-IAM-009 D4).
                    new LinkedHashSet<>(stored.resources));
            return new PendingAuthorization(
                    stored.transactionId,
                    request,
                    stored.csrfToken,
                    stored.bindingHash,
                    Instant.ofEpochSecond(stored.createdAtEpochSecond, stored.createdAtNano),
                    Instant.ofEpochSecond(stored.expiresAtEpochSecond, stored.expiresAtNano),
                    stored.subjectId);
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }
}
