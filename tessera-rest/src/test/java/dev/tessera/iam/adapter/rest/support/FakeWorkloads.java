// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.domain.client.ClientId;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The workload-identity clients of {@link FakeClientRepository}'s {@link FakeClientRepository#MACHINE_TENANT}:
 * each authenticates with a token its platform issues, so it registers an issuer and a subject and
 * no credential. Which issuers are trusted is configuration (the keyless flow test's profile); the
 * {@link #UNLISTED} one never is.
 */
public final class FakeWorkloads {

    /** Google's issuer, as its ID tokens carry it. */
    public static final String GOOGLE = "https://accounts.google.com";
    /** A Kubernetes cluster's service-account issuer, as its projected tokens carry it. */
    public static final String CLUSTER = "https://kubernetes.default.svc.cluster.local";
    /** An issuer that mints a fresh token per request, configured to enforce single use. */
    public static final String PER_REQUEST = "https://per-request.issuer.example";
    /** A trusted issuer whose key-set URL answers with a redirect. */
    public static final String REDIRECTING = "https://redirecting.issuer.example";
    /** A trusted issuer whose key-set URL answers with a body over the size limit. */
    public static final String OVERSIZED = "https://oversized.issuer.example";
    /** An issuer a client is registered with but the operator never listed. */
    public static final String UNLISTED = "https://unlisted.issuer.example";

    /** One registered workload: its {@code client_id}, identity, and the issuer and subject its token must carry. */
    public record Workload(String clientId, ClientId id, String issuer, String subject) {
    }

    public static final Workload GOOGLE_WORKLOAD = workload("orders-gateway", 1, GOOGLE, "112233445566778899001");
    public static final Workload OTHER_GOOGLE_WORKLOAD = workload("billing-job", 2, GOOGLE, "112233445566778899002");
    public static final Workload CLUSTER_WORKLOAD =
            workload("orders-cluster", 3, CLUSTER, "system:serviceaccount:orders:billing");
    public static final Workload PER_REQUEST_WORKLOAD = workload("per-request-job", 4, PER_REQUEST, "per-request-sa");
    public static final Workload REDIRECTING_WORKLOAD = workload("redirected-job", 5, REDIRECTING, "redirected-sa");
    public static final Workload OVERSIZED_WORKLOAD = workload("oversized-job", 6, OVERSIZED, "oversized-sa");
    public static final Workload UNLISTED_WORKLOAD = workload("unlisted-job", 7, UNLISTED, "unlisted-sa");

    private static final List<Workload> ALL = List.of(GOOGLE_WORKLOAD, OTHER_GOOGLE_WORKLOAD, CLUSTER_WORKLOAD,
            PER_REQUEST_WORKLOAD, REDIRECTING_WORKLOAD, OVERSIZED_WORKLOAD, UNLISTED_WORKLOAD);
    private static final Map<String, Workload> BY_CLIENT_ID =
            ALL.stream().collect(Collectors.toUnmodifiableMap(Workload::clientId, Function.identity()));
    private static final Map<ClientId, Workload> BY_IDENTITY =
            ALL.stream().collect(Collectors.toUnmodifiableMap(Workload::id, Function.identity()));

    private FakeWorkloads() {
    }

    /** The workload registered under {@code clientId}, or {@code null}. */
    public static Workload byClientId(String clientId) {
        return clientId == null ? null : BY_CLIENT_ID.get(clientId);
    }

    /** The workload with this identity, or {@code null}. */
    public static Workload byIdentity(ClientId id) {
        return id == null ? null : BY_IDENTITY.get(id);
    }

    private static Workload workload(String clientId, int n, String issuer, String subject) {
        return new Workload(clientId, new ClientId(UUID.fromString(String.format("00000000-0000-0000-0000-0000000001%02x", n))),
                issuer, subject);
    }
}
