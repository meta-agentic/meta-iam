package dev.tessera.iam.domain.client;

/**
 * How a {@link ConfidentialClient} authenticates to the token endpoint
 *.
 *
 * <p>Note the deliberate absence of a {@code NONE} member: a confidential client
 * <em>by definition</em> authenticates. "No client authentication" is not a
 * weaker confidential method — it is a {@link PublicClient}, a different type
 * entirely. Modelling the absence of auth out of this enum keeps the
 * public/confidential distinction honest at compile time.
 */
public enum ClientAuthMethod {

    /** Mutual-TLS client authentication (RFC 8705); also enables mTLS-bound tokens. */
    MTLS,

    /** {@code private_key_jwt} client assertion (RFC 7523) — asymmetric, no shared secret. */
    PRIVATE_KEY_JWT,

    /**
     * Keyless: a JWT client assertion (RFC 7523) that a trusted external issuer, such as a cloud
     * platform's workload identity, issues to the running workload. The client stores no credential.
     */
    WORKLOAD_IDENTITY,

    /** Shared secret in the {@code Authorization} header ({@code client_secret_basic}). */
    CLIENT_SECRET_BASIC,

    /** Shared secret in the form body ({@code client_secret_post}). */
    CLIENT_SECRET_POST;

    /** Whether a client registered for this method holds a shared secret at all. */
    public boolean holdsSecret() {
        return this == CLIENT_SECRET_BASIC || this == CLIENT_SECRET_POST;
    }

    /**
     * Whether a secret presented this way can authenticate a client registered for this method.
     *
     * @param presentation how the request carried the secret
     * @return {@code false} for every method that holds no secret, whatever the presentation
     */
    public boolean acceptsSecret(ClientSecretPresentation presentation) {
        return switch (this) {
            case CLIENT_SECRET_BASIC -> presentation == ClientSecretPresentation.BASIC;
            case CLIENT_SECRET_POST -> presentation == ClientSecretPresentation.POST;
            case MTLS, PRIVATE_KEY_JWT, WORKLOAD_IDENTITY -> false;
        };
    }
}
