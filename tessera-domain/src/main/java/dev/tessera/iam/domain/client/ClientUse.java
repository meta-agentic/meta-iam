package dev.tessera.iam.domain.client;

/**
 * What a client authenticates for, as far as a security profile cares (ADR-IAM-010 D3).
 */
public enum ClientUse {

    /** A grant that issues tokens for a person: the authorization-code and refresh grants. */
    ACTS_FOR_PERSON,

    /** Acting for itself: {@code client_credentials}, introspection and revocation. */
    ACTS_FOR_ITSELF
}
