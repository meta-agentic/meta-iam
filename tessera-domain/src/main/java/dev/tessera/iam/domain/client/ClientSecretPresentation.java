// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.domain.client;

/** How a request carried a client secret (RFC 6749 §2.3.1). */
public enum ClientSecretPresentation {

    /** The {@code Authorization: Basic} header: {@code client_secret_basic}. */
    BASIC,

    /** The form body: {@code client_secret_post}. */
    POST
}
