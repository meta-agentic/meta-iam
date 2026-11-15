// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import io.quarkus.qute.i18n.Message;
import io.quarkus.qute.i18n.MessageBundle;

/**
 * The consent step's plain-language description of each standard OpenID Connect scope (OIDC Core
 * §5.4 and §11). The text lives in {@code messages/consent_<lang>.properties}, one file per
 * language; English is the default and the fallback. Quarkus checks at build time that every
 * method has a message in every file.
 *
 * <p>{@code openid} has no entry on purpose: it only means "sign in", which the page's heading
 * already says, so it is never listed.
 */
@MessageBundle(value = "consent", locale = "en")
public interface ConsentMessages {

    @Message
    String scope_profile();

    @Message
    String scope_email();

    @Message
    String scope_address();

    @Message
    String scope_phone();

    @Message
    String scope_offline_access();
}
