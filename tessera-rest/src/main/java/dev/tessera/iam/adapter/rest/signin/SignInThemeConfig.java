// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.util.Optional;

/** Sign-in page themes ({@code iam.signin.themes.*}, ADR-IAM-008). */
@ConfigMapping(prefix = "iam.signin.themes")
public interface SignInThemeConfig {

    /** The directory holding one directory per theme; unset means no themes. */
    Optional<String> directory();

    /** What a client gets when it names no theme, or names one the directory lacks. */
    @WithDefault("neutral")
    Unthemed unthemed();

    /** The answers to a client that has no theme to show. */
    enum Unthemed {
        /** Tessera's own unbranded page. */
        NEUTRAL,
        /** No sign-in form at all, for a deployment where a page without a site's look is a fault. */
        REFUSE
    }
}
