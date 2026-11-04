// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.domain.client;

import java.util.regex.Pattern;

/**
 * The name of the theme a client's sign-in page shows.
 *
 * <p>The name is part of a URL path and of a directory name, so the pattern admits nothing that
 * could reach outside either: lower-case letters, digits and hyphens, starting with a letter or
 * digit.
 *
 * @param value the name (never {@code null})
 */
public record SignInTheme(String value) {

    private static final Pattern NAME = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");

    public SignInTheme {
        if (!isValid(value)) {
            throw new IllegalArgumentException("Invalid sign-in theme name: " + value);
        }
    }

    /**
     * Whether {@code value} is a legal theme name.
     *
     * @param value the candidate (may be {@code null})
     * @return {@code true} when it matches the pattern
     */
    public static boolean isValid(String value) {
        return value != null && NAME.matcher(value).matches();
    }
}
