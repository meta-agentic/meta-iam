// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import io.quarkus.qute.i18n.Localized;
import io.quarkus.qute.i18n.MessageBundles;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Turns the requested scopes into the rows the consent step lists: a plain-language description
 * where tessera has one, the scope's own name always.
 *
 * <ul>
 *   <li>{@code openid} is dropped: it only means "sign in", which the heading says.</li>
 *   <li>A standard OpenID Connect scope gets its description from {@link ConsentMessages}, in the
 *       first language the browser accepts that tessera has a bundle for, else English.</li>
 *   <li>Any other scope is listed by its name, so nothing the client asks for is hidden.</li>
 * </ul>
 */
public final class ConsentScopes {

    static final String DEFAULT_LANGUAGE = "en";
    /** The languages with a {@code messages/consent_<lang>.properties} file. */
    static final Set<String> LANGUAGES = Set.of(DEFAULT_LANGUAGE);

    private ConsentScopes() {
    }

    /**
     * One row of the consent step.
     *
     * @param name        the scope as the client requested it
     * @param description its plain-language description, or {@code null} when tessera has none
     */
    public record Line(String name, String description) {
    }

    /**
     * @param scopes    the requested scopes, in request order
     * @param languages the browser's accepted languages, most preferred first (may be empty)
     * @return the rows to list; empty when the request asks for nothing beyond signing in
     */
    public static List<Line> lines(List<String> scopes, List<Locale> languages) {
        ConsentMessages messages = MessageBundles.get(ConsentMessages.class, Localized.Literal.of(language(languages)));
        List<Line> lines = new ArrayList<>();
        for (String scope : scopes) {
            if ("openid".equals(scope)) {
                continue;
            }
            lines.add(new Line(scope, describe(scope, messages)));
        }
        return List.copyOf(lines);
    }

    /** The first accepted language tessera has a bundle for, else English. */
    static String language(List<Locale> languages) {
        if (languages != null) {
            for (Locale locale : languages) {
                String language = locale.getLanguage();
                if (LANGUAGES.contains(language)) {
                    return language;
                }
            }
        }
        return DEFAULT_LANGUAGE;
    }

    private static String describe(String scope, ConsentMessages messages) {
        return switch (scope) {
            case "profile" -> messages.scope_profile();
            case "email" -> messages.scope_email();
            case "address" -> messages.scope_address();
            case "phone" -> messages.scope_phone();
            case "offline_access" -> messages.scope_offline_access();
            default -> null;
        };
    }
}
