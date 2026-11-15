// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Consent scopes — the bundle language follows the browser, English when tessera has no match")
class ConsentScopesLanguageTest {

    @Test
    @DisplayName("the first accepted language with a bundle wins; none, or no header, falls back to English")
    void language() {
        assertThat(ConsentScopes.language(List.of(Locale.forLanguageTag("en-GB")))).isEqualTo("en");
        assertThat(ConsentScopes.language(List.of(Locale.GERMAN, Locale.forLanguageTag("en-US")))).isEqualTo("en");
        assertThat(ConsentScopes.language(List.of(Locale.ITALIAN))).isEqualTo("en");
        assertThat(ConsentScopes.language(List.of())).isEqualTo("en");
        assertThat(ConsentScopes.language(null)).isEqualTo("en");
    }
}
