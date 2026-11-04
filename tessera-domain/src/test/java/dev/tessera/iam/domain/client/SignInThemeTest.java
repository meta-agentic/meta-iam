// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.domain.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("Sign-in theme name — nothing that could reach outside a path or a directory")
class SignInThemeTest {

    @ParameterizedTest
    @ValueSource(strings = {"acme", "a", "site-2", "0day"})
    void accepts(String name) {
        assertThat(new SignInTheme(name).value()).isEqualTo(name);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "Acme", "-acme", "a b", "a/b", "..", "a.b", "a_b", "a\n",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
    void refuses(String name) {
        assertThat(SignInTheme.isValid(name)).isFalse();
        assertThatThrownBy(() -> new SignInTheme(name)).isInstanceOf(IllegalArgumentException.class);
    }
}
