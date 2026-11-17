package dev.tessera.iam.adapter.rest.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.tenancy.SecurityProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("iam.security.minimum-profile — only an available profile is accepted")
class SecurityConfigTest {

    private static SecurityConfig minimum(String value) {
        return () -> value;
    }

    @Test
    @DisplayName("standard is accepted")
    void standard() {
        assertThat(minimum("standard").minimum()).isEqualTo(SecurityProfile.STANDARD);
    }

    @Test
    @DisplayName("fapi2 fails startup until it is built")
    void fapi2() {
        assertThatThrownBy(() -> minimum("fapi2").minimum())
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("not available");
    }

    @Test
    @DisplayName("an unknown name fails startup")
    void unknown() {
        assertThatThrownBy(() -> minimum("gold").minimum())
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("minimum-profile");
    }
}
