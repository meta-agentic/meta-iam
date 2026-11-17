package dev.tessera.iam.adapter.rest.config;

import dev.tessera.iam.domain.tenancy.SecurityProfile;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Deployment-wide security settings (ADR-IAM-010 D2).
 */
@ConfigMapping(prefix = "iam.security")
public interface SecurityConfig {

    /**
     * The lowest security profile this deployment serves, as its registry name. A tenant stored
     * below it is refused at use. Only {@code standard} is accepted until {@code fapi2} is built:
     * any other value fails startup.
     */
    @WithDefault("standard")
    String minimumProfile();

    /**
     * The parsed minimum.
     *
     * @throws IllegalStateException if the value is unknown or names a profile that is not available
     */
    default SecurityProfile minimum() {
        SecurityProfile profile;
        try {
            profile = SecurityProfile.fromWireName(minimumProfile().trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "iam.security.minimum-profile must be a known profile, got: " + minimumProfile(), e);
        }
        if (!profile.isAvailable()) {
            throw new IllegalStateException("iam.security.minimum-profile=" + profile.wireName()
                    + " is not available yet: only standard can be served");
        }
        return profile;
    }
}
