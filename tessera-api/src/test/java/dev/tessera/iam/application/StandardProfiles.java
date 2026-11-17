package dev.tessera.iam.application;

import dev.tessera.iam.application.port.out.UserProfilePort;
import dev.tessera.iam.domain.authflow.UserProfile;
import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.SecurityProfile;
import dev.tessera.iam.domain.tenancy.TenantStatus;
import io.smallrye.mutiny.Uni;
import java.util.Optional;

/** A profile check that holds every tenant registered, active and on {@code standard}. */
public final class StandardProfiles {

    /** Every tenant on {@code standard}, so every client conforms. */
    public static final ClientProfileCheck CHECK = new ClientProfileCheck(tenant -> Uni.createFrom().item(
            Optional.of(new RegisteredTenant(tenant, SecurityProfile.STANDARD, TenantStatus.ACTIVE))));

    /** No user has a profile: ID tokens carry no email or name. */
    public static final UserProfilePort NO_USER_PROFILES = (realm, subject) -> Uni.createFrom().item(UserProfile.EMPTY);

    private StandardProfiles() {
    }
}
