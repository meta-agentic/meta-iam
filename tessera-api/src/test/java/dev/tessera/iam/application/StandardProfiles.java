package dev.tessera.iam.application;

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

    private StandardProfiles() {
    }
}
