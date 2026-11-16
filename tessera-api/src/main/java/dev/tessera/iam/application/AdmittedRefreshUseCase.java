package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.RefreshUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import io.smallrye.mutiny.Uni;

/**
 * The refresh grant, admitted by {@link TenantAdmission} first. It admits the request's tenant: the
 * grant mints only when that tenant equals the family's owning tenant, so admitting it covers both.
 */
public final class AdmittedRefreshUseCase implements RefreshUseCase {

    private final TenantAdmission admission;
    private final RefreshUseCase delegate;

    /**
     * @param admission the tenant admission (never {@code null})
     * @param delegate  the grant it guards (never {@code null})
     */
    public AdmittedRefreshUseCase(TenantAdmission admission, RefreshUseCase delegate) {
        if (admission == null || delegate == null) {
            throw new IllegalArgumentException("admission and delegate must not be null");
        }
        this.admission = admission;
        this.delegate = delegate;
    }

    @Override
    public Uni<TokenResult> redeem(RefreshCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        return admission.admit(command.requestRealm().tenant(), () -> delegate.redeem(command));
    }
}
