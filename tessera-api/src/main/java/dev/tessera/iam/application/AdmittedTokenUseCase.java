package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.TokenUseCase;
import io.smallrye.mutiny.Uni;

/** The authorization-code grant, admitted by {@link TenantAdmission} first. */
public final class AdmittedTokenUseCase implements TokenUseCase {

    private final TenantAdmission admission;
    private final TokenUseCase delegate;

    /**
     * @param admission the tenant admission (never {@code null})
     * @param delegate  the grant it guards (never {@code null})
     */
    public AdmittedTokenUseCase(TenantAdmission admission, TokenUseCase delegate) {
        if (admission == null || delegate == null) {
            throw new IllegalArgumentException("admission and delegate must not be null");
        }
        this.admission = admission;
        this.delegate = delegate;
    }

    @Override
    public Uni<TokenResult> redeemAuthorizationCode(TokenRequestCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        return admission.admit(command.realm().tenant(), () -> delegate.redeemAuthorizationCode(command));
    }
}
