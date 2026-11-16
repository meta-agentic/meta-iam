package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.ClientCredentialsUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import io.smallrye.mutiny.Uni;

/** The client-credentials grant, admitted by {@link TenantAdmission} first. */
public final class AdmittedClientCredentialsUseCase implements ClientCredentialsUseCase {

    private final TenantAdmission admission;
    private final ClientCredentialsUseCase delegate;

    /**
     * @param admission the tenant admission (never {@code null})
     * @param delegate  the grant it guards (never {@code null})
     */
    public AdmittedClientCredentialsUseCase(TenantAdmission admission, ClientCredentialsUseCase delegate) {
        if (admission == null || delegate == null) {
            throw new IllegalArgumentException("admission and delegate must not be null");
        }
        this.admission = admission;
        this.delegate = delegate;
    }

    @Override
    public Uni<TokenResult> issue(ClientCredentialsCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        return admission.admit(command.realm().tenant(), () -> delegate.issue(command));
    }
}
