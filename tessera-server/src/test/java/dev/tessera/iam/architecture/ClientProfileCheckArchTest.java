package dev.tessera.iam.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import dev.tessera.iam.application.ClientProfileCheck;
import dev.tessera.iam.application.port.in.ClientCredentialsUseCase;
import dev.tessera.iam.application.port.in.IntrospectUseCase;
import dev.tessera.iam.application.port.in.RefreshUseCase;
import dev.tessera.iam.application.port.in.RevokeUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Every endpoint that authenticates a client goes through the one profile check (ADR-IAM-010 D2):
 * each use case that authenticates a client, apart from the admission decorators that delegate to
 * one, depends on {@link ClientProfileCheck}, and so does any class that uses the shared
 * client-authentication step.
 */
@DisplayName("Architecture — every client-authenticating use case applies the profile check")
class ClientProfileCheckArchTest {

    private static final String SHARED_AUTHENTICATION = "dev.tessera.iam.application.ClientAuthentication";

    private static final DescribedPredicate<JavaClass> USE_SHARED_AUTHENTICATION =
            new DescribedPredicate<>("use the shared client-authentication step") {
                @Override
                public boolean test(JavaClass type) {
                    return !type.getName().equals(SHARED_AUTHENTICATION)
                            && type.getDirectDependenciesFromSelf().stream()
                                    .anyMatch(dependency -> dependency.getTargetClass().getName()
                                            .equals(SHARED_AUTHENTICATION));
                }
            };

    private static JavaClasses application;

    @BeforeAll
    static void importClasses() {
        application = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("dev.tessera.iam.application");
    }

    @Test
    @DisplayName("token, refresh, client-credentials, introspect and revoke services depend on ClientProfileCheck")
    void clientAuthenticatingUseCases_applyTheProfileCheck() {
        ArchRule rule = classes()
                .that().implement(TokenUseCase.class)
                .or().implement(RefreshUseCase.class)
                .or().implement(ClientCredentialsUseCase.class)
                .or().implement(IntrospectUseCase.class)
                .or().implement(RevokeUseCase.class)
                .and().haveSimpleNameNotStartingWith("Admitted")
                .should().dependOnClassesThat().areAssignableTo(ClientProfileCheck.class)
                .as("A use case that authenticates a client applies its tenant's profile through ClientProfileCheck");
        rule.check(application);
    }

    @Test
    @DisplayName("every user of the shared client-authentication step depends on ClientProfileCheck")
    void sharedAuthenticationUsers_applyTheProfileCheck() {
        ArchRule rule = classes()
                .that(USE_SHARED_AUTHENTICATION)
                .should().dependOnClassesThat().areAssignableTo(ClientProfileCheck.class)
                .allowEmptyShould(false);
        rule.check(application);
    }
}
