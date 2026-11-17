package dev.tessera.iam.domain.client;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.ClientCredentials;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.SecurityProfile;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.Test;

@DisplayName("ProfileConformance — whether a client meets its tenant's profile (ADR-IAM-010 D3)")
class ProfileConformanceTest {

    private static final RealmKey REALM = new RealmKey(TenantId.generate(), new BaselineId(new UUID(0L, 0L)));

    private static ConfidentialClient confidential(ClientAuthMethod method) {
        return new ConfidentialClient(new ClientId(UUID.randomUUID()), REALM, Set.of(new ClientCredentials()),
                method, Set.of(), Set.of(), Set.of(), List.of(), Set.of(), null);
    }

    private static PublicClient publicClient() {
        return new PublicClient(new ClientId(UUID.randomUUID()), REALM, Set.of(new AuthorizationCode()),
                Set.of("https://app.example/cb"));
    }

    @ParameterizedTest
    @EnumSource(ClientAuthMethod.class)
    @DisplayName("standard: every confidential client meets it, for either use")
    void standard_confidential(ClientAuthMethod method) {
        for (ClientUse use : ClientUse.values()) {
            assertThat(ProfileConformance.check(SecurityProfile.STANDARD, confidential(method), use).meets()).isTrue();
        }
    }

    @Test
    @DisplayName("standard: a public client meets it")
    void standard_public() {
        assertThat(ProfileConformance.check(SecurityProfile.STANDARD, publicClient(), ClientUse.ACTS_FOR_PERSON)
                .meets()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(ClientAuthMethod.class)
    @DisplayName("fapi2 is not available yet, so no client meets it")
    void fapi2_unavailable_meetsNone(ClientAuthMethod method) {
        for (ClientUse use : ClientUse.values()) {
            assertThat(ProfileConformance.check(SecurityProfile.FAPI2, confidential(method), use).meets()).isFalse();
        }
        assertThat(ProfileConformance.check(SecurityProfile.FAPI2, publicClient(), ClientUse.ACTS_FOR_PERSON)
                .meets()).isFalse();
    }
}
