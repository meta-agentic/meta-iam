package dev.tessera.iam.application.refresh;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.RefreshService;
import dev.tessera.iam.application.StandardProfiles;
import dev.tessera.iam.application.port.in.RefreshUseCase.RefreshCommand;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ClientSecretPresentation;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.RefreshToken;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshDecision;
import dev.tessera.iam.domain.refresh.RefreshReuseDetection;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.token.ClaimSet;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Rule A2 (ADR-IAM-009 D3) against a client whose registered list changes after the grant: an
 * audience removed from the client leaves its families at once, one added later never enters them,
 * and a refusal leaves the live refresh token unspent.
 */
@DisplayName("RefreshService — rule A2 follows the client's current audiences")
class RefreshAudienceTest {

    private static final String A = "https://a.api.example";
    private static final String B = "https://b.api.example";
    private static final String C = "https://c.api.example";
    private static final String ISSUER = "https://issuer.test";
    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final RealmKey REALM =
            new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L)));
    private static final ClientId CLIENT_ID = new ClientId(UUID.randomUUID());

    private Set<String> registered = Set.of(A, B);
    private final List<ClaimSet> accessTokens = new ArrayList<>();
    private final FamilyStore store = new FamilyStore();

    private RefreshService service() {
        return new RefreshService(
                (realm, clientId) -> Uni.createFrom().item(new ConfidentialClient(CLIENT_ID, realm,
                        Set.of(new AuthorizationCode(), new RefreshToken()),
                        ClientAuthMethod.CLIENT_SECRET_POST, Set.of("https://c/cb"), Set.of(), Set.of(), List.of(),
                        Set.of(), null, Set.of(), registered)),
                (realm, clientId, presented) -> Uni.createFrom().item(Boolean.TRUE),
                (realm, typ, claims) -> {
                    if ("at+jwt".equals(typ)) {
                        accessTokens.add(claims);
                    }
                    return Uni.createFrom().item("signed.jwt");
                },
                new OpaqueIdentifierPort() {
                    @Override public String newAuthorizationCode() { return "code"; }
                    @Override public String newTokenId() { return "jti"; }
                    @Override public String newRefreshToken() { return "next-" + UUID.randomUUID(); }
                    @Override public UUID newFamilyId() { return UUID.randomUUID(); }
                    @Override public String newSignInSecret() { return UUID.randomUUID().toString(); }
                },
                store,
                id -> Uni.createFrom().item(Optional.of(REALM)),
                Clock.fixed(T0, ZoneOffset.UTC), ISSUER, Duration.ofMinutes(5), true,
                StandardProfiles.NO_USER_PROFILES, StandardProfiles.CHECK);
    }

    private String seed(Set<String> granted) {
        FamilyId fid = new FamilyId(UUID.randomUUID());
        String secret = "seed-" + UUID.randomUUID();
        store.family = new RefreshTokenFamily(fid, REALM, UUID.randomUUID().toString(), CLIENT_ID,
                RefreshTokenCodec.sha256(secret), null, 0, false, T0, T0.plusSeconds(3600), null, null,
                Set.of(), granted);
        return RefreshTokenCodec.assemble(fid, secret);
    }

    private TokenResult refresh(String wire, List<String> resources) {
        return service().redeem(new RefreshCommand(REALM, wire, "client", "secret",
                ClientSecretPresentation.POST, null, resources)).await().indefinitely();
    }

    private Object lastAudience() {
        return accessTokens.get(accessTokens.size() - 1).claims().get("aud");
    }

    @Test
    @DisplayName("an audience removed from the client leaves the family at once")
    void removedAudience_leavesTheFamily() {
        String wire = seed(Set.of(A, B));
        registered = Set.of(A);

        assertThat(refresh(wire, List.of(B))).isEqualTo(new TokenResult.Failed(
                AuthorizationError.INVALID_TARGET, "the requested resource was not granted to this client"));
        TokenResult issued = refresh(wire, List.of());
        assertThat(issued).as("the refusal did not spend the token").isInstanceOf(TokenResult.Issued.class);
        assertThat(lastAudience()).asString().contains(A).doesNotContain(B);
    }

    @Test
    @DisplayName("with every granted audience removed, the refresh is refused and the token stays live")
    void allAudiencesRemoved_refusedWithoutSpending() {
        String wire = seed(Set.of(A));
        registered = Set.of(B);

        assertThat(refresh(wire, List.of())).isInstanceOf(TokenResult.Failed.class);
        assertThat(store.family.generation()).as("nothing rotated").isZero();
        registered = Set.of(A);
        assertThat(refresh(wire, List.of())).isInstanceOf(TokenResult.Issued.class);
    }

    @Test
    @DisplayName("an audience registered after the grant never enters the family")
    void laterAudience_neverEnters() {
        String wire = seed(Set.of(A));
        registered = Set.of(A, C);

        assertThat(refresh(wire, List.of(C))).isInstanceOf(TokenResult.Failed.class);
        assertThat(refresh(wire, List.of())).isInstanceOf(TokenResult.Issued.class);
        assertThat(lastAudience()).asString().contains(A).doesNotContain(C).doesNotContain(ISSUER);
    }

    @Test
    @DisplayName("a family created before resources were recorded mints no token for a person")
    void legacyFamily_mintsNothing() {
        String wire = seed(Set.of());
        assertThat(refresh(wire, List.of())).isInstanceOf(TokenResult.Failed.class);
    }

    private static final class FamilyStore implements RefreshTokenStorePort {
        RefreshTokenFamily family;

        @Override
        public Uni<Void> createFamily(RefreshTokenFamily created) {
            family = created;
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<RefreshConsumeOutcome> consumeAndRotate(FamilyId id, RealmKey realm,
                String presentedHash, String newTokenHash, Instant now, Duration reuseGrace,
                String rotationSalt) {
            RefreshDecision decision = RefreshReuseDetection.classify(family, presentedHash, now, reuseGrace);
            if (decision instanceof RefreshDecision.Rotate) {
                family = family.rotatedTo(newTokenHash, now, rotationSalt);
            } else if (decision instanceof RefreshDecision.Replay) {
                family = family.burned();
            }
            return Uni.createFrom().item(new RefreshConsumeOutcome(decision, family));
        }

        @Override
        public Uni<Void> revokeFamily(FamilyId id, RealmKey realm) {
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<Void> revokeFamiliesOf(RealmKey realm, String userId, ClientId clientId, Instant createdBefore) {
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<RefreshTokenFamily> find(FamilyId id, RealmKey realm) {
            return Uni.createFrom().item(family);
        }
    }
}
