package dev.tessera.iam.adapter.rest.authcode;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.authcode.CodeChallenge;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("StoredGrant — the grant's resources round-trip, and an entry without them is a miss")
class StoredGrantTest {

    private static final Instant T0 = Instant.parse("2026-11-19T00:00:00Z");

    private static AuthorizationGrant grant() {
        return new AuthorizationGrant(
                new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L))),
                new ClientId(UUID.randomUUID()), "subject", "https://client.example/cb", Set.of("openid"), null,
                CodeChallenge.s256("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"), T0, T0.plusSeconds(120),
                Set.of("https://a.api.example", "https://b.api.example"));
    }

    @Test
    @DisplayName("resources survive the round-trip")
    void roundTrip() {
        AuthorizationGrant decoded = StoredGrant.decode(StoredGrant.encode(grant()));
        assertThat(decoded).isNotNull();
        assertThat(decoded.resources()).containsExactlyInAnyOrder("https://a.api.example", "https://b.api.example");
    }

    @Test
    @DisplayName("a code stored before resources were recorded does not decode (ADR-IAM-009 D4)")
    void entryWithoutResources_isAMiss() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode stored = (ObjectNode) mapper.readTree(StoredGrant.encode(grant()));
        stored.remove("resources");
        assertThat(StoredGrant.decode(mapper.writeValueAsString(stored))).isNull();
    }
}
