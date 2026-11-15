package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Test double for {@link ConsentStorePort} (the persistence-backed store is owned by
 * {@code tessera-persistence}). An in-memory map keyed by {@code (realm, subject, client)}.
 *
 * <p><strong>Consent is assumed for a subject unless a test asks for it to be strict.</strong>
 * Most flow tests are about tokens, not consent, and mint subjects at random; they get a code as
 * before. A test about consent calls {@link #requireConsent} for its subject, which then behaves
 * like the real store: consented only to what it granted. Enforcement itself is proven by
 * {@code AuthorizationServiceTest}, the consent flow test and the Postgres integration test.
 */
@Mock
@ApplicationScoped
public class FakeConsentStore implements ConsentStorePort {

    private final ConcurrentMap<Key, Set<String>> granted = new ConcurrentHashMap<>();
    private final Set<String> strict = ConcurrentHashMap.newKeySet();

    /** From now on, {@code subject} is consented only to what it has granted. */
    public void requireConsent(String subject) {
        strict.add(subject);
    }

    /** Forgets every consent {@code subject} granted, so a test starts from none. */
    public void forget(String subject) {
        granted.keySet().removeIf(key -> key.subjectId().equals(subject));
    }

    @Override
    public Uni<Boolean> hasConsent(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        if (!strict.contains(subjectId)) {
            return Uni.createFrom().item(true);
        }
        Set<String> existing = granted.get(new Key(realm, subjectId, clientId));
        return Uni.createFrom().item(existing != null && existing.containsAll(scopes));
    }

    @Override
    public Uni<Void> grant(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        granted.put(new Key(realm, subjectId, clientId), Set.copyOf(scopes));
        return Uni.createFrom().voidItem();
    }

    private record Key(RealmKey realm, String subjectId, ClientId clientId) {
    }
}
