// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.in.AuthorizeUseCase.AuthorizeResult;
import dev.tessera.iam.application.port.in.LoginUseCase;
import dev.tessera.iam.application.port.in.LoginUseCase.LoginResult;
import dev.tessera.iam.application.port.in.SignInUseCase.BeginResult;
import dev.tessera.iam.application.port.in.SignInUseCase.Decision;
import dev.tessera.iam.application.port.in.SignInUseCase.DecisionResult;
import dev.tessera.iam.application.port.in.SignInUseCase.FormResult;
import dev.tessera.iam.application.port.in.SignInUseCase.Submission;
import dev.tessera.iam.application.port.in.SignInUseCase.SubmitResult;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.PendingAuthorizationStorePort;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.authcode.CodeChallenge;
import dev.tessera.iam.domain.authcode.PendingAuthorization;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SignInService — validate first, bind to the browser, answer once")
class SignInServiceTest {

    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final String CLIENT_ID = "web-app";
    private static final String REGISTERED = "https://c.example/cb";
    private static final String CHALLENGE = "a".repeat(43);
    private static final String USERNAME = "alice";
    private static final String PASSWORD = "correct";
    private static final String SUBJECT = "sub-alice";
    private static final Duration LIFETIME = Duration.ofMinutes(10);

    private final MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    private final Map<String, PendingAuthorization> entries = new HashMap<>();
    private final AtomicInteger logins = new AtomicInteger();
    private final List<String> authorizedSubjects = new ArrayList<>();
    /** Recorded consents, subject to scopes; the default test subject has consented to openid. */
    private final Map<String, Set<String>> consents = new HashMap<>();
    private Client client = new PublicClient(
            ClientId.generate(), REALM, Set.<GrantType>of(new AuthorizationCode()), Set.of(REGISTERED), Set.of(),
            null, Set.of(), Set.of("https://api.example/"));
    private int secrets;

    private final PendingAuthorizationStorePort store = new PendingAuthorizationStorePort() {
        @Override
        public Uni<Void> store(PendingAuthorization pending) {
            entries.put(pending.transactionId(), pending);
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<PendingAuthorization> find(RealmKey realm, String transactionId) {
            PendingAuthorization entry = entries.get(transactionId);
            return Uni.createFrom().item(entry != null && entry.realm().equals(realm) ? entry : null);
        }

        @Override
        public Uni<PendingAuthorization> consume(RealmKey realm, String transactionId) {
            PendingAuthorization entry = entries.remove(transactionId);
            return Uni.createFrom().item(entry != null && entry.realm().equals(realm) ? entry : null);
        }
    };

    private SignInService service() {
        ClientRepositoryPort clients =
                (realm, clientId) -> Uni.createFrom().item(CLIENT_ID.equals(clientId) ? client : null);
        AuthorizeUseCase authorize = (request, subjectId) -> {
            authorizedSubjects.add(subjectId);
            if (!client.redirectUris().contains(request.redirectUri())) {
                return Uni.createFrom().item(new AuthorizeResult.Failed(AuthorizationError.INVALID_REQUEST, "gone", false));
            }
            Set<String> granted = consents.get(subjectId);
            return Uni.createFrom().item(granted != null && granted.containsAll(request.scopes())
                    ? new AuthorizeResult.Issued("code-1", request.state())
                    : new AuthorizeResult.ConsentRequired());
        };
        ConsentStorePort consentStore = new ConsentStorePort() {
            @Override
            public Uni<Boolean> hasConsent(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
                Set<String> granted = consents.get(subjectId);
                return Uni.createFrom().item(granted != null && granted.containsAll(scopes));
            }

            @Override
            public Uni<Void> grant(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
                consents.put(subjectId, Set.copyOf(scopes));
                return Uni.createFrom().voidItem();
            }
        };
        LoginUseCase login = (realm, username, password) -> {
            logins.incrementAndGet();
            return Uni.createFrom().item(USERNAME.equals(username) && PASSWORD.equals(password)
                    ? new LoginResult.Authenticated(SessionId.generate(), SUBJECT)
                    : new LoginResult.Denied("invalid_credentials"));
        };
        OpaqueIdentifierPort ids = new OpaqueIdentifierPort() {
            @Override
            public String newAuthorizationCode() {
                return "unused";
            }

            @Override
            public String newTokenId() {
                return "unused";
            }

            @Override
            public String newRefreshToken() {
                return "unused";
            }

            @Override
            public UUID newFamilyId() {
                return UUID.randomUUID();
            }

            @Override
            public String newSignInSecret() {
                return "secret-" + (++secrets);
            }
        };
        return new SignInService(clients, consentStore, authorize, login, store, ids, clock, LIFETIME);
    }

    private static AuthorizationRequest request(String clientId, String redirectUri) {
        return new AuthorizationRequest(REALM, clientId, redirectUri, Set.of("openid"), "state-1",
                null, CodeChallenge.s256(CHALLENGE));
    }

    private BeginResult.Started begin() {
        BeginResult result = service().begin(request(CLIENT_ID, REGISTERED)).await().indefinitely();
        assertThat(result).isInstanceOf(BeginResult.Started.class);
        return (BeginResult.Started) result;
    }

    {
        consents.put(SUBJECT, Set.of("openid"));
    }

    private DecisionResult decide(String txn, String binding, String csrf, boolean allow) {
        return service().decide(new Decision(REALM, txn, binding, csrf, allow)).await().indefinitely();
    }

    private String csrf(BeginResult.Started started) {
        return entries.get(started.transactionId()).csrfToken();
    }

    private SubmitResult submit(String txn, String binding, String csrf, String username, String password) {
        return service().submit(new Submission(REALM, txn, binding, csrf, username, password))
                .await().indefinitely();
    }

    @Test
    @DisplayName("an unknown client or unregistered redirect URI is refused before anything is parked")
    void refusesBeforeParking() {
        BeginResult unknown = service().begin(request("other", REGISTERED)).await().indefinitely();
        BeginResult unregistered = service().begin(request(CLIENT_ID, "https://evil.example/cb"))
                .await().indefinitely();

        assertThat(unknown).isInstanceOf(BeginResult.Refused.class);
        assertThat(unregistered).isInstanceOfSatisfying(BeginResult.Refused.class,
                refused -> assertThat(refused.error()).isEqualTo(AuthorizationError.INVALID_REQUEST));
        assertThat(entries).isEmpty();
    }

    @Test
    @DisplayName("a parked request keeps only the hash of the browser binding")
    void storesBindingHashOnly() {
        BeginResult.Started started = begin();

        PendingAuthorization entry = entries.get(started.transactionId());
        assertThat(started.lifetime()).isEqualTo(LIFETIME);
        assertThat(entry.bindingHash()).isNotEqualTo(started.binding());
        assertThat(entry.expiresAt()).isEqualTo(clock.instant().plus(LIFETIME));
    }

    @Test
    @DisplayName("the form is shown only to the browser holding the binding")
    void showRequiresBinding() {
        BeginResult.Started started = begin();

        assertThat(service().show(REALM, started.transactionId(), started.binding()).await().indefinitely())
                .isInstanceOfSatisfying(FormResult.Shown.class,
                        shown -> assertThat(shown.form().redirectUri()).isEqualTo(REGISTERED));
        assertThat(service().show(REALM, started.transactionId(), "another-browser").await().indefinitely())
                .isInstanceOf(FormResult.Unavailable.class);
        assertThat(service().show(REALM, started.transactionId(), null).await().indefinitely())
                .isInstanceOf(FormResult.Unavailable.class);
        RealmKey otherRealm = new RealmKey(TenantId.generate(), BaselineId.generate());
        assertThat(service().show(otherRealm, started.transactionId(), started.binding()).await().indefinitely())
                .isInstanceOf(FormResult.Unavailable.class);
    }

    @Test
    @DisplayName("a correct sign-in answers the parked request once, for the signed-in subject")
    void completesOnce() {
        BeginResult.Started started = begin();
        String csrf = csrf(started);

        SubmitResult first = submit(started.transactionId(), started.binding(), csrf, USERNAME, PASSWORD);
        SubmitResult replay = submit(started.transactionId(), started.binding(), csrf, USERNAME, PASSWORD);

        assertThat(first).isInstanceOfSatisfying(SubmitResult.Completed.class, completed -> {
            assertThat(completed.redirectUri()).isEqualTo(REGISTERED);
            assertThat(completed.code()).isEqualTo("code-1");
            assertThat(completed.state()).isEqualTo("state-1");
        });
        assertThat(replay).isInstanceOf(SubmitResult.Unavailable.class);
        assertThat(authorizedSubjects).containsExactly(SUBJECT);
    }

    @Test
    @DisplayName("a wrong password shows the form again and leaves the transaction usable")
    void wrongPasswordCanBeRetried() {
        BeginResult.Started started = begin();
        String csrf = csrf(started);

        SubmitResult denied = submit(started.transactionId(), started.binding(), csrf, USERNAME, "wrong");
        SubmitResult retried = submit(started.transactionId(), started.binding(), csrf, USERNAME, PASSWORD);

        assertThat(denied).isInstanceOfSatisfying(SubmitResult.Denied.class,
                d -> assertThat(d.form().csrfToken()).isEqualTo(csrf));
        assertThat(retried).isInstanceOf(SubmitResult.Completed.class);
    }

    @Test
    @DisplayName("a wrong binding or synchronizer token is refused before the credential is checked")
    void bindingAndTokenCheckedBeforeCredential() {
        BeginResult.Started started = begin();
        String csrf = csrf(started);

        assertThat(submit(started.transactionId(), "another-browser", csrf, USERNAME, PASSWORD))
                .isInstanceOf(SubmitResult.Unavailable.class);
        assertThat(submit(started.transactionId(), started.binding(), "forged", USERNAME, PASSWORD))
                .isInstanceOf(SubmitResult.Unavailable.class);
        assertThat(submit(started.transactionId(), started.binding(), null, USERNAME, PASSWORD))
                .isInstanceOf(SubmitResult.Unavailable.class);
        assertThat(logins).hasValue(0);
        assertThat(entries).containsKey(started.transactionId());
    }

    @Test
    @DisplayName("an expired transaction can be neither shown nor completed")
    void expiredTransactionIsUnavailable() {
        BeginResult.Started started = begin();
        String csrf = csrf(started);
        clock.advance(LIFETIME);

        assertThat(service().show(REALM, started.transactionId(), started.binding()).await().indefinitely())
                .isInstanceOf(FormResult.Unavailable.class);
        assertThat(submit(started.transactionId(), started.binding(), csrf, USERNAME, PASSWORD))
                .isInstanceOf(SubmitResult.Unavailable.class);
        assertThat(logins).hasValue(0);
    }

    @Test
    @DisplayName("a request whose client changed while the user signed in is refused, not redirected")
    void clientChangedMeanwhile() {
        BeginResult.Started started = begin();
        client = new PublicClient(ClientId.generate(), REALM, Set.<GrantType>of(new AuthorizationCode()),
                Set.of("https://c.example/other"), Set.of(), null, Set.of(), Set.of("https://api.example/"));

        assertThat(submit(started.transactionId(), started.binding(), csrf(started), USERNAME, PASSWORD))
                .isInstanceOf(SubmitResult.Refused.class);
    }

    @Test
    @DisplayName("a submission never renders its password")
    void submissionHidesPassword() {
        assertThat(new Submission(REALM, "t", "b", "c", USERNAME, PASSWORD).toString())
                .doesNotContain(PASSWORD);
    }

    @Test
    @DisplayName("signed in without consent: no code, the request waits for this user's consent under the same transaction")
    void signInWithoutConsentWaitsForIt() {
        consents.clear();
        BeginResult.Started started = begin();
        String csrf = csrf(started);

        SubmitResult result = submit(started.transactionId(), started.binding(), csrf, USERNAME, PASSWORD);

        assertThat(result).isInstanceOfSatisfying(SubmitResult.ConsentNeeded.class, needed -> {
            assertThat(needed.form().transactionId()).isEqualTo(started.transactionId());
            assertThat(needed.form().clientId()).isEqualTo(CLIENT_ID);
            assertThat(needed.form().scopes()).containsExactly("openid");
            assertThat(needed.sessionId()).isNotNull();
        });
        PendingAuthorization waiting = entries.get(started.transactionId());
        assertThat(waiting.subjectId()).isEqualTo(SUBJECT);
        assertThat(waiting.csrfToken()).isEqualTo(csrf);
        assertThat(service().show(REALM, started.transactionId(), started.binding()).await().indefinitely())
                .isInstanceOf(FormResult.ConsentShown.class);
    }

    @Test
    @DisplayName("allow records the consent and answers once with a code; a replayed answer is unavailable")
    void allowRecordsAndAnswersOnce() {
        consents.clear();
        BeginResult.Started started = begin();
        String csrf = csrf(started);
        submit(started.transactionId(), started.binding(), csrf, USERNAME, PASSWORD);

        DecisionResult first = decide(started.transactionId(), started.binding(), csrf, true);
        DecisionResult replay = decide(started.transactionId(), started.binding(), csrf, true);

        assertThat(first).isInstanceOfSatisfying(DecisionResult.Completed.class, completed -> {
            assertThat(completed.code()).isEqualTo("code-1");
            assertThat(completed.redirectUri()).isEqualTo(REGISTERED);
        });
        assertThat(consents.get(SUBJECT)).containsExactly("openid");
        assertThat(replay).isInstanceOf(DecisionResult.Unavailable.class);
    }

    @Test
    @DisplayName("deny answers with access_denied and records nothing")
    void denyRecordsNothing() {
        consents.clear();
        BeginResult.Started started = begin();
        String csrf = csrf(started);
        submit(started.transactionId(), started.binding(), csrf, USERNAME, PASSWORD);

        DecisionResult result = decide(started.transactionId(), started.binding(), csrf, false);

        assertThat(result).isInstanceOfSatisfying(DecisionResult.Declined.class, declined -> {
            assertThat(declined.redirectUri()).isEqualTo(REGISTERED);
            assertThat(declined.state()).isEqualTo("state-1");
        });
        assertThat(consents).isEmpty();
        assertThat(entries).isEmpty();
    }

    @Test
    @DisplayName("an answer needs the binding and the token, and a request that has not signed in cannot be answered")
    void answerNeedsBindingTokenAndASignedInUser() {
        consents.clear();
        BeginResult.Started started = begin();
        String csrf = csrf(started);

        // Before the sign-in there is no subject: an allow posted now must not create one.
        assertThat(decide(started.transactionId(), started.binding(), csrf, true))
                .isInstanceOf(DecisionResult.Unavailable.class);
        assertThat(consents).isEmpty();

        submit(started.transactionId(), started.binding(), csrf, USERNAME, PASSWORD);
        assertThat(decide(started.transactionId(), "another-browser", csrf, true))
                .isInstanceOf(DecisionResult.Unavailable.class);
        assertThat(decide(started.transactionId(), started.binding(), "forged", true))
                .isInstanceOf(DecisionResult.Unavailable.class);
        assertThat(consents).isEmpty();
        assertThat(entries).containsKey(started.transactionId());
    }

    @Test
    @DisplayName("a signed-in request without consent is parked for that user, after the client checks")
    void beginConsentParksForTheUser() {
        consents.clear();
        BeginResult refused = service().beginConsent(request(CLIENT_ID, "https://evil.example/cb"), SUBJECT)
                .await().indefinitely();
        assertThat(refused).isInstanceOf(BeginResult.Refused.class);
        assertThat(entries).isEmpty();

        BeginResult begun = service().beginConsent(request(CLIENT_ID, REGISTERED), SUBJECT).await().indefinitely();
        assertThat(begun).isInstanceOfSatisfying(BeginResult.Started.class, started -> {
            assertThat(entries.get(started.transactionId()).subjectId()).isEqualTo(SUBJECT);
            assertThat(service().show(REALM, started.transactionId(), started.binding()).await().indefinitely())
                    .isInstanceOf(FormResult.ConsentShown.class);
            DecisionResult allowed = decide(started.transactionId(), started.binding(),
                    entries.get(started.transactionId()).csrfToken(), true);
            assertThat(allowed).isInstanceOf(DecisionResult.Completed.class);
        });
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
