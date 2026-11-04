# ADR-IAM-010 — The FAPI 2.0 Security Profile is tessera's baseline: confidential clients, no shared secrets, pushed requests, bound tokens, no refresh rotation

| Field | Value |
|---|---|
| Status | **Proposed**. The maintainers adopted the profile as the baseline on 2026-11-04 (D1). The other decisions are proposed for acceptance |
| Date | 2026-11-04 |
| Relates to | [ADR-IAM-004](ADR-IAM-004-end-user-session-and-consent.md) (MFA, D9), [ADR-IAM-005](ADR-IAM-005-oidf-basic-op-conformance-in-ci.md) (amended by D8), [ADR-IAM-006](ADR-IAM-006-standalone-provider-for-many-sites-and-agents.md) (amended by D2), [ADR-IAM-007](ADR-IAM-007-token-exchange-and-agent-delegation-profile.md) (amended by D4 and D5), [ADR-IAM-009](ADR-IAM-009-sender-constraint-refresh-binding-and-audience.md) (applies D4 and D6) |

---

## Background

The maintainers set the bar on 2026-11-04: there is no legacy and no backward compatibility to keep yet, and security must be no lower than banks and financial services. The closest published standard is the OpenID Foundation's FAPI 2.0 Security Profile, final version, read at `openid.net/specs/fapi-security-profile-2_0-final.html` on 2026-11-04.

Path abbreviations as in ADR-IAM-007. Code references are at `main` commit `adbc232`. This comparison comes from reading the code. It is not a conformance result, and tessera makes no conformance claim until D8's suite passes.

### Already met

| Profile | Requirement | Tessera |
|---|---|---|
| 5.3.2.2 | `response_type` is `code` | The only value offered (`dom/oidc/OidcCapabilities.java`) |
| 5.3.2.2 | PKCE with `S256` | The only method offered |
| 5.3.2.2 | `iss` in the authorization response | `AuthorizationResponses` |
| 5.3.2.2 | A code is refused if already used | Removed atomically on redemption |
| 5.3.2.2 | 303, never 307, after credentials | `rest/signin/SignInResource.java:128`. `/authorize`'s own redirect is a 302 (`rest/AuthorizeResource.java:206`), which item 11's "should" would have be a 303 (D7) |
| 5.3.2.1 | Code lifetime at most 60 seconds | Default `PT1M` (`rest/config/AuthFlowConfig.java:23`), but configurable upward (D7) |
| 5.3.2.1 | Client assertion `aud` is the issuer only | `rest/token/NimbusClientAssertionVerifier.java:253`. A one-element array also passes; the client rule says a string (D7) |
| 5.3.2.1 | No resource owner password grant | Not offered |
| 5.2.3 | No CORS on the authorization endpoint | `AuthorizeCorsExclusionTest` |
| 5.4.1 | Signing with `PS256`, `ES256` or `EdDSA`; never `none` | `EdDSA` and `ES256` (`dom/signingkey/SigningAlgorithm.java`) |

### Gaps

| Profile | Requirement | Tessera today | Closed by |
|---|---|---|---|
| 5.3.2.1 item 3 | Confidential clients only | `PublicClient` exists, and discovery and the README offer it | D2 |
| 5.3.2.1 item 6 | `private_key_jwt` or mTLS only | Secrets are the only method on the code and refresh grants (`rest/TokenResource.java:121-122`). mTLS authentication is not built | D3 |
| 5.3.2.1 item 4 | Only sender-constrained access tokens | `iam.authflow.require-sender-constraint=false` issues Bearer tokens, and a refresh always does (`api/RefreshService.java`) | D4 |
| 5.3.2.1 item 5 | mTLS or DPoP | A confidential client's DPoP proof is ignored (`api/TokenService.java:272`), so a client behind an edge with no client certificates has neither | D4 |
| 5.3.2.1 item 12 | Authorization code binding to a DPoP key | `dpop_jkt` is not built | D4 |
| 5.3.2.2 items 2-4, 6, 12 | Pushed authorization requests, required | Not built; `/authorize` takes its parameters directly (`rest/AuthorizeResource.java:102-109`) | D5 |
| 5.3.2.1 item 9 | No refresh rotation, except in extraordinary circumstances | Every refresh rotates (`api/RefreshService.java:207`) | D6 |
| 5.4.1 item 1 | JWTs use `PS256`, `ES256` or `EdDSA` | Client assertions also accept `RS256` (`dom/oidc/OidcCapabilities.java:63`) | D7 |
| 5.3.2.1 item 13 | Accept `iat` and `nbf` up to 10 seconds ahead; refuse beyond 60 | A DPoP proof is refused beyond 5 seconds (`rest/config/DpopConfig.java:32`), and its `nbf` is not read | D7 |
| 5.3.2.1 item 14 | Restrict a token's privileges to the minimum required (a "should") | On the sign-in path a client's registered `allowedScopes` is never checked: only `client_credentials` reads it, and `api/ClientRequestCheck.java` has no scope check. There is no consent screen either (`ConsentService.hasConsented` has no caller). A client can ask for any scope and the token carries it | D5, D9 |

Not checked, because tessera's code cannot show it: TLS version and cipher suites at the edge (5.2), and the entropy of credentials a deployment creates itself (5.4.1 item 4).

Who this touches today: the one running deployment has one client on the sign-in path, a confidential back-end-for-frontend that holds a shared secret and receives Bearer tokens. It has no public client.

## D1 — The baseline is the whole authorization-server part of the profile, and configuration cannot lower it

**Decision.** Tessera meets the profile's requirements on authorization servers, for every client and every grant. There is one profile: no tier, mode or flag turns it off. Configuration can only make a value stricter, and a value outside the profile fails startup. A deviation exists only as a row in this record, with its reason. D3 has the only one today.

There is no carry-over. A change that removes a capability removes it. Rows and refresh tokens that no longer meet the baseline are migrated to something stricter or revoked, never adopted. An access token already issued cannot be recalled, and lives out its lifetime of minutes.

**Consequences.**
1. ADR-IAM-007's rule that no configuration state weakens security now holds for the whole provider, not only for delegation.
2. An operator accepts one forced sign-in for every user when the changes in the plan deploy.
3. New work is judged against the profile. A proposal that needs a relaxation needs a deviation row first.

## D2 — Confidential clients only

**Decision.** `PublicClient` is removed from the domain and refused at registration. A browser or native application signs in through a backend it trusts, which is the confidential client. Public-client rows are deleted by a migration, with their refresh tokens.

**What it removes.** `client_id`-only access at `/revoke` (`api/RevokeService.java`; `api/ClientAuthentication.java:85`), the loopback redirect exception, DPoP as the way a client with no credentials proves itself, and any reason to allow an origin at `/token` through CORS.

**Consequences.**
1. A relying party with no backend, such as a static single-page site, needs one before it can use tessera. That is the real cost of this decision.
2. ADR-IAM-006 D1 is amended: a relying party is a confidential client registration. ADR-IAM-006 does not itself require public clients, so its many-sites model stands.
3. ADR-IAM-006 D2 is amended: `POST /login` (`rest/login/LoginResource.java`) is removed, with the allowed origins of `TESSERA_CORS_ORIGINS`. The hosted page is then the only sign-in path, so a relying party never handles a password. The endpoint has no CSRF token or Fetch Metadata check today, so a cross-site post can plant an attacker's session, which `SameSite=Strict` only limits to same-site relying parties.

## D3 — Clients authenticate with a key; shared secrets are removed

**Decision.** The sign-in path, meaning the code and refresh grants, accepts `private_key_jwt`, and mTLS once RFC 8705 §2 matching is built. `CLIENT_SECRET_BASIC` and `CLIENT_SECRET_POST` are removed once the last client has moved. They exist until then only so the provider can be built in order, and nothing new may register with them.

**Deviation.** A keyless workload-identity assertion stays for clients that act for themselves: `client_credentials`, token exchange under ADR-IAM-007 D1's stricter rule (the credential carries a key or its issuer enforces single use), and authenticating at `/introspect` and `/revoke`. Such a client is refused at `/par` and on the code and refresh grants. The profile names only `private_key_jwt` and mTLS. A workload assertion has the same form (an RFC 7523 JWT, asymmetric, `aud` the issuer) but is signed by a trusted platform's key, not a key registered for the client. It may also be presented again until it expires unless the issuer enforces single use (`rest/token/NimbusClientAssertionVerifier.java`), and a platform may sign it with `RS256`, which D7 otherwise removes.

| | |
|---|---|
| Why it stays | No private key is stored at all, which removes the credential most likely to leak from an agent's environment |
| What it leaves open | Whoever captures an assertion can present it with their own DPoP key and get tokens bound to that key, until the assertion expires. An issuer's lifetime ceiling is at most one hour (`rest/config/ClientAssertionConfig.java`), and `enforce-single-use` is off by default |
| What bounds it | No person signs in through it. A token with a person in `sub` needs ADR-IAM-007 D1's stricter credential. The assertion travels only to tessera over TLS, and is valid only for its issuer as `aud`. Its tokens name one audience and last minutes (D7). A deployment that needs more sets `enforce-single-use` where the platform supports it |
| How it is tested | D8's plan runs with `private_key_jwt`, so the suite never exercises this method |

**Consequences.**
1. A client holding a long-lived private key needs custody for it, ideally a key store that signs without releasing it. Rotation is by publishing a new key in the client's JWK Set, with no sign-out.
2. Quarkus OIDC, which the running deployment's back-end-for-frontend uses, can send `private_key_jwt` on the code flow (read from `quarkus-oidc` 3.40.1.1, `OidcProviderClientImpl`). Sending it with that deployment's key has not been run.
3. Rejected in favour of this: extending workload identity to the sign-in path. It would widen the deviation to tokens for people, for a client that can hold a key.

## D4 — Every access token is sender-constrained, per client, by DPoP or mTLS

**Decision.** A client's mode is `dpop` or `mtls`, and it is required. `none` does not exist, and `iam.authflow.require-sender-constraint` is removed. DPoP is offered to every client on every grant. `dpop_jkt` is built, and the shared `jti` store that ADR-IAM-007 D7 describes is required once more than one instance runs. ADR-IAM-009 holds the rule table and the refresh path.

**Why both.** DPoP works behind an edge that cannot forward a client certificate. mTLS suits a deployment whose clients already hold certificates. Neither is below the other, and the profile allows both. `mtls` is refused where the certificate is not believed.

**DPoP nonce.** The profile lets a server use one and requires a client to support one. Tessera does not issue nonces in this plan. The profile's section 6.2 names proof replay as the risk they reduce, so this is open item 1.

**Consequences.**
1. Quarkus OIDC 3.40.1.1 shows no client-side DPoP on the code flow in the classes read (`CodeAuthenticationMechanism`, `OidcProviderClientImpl`), but `OidcRequestFilter` can act on its token requests. A back-end-for-frontend on it must add the proof there, and whether the library accepts a `token_type` of `DPoP` has not been checked. This is the plan's largest unknown, and step 4 proves it first.
2. ADR-IAM-007 D5 is amended: its restriction of the flag is moot, because the flag is gone, and its `dpop_jkt` moves from `/authorize` to `/par` (D5).

## D5 — Authorization requests are pushed

**Decision.** `POST /par` (RFC 9126) takes the full request and authenticates the client as `/token` does. `/authorize` accepts only `client_id` and `request_uri` and refuses anything else. `redirect_uri` is required at `/par`. A `request_uri` is single-use and bound to the client, in the shared store codes already use, with `expires_in` defaulting to 60 seconds; a configured value of 600 or more fails startup. Discovery advertises `pushed_authorization_request_endpoint` and `require_pushed_authorization_requests: true`.

`/par` is where a request is judged. A scope beyond the client's registered `allowedScopes` is `invalid_scope`. A `resource` not registered is `invalid_target` (ADR-IAM-009 D3). A client that cannot use the code grant (D3's workload clients) is refused. A `DPoP` header on the request is validated and treated as `dpop_jkt`, and a mismatch between the two is refused (RFC 9449 §10.1). The store key includes the realm, as a code's does.

**What it means.** The sign-in session starts when the browser arrives with the `request_uri`, so a slow sign-in is bounded by `iam.authflow.sign-in-ttl` and not by the 60 seconds. `dpop_jkt`, the scopes and the resources travel in the pending sign-in record to the code, and a test covers that path. Errors return as JSON to the backend before a browser is involved.

**Consequences.**
1. Request parameters leave the browser's URL and history.
2. Quarkus OIDC 3.40.1.1 has a `PushedAuthorizationRequest` setting and a client path for it. It has not been run against tessera.
3. Signed request objects are not part of this profile. The separate FAPI 2.0 Message Signing profile is not adopted (open item 2).

## D6 — A refresh token does not rotate

**Decision.** A refresh token stays the same for the life of its grant, bound to the client through client authentication and to the grant's key (ADR-IAM-009 D2). Rotation, reuse detection, the reuse grace and the successor key are removed. The only allowed exception is the profile's: an extraordinary event such as moving tokens to a new format, decided by its own record.

**Why this is safe.** Rotation existed because a public client's refresh token was its only proof (RFC 9700 §2.2.2 requires rotation or sender-constraint for those clients). With D2 and D3, a stolen refresh token is useless without the client's private key and the grant's sender key.

**What it leaves.** A thief holding all three can refresh silently until the token's absolute limit, because nothing like a reuse signal exists any more. D7 caps that limit. A client should keep its two keys apart, ideally in a key store that does not release them.

**What it removes.** `consumeAndRotate`, `RefreshReuseDetection`, `RefreshDecision`, `RefreshTokenCodec.successorSecret`, `iam.refresh.reuse-grace`, the successor-key secret, and from `refresh_token_family` the columns `previous_token_hash`, `generation`, `rotated_at`, `rotation_salt` and `reused`. `revoked_at` becomes the family's only revocation flag, and readers of `reused` (`api/IntrospectService.java:110`) move to it. `iam.refresh.refresh-token-ttl` stays as an absolute limit (`rest/config/RefreshConfig.java:26`). Threat model row 2 and the RFC 9700 checklist's rotation row change with it.

**Consequences.**
1. Concurrent refreshes from several instances of a client no longer race and no longer sign a user out, so client-side workarounds for that can go.
2. Revocation today has limits, and they matter more without rotation. `/revoke` needs the client. `/end_session` with a hint revokes for that client only. `POST /logout` ends only the session. An operator has no surface to revoke by client, which ADR-IAM-009 D5 adds.
3. There is no reuse signal any more. ADR-IAM-009 D2's mismatch event is the signal that a token may be stolen.

## D7 — Values the profile bounds are bounded in code

**Decision.** `private_key_jwt` accepts `ES256` and `PS256`; `RS256` is removed, except on D3's workload assertions, and `aud` must be a string. A proof's or an assertion's `iat` and `nbf` are accepted up to 10 seconds ahead. Each of these fails startup: a code lifetime above 60 seconds, an `iat`/`nbf` tolerance outside 10 to 60 seconds, a `request_uri` lifetime of 600 seconds or more, an access-token lifetime above 15 minutes, a refresh-token limit above 30 days. A `client_credentials` token names one audience, under ADR-IAM-009's rule A1. `/authorize`'s redirect becomes a 303. Discovery gains `authorization_response_iss_parameter_supported` (RFC 9207), and `tls_client_certificate_bound_access_tokens` becomes true only while certificates are believed; today it is always true (`dom/oidc/OidcCapabilities.java`).

**Consequences.**
1. A client that signs with `RS256` must move to `PS256` or `ES256`.
2. A deployment's edge must offer TLS 1.2 or later with BCP 195 suites, and HSTS, which the production profile already sets. Tessera's guide states it, and the suite in D8 checks it.

## D8 — The FAPI 2.0 conformance plan runs in CI, in place of the Basic OP plan

**Decision.** Once D5 ships, `fapi2-security-profile-final-test-plan` runs self-hosted and nightly, on the harness ADR-IAM-005 D1 describes, and blocks only on a new failure against a committed list. It runs with `client_auth_type=private_key_jwt`, `sender_constrain=dpop`, `openid=openid_connect` and the `unsigned` request method (variants read from the suite's `FAPI2SPFinalTestPlan.java` on 2026-11-04). The `mtls` variants are added when mTLS is usable. Whether to certify stays a separate decision (ADR-IAM-005 D3).

ADR-IAM-005 D1 is amended: its plan needs static secret clients, which D3 removes. Its three gaps (hosted page, session-aware `prompt`/`max_age`/`auth_time`, `/userinfo`) are not closed by this record. Which of them the FAPI plan's OpenID Connect variant requires is found on its first run. Whether the Basic plan could run without a secret was not checked.

**Consequences.** Until the suite passes, tessera says "built to the FAPI 2.0 Security Profile", never "conformant" or "certified".

## D9 — What the profile does not cover is still below the bar

**Decision.** The profile secures the protocol. It does not make tessera equal to a bank. These are recorded here so that adopting it is not read as finishing the job, and each needs its own decision:

| Area | Today |
|---|---|
| Strength of user authentication | A password. MFA is out of scope (ADR-IAM-004 D5), and no token carries `acr` (threat model row 16) |
| Custody of token-signing keys | Generated by the application and stored in its database under a master key (`pers/signingkey/DbKeyProviderAdapter.java`), not in a key store that keeps them |
| Consent | No consent screen is shown: `ConsentService.hasConsented` has no caller. The profile requires a client to act only with a user's consent, and leaves the server's part open |
| Durable audit | `TenantAuditLog` has only an in-memory repository and no caller on the token path |
| Client registration | No provisioning surface beyond first boot and ADR-IAM-009 D5's declaration |

## The plan

Each step closes the gaps it names and depends on the ones before it, unless stated.

| Step | Work | Closes |
|---|---|---|
| 1 | `private_key_jwt` on the code and refresh grants | D3 for tessera |
| 2 | Per-client mode, DPoP for confidential clients, refresh proves the binding, no rotation, cut-over migration | D4, D6, ADR-IAM-009 D1, D2, D4, D5 |
| 3 | Pushed authorization requests, `dpop_jkt`, shared `jti` store | D4, D5 |
| 4 | The running back-end-for-frontend moves to an assertion, DPoP and PAR. Prove DPoP on its library first, because the result can change step 2's shape | D3, D4, D5 for that client |
| 5 | Per-resource audience | ADR-IAM-009 D3 |
| 6 | Remove public clients, secret methods, the flag and `POST /login`. Apply D7's bounds | D1, D2, D3, D7 |
| 7 | The conformance plan in CI | D8 |
| Apart | Decide D9's areas | D9 |

Steps 2 to 6 deploy together on any running deployment, because a client that has not moved is refused. Old instances are drained first (ADR-IAM-009 D4).

## Rejected alternatives

- **Two profiles, FAPI for some clients and plain OAuth for others.** A deployment's security would then be its weakest registered client, and that is the switch this record removes.
- **Keeping public clients with DPoP and rotation.** Current best practice for plain OAuth, but the profile excludes them by name.
- **Keeping secrets for conformance runs or first boot.** A test-only method is still a method in the shipped code.
- **Keeping rotation as defence in depth.** The profile says not to, and rotation is what signs users out when requests race.
- **`mtls` only.** It needs an edge that forwards certificates, which common managed platforms do not provide.
- **`dpop` only.** It would exclude deployments whose clients already hold certificates, with no security gain.
- **A lesser named bar, such as RFC 9700 alone.** It allows secrets, Bearer tokens and public clients, which is below what the maintainers asked for.
- **Adopting the profile without an ADR, one fix at a time.** Public clients, rotation and the conformance plan interlock and would be re-argued piece by piece.

## Open items

1. **DPoP nonces.** They shorten the window for a replayed proof at the cost of a round trip. *Recommendation:* leave them out at first, and require clients to support them as the profile does, so they can be turned on without changing clients.
2. **FAPI 2.0 Message Signing.** It adds non-repudiation of requests and responses. *Recommendation:* do not adopt it until a customer's regulation needs it.
3. **D9's areas.** *Recommendation:* decide user authentication first, because it is what a person meets every day and it changes the hosted page.
