# ADR-IAM-010 — Every tenant gets a security floor and a strong default; FAPI 2.0 is a stricter profile a tenant chooses

| Field | Value |
|---|---|
| Status | **Proposed** |
| Date | 2026-11-04 |
| Relates to | [ADR-IAM-003](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) (where a tenant's settings live; one issuer and discovery document per realm), [ADR-IAM-004](ADR-IAM-004-end-user-session-and-consent.md) (MFA, D8), [ADR-IAM-005](ADR-IAM-005-oidf-basic-op-conformance-in-ci.md) (conformance, D7), [ADR-IAM-006](ADR-IAM-006-standalone-provider-for-many-sites-and-agents.md) (amended by D1), [ADR-IAM-007](ADR-IAM-007-token-exchange-and-agent-delegation-profile.md) (the rule for configuration points, followed by D2), [ADR-IAM-009](ADR-IAM-009-sender-constraint-refresh-binding-and-audience.md) (the token rules for each profile) |

---

## Background

Tessera is a provider other people adopt, in many configurations, and one deployment can serve many tenants. Some adopters need bank-level security, and most need something their ordinary OIDC library can talk to. The maintainers set three rules on 2026-11-04:
- A tenant that needs financial-grade security must be able to have it. The closest published standard is the OpenID Foundation's FAPI 2.0 Security Profile, final version, read at `openid.net/specs/fapi-security-profile-2_0-final.html` on 2026-11-04.
- FAPI cannot be imposed on every adopter, so one tenant's bar does not become everyone's.
- Standards stay high in every configuration. There is no legacy yet, so nothing is kept for compatibility.

So this record separates what every tenant gets from what a tenant may choose.

Path abbreviations as in ADR-IAM-007. Code references are at `main` commit `adbc232`.

### Tessera against the profile today

From reading the code. This is not a conformance result, and no conformance claim is made until D7's plan passes.

**Already met:**

| Profile | Requirement | Tessera |
|---|---|---|
| 5.3.2.2 | `response_type` is `code` | The only value offered (`dom/oidc/OidcCapabilities.java`) |
| 5.3.2.2 | PKCE with `S256` | The only method offered |
| 5.3.2.2 | `iss` in the authorization response | `AuthorizationResponses` |
| 5.3.2.2 | A code is refused if already used | Removed atomically on redemption |
| 5.3.2.2 | 303, never 307, after credentials | `rest/signin/SignInResource.java:128`. `/authorize`'s own redirect is a 302 (`rest/AuthorizeResource.java:206`), which item 11's "should" would have be a 303 (D6) |
| 5.3.2.1 | Code lifetime at most 60 seconds | Default `PT1M` (`rest/config/AuthFlowConfig.java:23`), but configurable upward (D6) |
| 5.3.2.1 | Client assertion `aud` is the issuer only | `rest/token/NimbusClientAssertionVerifier.java:253`. A one-element array also passes; the client rule says a string (D6) |
| 5.3.2.1 | No resource owner password grant | Not offered |
| 5.2.3 | No CORS on the authorization endpoint | `AuthorizeCorsExclusionTest` |
| 5.4.1 | Signing with `PS256`, `ES256` or `EdDSA`; never `none` | `EdDSA` and `ES256` (`dom/signingkey/SigningAlgorithm.java`) |

**Gaps, closed under `fapi2` by D3 to D6:**

| Profile | Requirement | Tessera today |
|---|---|---|
| 5.3.2.1 item 3 | Confidential clients only | Public clients are offered |
| 5.3.2.1 item 6 | `private_key_jwt` or mTLS only | Secrets are the only method on the code and refresh grants (`rest/TokenResource.java:121-122`). mTLS authentication is not built |
| 5.3.2.1 item 4 | Only sender-constrained access tokens | `iam.authflow.require-sender-constraint=false` issues Bearer tokens, and a refresh always does (`api/RefreshService.java`) |
| 5.3.2.1 item 5 | mTLS or DPoP | A confidential client's DPoP proof is ignored (`api/TokenService.java:272`), so a client behind an edge with no client certificates has neither |
| 5.3.2.1 item 12 | Authorization code binding to a DPoP key | `dpop_jkt` is not built |
| 5.3.2.2 items 2-4, 6, 12 | Pushed authorization requests, required | Not built |
| 5.3.2.1 item 9 | No refresh rotation, except in extraordinary circumstances | Every refresh rotates (`api/RefreshService.java:207`) |
| 5.4.1 item 1 | JWTs use `PS256`, `ES256` or `EdDSA` | Client assertions also accept `RS256` (`dom/oidc/OidcCapabilities.java:63`) |
| 5.3.2.1 item 13 | Accept `iat` and `nbf` up to 10 seconds ahead; refuse beyond 60 | A DPoP proof is refused beyond 5 seconds (`rest/config/DpopConfig.java:32`), and its `nbf` is not read |
| 5.3.2.1 item 14 | Restrict a token's privileges to the minimum required (a "should") | See the first defect below |

Not checked, because tessera's code cannot show it: TLS version and cipher suites at the edge (5.2), and the entropy of credentials a deployment creates itself (5.4.1 item 4).

**Two defects found while comparing, on `main` today, whatever the profile:**
1. On the sign-in path a client's registered `allowedScopes` is never checked: only `client_credentials` reads it, and `api/ClientRequestCheck.java` has no scope check. There is no consent screen either (`ConsentService.hasConsented` has no caller). A client can ask for any scope and the token carries it.
2. `POST /login` (`rest/login/LoginResource.java`) has no CSRF token or Fetch Metadata check, so a cross-site post can plant an attacker's session. `SameSite=Strict` only limits that to same-site relying parties.

## D1 — A floor every tenant gets, which no configuration lowers

**Decision.** These hold for every tenant, on every profile, with no setting to turn them off:

| Area | The floor |
|---|---|
| Flow | The code flow with PKCE `S256`. No implicit flow and no password grant |
| Redirects | Exact match. Plain http only on loopback, for public clients |
| Codes | Single use, at most 60 seconds |
| Authorization response | `iss` always present (RFC 9207), and `/authorize` never answers CORS |
| Scopes | A request beyond the client's registered `allowedScopes` is `invalid_scope` |
| Sign-in | The hosted page only. `POST /login` is removed, so a relying party never handles a password. `iam.subject.trust-header` is removed, because with it on `/authorize` issues a code from `X-Subject-Id` with no sign-in, for every tenant in the deployment. Themes (ADR-IAM-008) are how a relying party makes the page its own |
| Public clients | Always bound by DPoP. Never unbound |
| Agents and exchange clients | Authenticate with a key and are always bound (ADR-IAM-007) |
| Audience | An access token for a person names one API and is never the issuer (ADR-IAM-009 D3) |
| Refresh | A refresh proves the binding the grant was issued with (ADR-IAM-009 D2) |
| Signing | Asymmetric only. Never `none` or an HMAC keyed with a public key |
| Discovery | Advertises exactly what this issuer enforces |
| Limits | D6's limits fail startup |

**Consequences.**
1. ADR-IAM-006 D2 is amended: a form served by a relying party and posted to `/login` is no longer possible. A themed hosted page does the same job, and a relying party that still posts there moves first.
2. The two defects above are fixed for everyone, and neither waits for a profile.
3. A new request for a setting below this table needs a change to this record, not a configuration option.

## D2 — A tenant chooses a profile: `standard` by default, or `fapi2`

**Decision.** A tenant has one security profile, and it applies to all its realms. The states are ordered, as ADR-IAM-007's rule for configuration points requires, and neither is below the floor.

| State | Behaviour | Protects | Costs | Who picks | Default |
|---|---|---|---|---|---|
| `standard` | D1, plus secure defaults a mainstream OIDC library can meet: every client binds its tokens unless the operator allows and declares otherwise, and secrets are offered. RFC 9700's requirements hold, except that until consent is enforced "as consented" means what the operator registered (ADR-IAM-009 D3) | Against the threats RFC 9700 covers, for adopters who cannot use FAPI yet | A client on a secret is only as safe as that secret, and one declared `none` gets replayable tokens | Operator | **Yes** |
| `fapi2` | D1, plus the authorization-server part of the FAPI 2.0 Security Profile (D3) | The profile's attacker model | Clients need a backend, a key, DPoP or mTLS, and PAR. Few mainstream libraries do all of that today | Operator; the deployment can also require it (below) | No |

**Where it lives.** It is a column of ADR-IAM-003 D1's tenant registry, which only the administrative role can write. That registry is not built yet, so this work builds its first version. A tenant missing from the registry gets no token, as ADR-IAM-003 D1 says. A tier is a separate question: it covers what a tenant has bought, and a tier never decides the security profile.

**How it is set.** Through ADR-IAM-009 D5's audited declaration, applied as the administrative role, which also registers a new tenant. ADR-IAM-003 D1 consequence 4 is amended so its narrow port also returns the profile. Raising needs nothing more. Lowering also writes its event at warning level, which is ADR-IAM-007's rule 3. `iam.security.minimum-profile`, default `standard`, lets a deployment refuse anything lower for all its tenants: a tenant stored below it is refused at use, and a declaration below it fails startup.

**How it is enforced.** At use, by one domain function given the tenant's profile, the client and the request. A client that does not meet its tenant's profile is `invalid_client`. So raising a tenant needs no migration: its non-conforming clients stop at once on every endpoint that authenticates a client, which fails closed. Stored clients sit behind per-tenant row-level security and cannot be scanned at startup anyway. What is in flight is checked again: a pending sign-in records whether its request was pushed, and sign-in and code redemption refuse one the profile no longer allows. A refused client's refresh families are not deleted and work again if the tenant is lowered, so an operator who means it permanently also moves `grants_valid_after` (ADR-IAM-009 D5).

**What it means for discovery.** Each realm is meant to have its own document (ADR-IAM-003 D3), so each advertises what its tenant's profile enforces, and `OidcCapabilities.enforced` takes the profile. That is not built: today `DiscoveryResource` serves one issuer, publicly cacheable, with no `Vary`, and tenants share `iss` and the assertion `aud`. So until ADR-IAM-003 D3 and D5 ship, `fapi2` is refused in multi-tenant mode at startup and at use, and works in single-tenant mode, where the deployment has one tenant and one document.

**Consequences.**
1. Once ADR-IAM-003 D3 and D5 ship, one deployment can serve a bank-level tenant and an ordinary one side by side. Values set per deployment apply to both, so D6 bounds them, and the weaker tenant cannot widen the stricter one's limits.
2. `fapi2` is built and tested as a named whole. A long list of independent switches would leave combinations nobody has tested.
3. A relying party cannot pick a profile. A request never lowers anything.

## D3 — What `fapi2` requires beyond `standard`

**Decision.**

| | `standard` | `fapi2` |
|---|---|---|
| Client types | Confidential and public | Confidential only |
| Client authentication, on every grant and at `/par`, `/introspect` and `/revoke` | `private_key_jwt`, mTLS once built, or a secret | `private_key_jwt`, or mTLS once built, plus the deviation below |
| Sender constraint | Per client: `dpop` or `mtls`. `none` is off unless `iam.security.allow-unbound-clients` is on, default off, and then an operator may declare it for a confidential client that is not an agent | `dpop` or `mtls`, always |
| Authorization requests | Pushed or direct. A client may be registered to require PAR (RFC 9126 §6) | Pushed only; `/authorize` takes only `client_id` and `request_uri` |
| Refresh tokens | Rotate, with reuse detection | Do not rotate |
| Assertion algorithms | `ES256`, `PS256`, `RS256` | `ES256`, `PS256` |
| Access-token lifetime | As configured, within D6's limit | At most 15 minutes |
| Refresh-token limit | As configured | At most 30 days |

Limits under `fapi2` apply as the lower of the configured value and the limit, because lifetimes are configured per deployment and profiles per tenant. The refresh limit is also checked at each refresh against when the family was created, so a family from before a raise cannot outlive it.

**Deviation from the profile, which a `fapi2` tenant accepts by registering such a client.** A keyless workload-identity assertion stays for clients that act for themselves: `client_credentials`, token exchange under ADR-IAM-007 D1's stricter rule (the credential carries a key or its issuer enforces single use), and authenticating at `/introspect` and `/revoke`. On either profile, such a client is refused at `/par`, at `/authorize` and on the code and refresh grants. The profile names only `private_key_jwt` and mTLS. A workload assertion has the same form (an RFC 7523 JWT, asymmetric, `aud` the issuer) but is signed by a trusted platform's key, not a key registered for the client. It may be presented again until it expires unless the issuer enforces single use (`rest/token/NimbusClientAssertionVerifier.java`), and a platform may sign it with `RS256`.

| | |
|---|---|
| Why it stays | No private key is stored at all, which removes the credential most likely to leak from an agent's environment |
| What it leaves open | Whoever captures an assertion can present it with their own DPoP key and get tokens bound to that key, until the assertion expires. An issuer's lifetime ceiling is at most one hour (`rest/config/ClientAssertionConfig.java`), and `enforce-single-use` is off by default |
| What bounds it | No person signs in through it. A token with a person in `sub` needs ADR-IAM-007 D1's stricter credential. The assertion travels only to tessera over TLS, and is valid only for its issuer as `aud`. Its tokens name one audience and last minutes. A tenant that wants none of this registers no such client |
| How it is tested | D7's plan runs with `private_key_jwt`, so the suite never exercises this method |

## D4 — What is built for every tenant, because `fapi2` needs it

**Decision.** These are capabilities first, offered on `standard` and required on `fapi2`:
- **`private_key_jwt` on the code and refresh grants.** A client needs no shared secret on any profile.
- **DPoP for confidential clients on every grant,** and `dpop_jkt` (RFC 9449 §10). DPoP works behind an edge that cannot forward a client certificate, and mTLS suits a deployment whose clients already hold certificates. `mtls` is refused where the certificate is not believed.
- **A shared `jti` store,** which ADR-IAM-007 D7 describes, required once more than one instance runs. It is keyed by realm, proof key and `jti`, with a cap per realm, so one tenant's traffic cannot crowd out another's. Today's map is keyed by `jti` alone and uncapped.
- **Pushed authorization requests.** `POST /par` (RFC 9126) authenticates the client as `/token` does, and `redirect_uri` is required there. A `request_uri` is single-use, bound to the client and the realm, in the shared store codes already use, with `expires_in` defaulting to 60 seconds. A scope beyond `allowedScopes` is `invalid_scope`, and a `resource` not registered is `invalid_target` (ADR-IAM-009 D3). A `DPoP` header is validated and treated as `dpop_jkt`, and a mismatch between the two is refused (RFC 9449 §10.1). `dpop_jkt`, the scopes and the resources travel in the pending sign-in record to the code. Discovery advertises `pushed_authorization_request_endpoint`, and `require_pushed_authorization_requests: true` only under `fapi2`.

**What it means.** The sign-in session starts when the browser arrives with the `request_uri`, so a slow sign-in is bounded by `iam.authflow.sign-in-ttl` and not by the 60 seconds. Under `standard`, `/authorize` still takes direct requests, with the same checks.

**Consequences.**
1. A client on `standard` can adopt each of these on its own and move up when it is ready. The profile is then a statement of what is already true.
2. Quarkus OIDC 3.40.1.1 can send `private_key_jwt` and has a PAR setting. It shows no client-side DPoP on the code flow in the classes read (`CodeAuthenticationMechanism`, `OidcProviderClientImpl`), but `OidcRequestFilter` can act on its token requests. None of that has been run against tessera. A back-end-for-frontend on it that needs `fapi2` must prove this first, and it is the plan's largest unknown.
3. Signed request objects and FAPI 2.0 Message Signing are not part of this profile and are not adopted (open item 3).

## D5 — Refresh rotation follows the profile

**Decision.** Under `standard` a refresh token rotates, with reuse detection and the optional grace, as it does today (RFC 9700 §4.14). Under `fapi2` it stays the same for the life of its grant, as the profile requires, except in an extraordinary event such as moving tokens to a new format, decided by its own record. A token superseded before a tenant was raised still takes the replay path and burns its family. A family's binding works the same way under both (ADR-IAM-009 D2).

**Why not one behaviour.** A rotating token gives a public client a theft signal, which `standard` should keep for adopters, and the code is built and tested. `fapi2` forbids it. A stolen refresh token under `fapi2` is useless without the client's private key and the grant's sender key.

**What `fapi2` gives up.** A thief holding all three can refresh silently until the token's limit, because no reuse signal exists there. A client should keep its two keys apart, ideally in a key store that does not release them. ADR-IAM-009 D2's mismatch event is the signal that a token may be stolen.

**Consequences.**
1. Revocation has limits under both, and they matter more without rotation. `/revoke` needs the client. `/end_session` with a hint revokes for that client only. `POST /logout` ends only the session. ADR-IAM-009 D5 adds a by-client revocation for the operator.
2. Lowering a tenant from `fapi2` to `standard` starts rotation at each family's next refresh. Raising stops it.
3. Threat model row 2 and the RFC 9700 checklist's rotation row say which profile they apply to.

## D6 — Values that matter are bounded in code

**Decision.**
- **Startup fails, on every profile,** on: a code lifetime above 60 seconds; an `iat`/`nbf` tolerance outside 10 to 60 seconds; a `request_uri` lifetime of 600 seconds or more; an access-token lifetime above one hour; a refresh-token limit above 90 days; a DPoP `proof-max-age` above five minutes; an assertion `max-lifetime` above one hour; a `sign-in-ttl` above one hour; a reuse grace above one minute. ADR-IAM-007 already lists missing bounds as work to do, and these values are shared by every tenant in a deployment.
- A proof's or an assertion's `iat` and `nbf` are accepted up to 10 seconds ahead, on every profile.
- Under `fapi2`, a `private_key_jwt` assertion must use `ES256` or `PS256` with `aud` as a string, except D3's workload assertions.
- A `client_credentials` token names one audience, under ADR-IAM-009's rule A1.
- `/authorize`'s redirect becomes a 303. Discovery gains `authorization_response_iss_parameter_supported` (RFC 9207), and `tls_client_certificate_bound_access_tokens` becomes true only while certificates are believed; today it is always true (`dom/oidc/OidcCapabilities.java`).

**Consequences.** A deployment's edge must offer TLS 1.2 or later and HSTS, which the production profile already sets, with BCP 195 suites under `fapi2`. Tessera's guide states it, and D7's plan checks it.

## D7 — Each profile has its conformance plan

**Decision.** ADR-IAM-005 stands for `standard`: the Basic OP plan, with its secret clients, once its three gaps are closed. A second nightly run, on the same harness, runs `fapi2-security-profile-final-test-plan` against a `fapi2` tenant once PAR ships. It uses `client_auth_type=private_key_jwt`, `sender_constrain=dpop`, `openid=openid_connect` and the `unsigned` request method (variants read from the suite's `FAPI2SPFinalTestPlan.java` on 2026-11-04), and adds the `mtls` variants when mTLS is usable, on a harness where certificates are believed, which ADR-IAM-005's fixed-tenant harness is not. Both block only on a new failure against a committed list. Whether to certify stays a separate decision (ADR-IAM-005 D3).

**Consequences.** Until the plan passes, tessera says "`fapi2` is built to the FAPI 2.0 Security Profile", never "conformant" or "certified".

## D8 — What no profile covers

**Decision.** Choosing `fapi2` secures the protocol. It does not make a tenant equal to a bank. These are recorded so that it is not read as finishing the job. Each needs its own decision, and each should be something a tenant can choose rather than a rule for all:

| Area | Today |
|---|---|
| Strength of user authentication | A password. MFA is out of scope (ADR-IAM-004 D5), and no token carries `acr` (threat model row 16) |
| Custody of token-signing keys | Generated by the application and stored in its database under a master key (`pers/signingkey/DbKeyProviderAdapter.java`), not in a key store that keeps them |
| Consent | No consent screen is shown: `ConsentService.hasConsented` has no caller |
| Durable audit | `TenantAuditLog` has only an in-memory repository and no caller on the token path |
| Client registration | No provisioning surface beyond first boot and ADR-IAM-009 D5's declaration |

## The plan

| Step | Work | For |
|---|---|---|
| 1 | Fix the two defects: scope checks, and remove `POST /login` once its users have moved. Remove `iam.subject.trust-header` | Everyone |
| 2 | The tenant registry's first version, `standard`, `iam.security.minimum-profile` and the one enforcing function | Everyone |
| 3 | `private_key_jwt` on the code and refresh grants | Everyone |
| 4 | Per-client mode, DPoP for confidential clients, a refresh proves the binding, the cut-over migration, the audited writer | Everyone |
| 5 | Per-resource audience | Everyone |
| 6 | PAR, `dpop_jkt`, shared `jti` store | Everyone |
| 7 | `fapi2` as a state: refuse public clients and secrets, no rotation, its limits and algorithms. The name is unknown and fails startup until this ships (ADR-IAM-007 rule 6) | `fapi2` |
| 8 | Conformance plans in CI | Each profile |
| Apart | D6's limits can ship at any point. ADR-IAM-003 D3 and D5 open `fapi2` to multi-tenant mode. D8's areas are decided separately | |

A relying party that needs `fapi2` proves its client library first, because the result can change step 4's shape, and it moves when steps 3 to 7 are in. Step 4's cut-over deploys with every relying party ready (ADR-IAM-009 D4).

## Rejected alternatives

- **One profile for every adopter, FAPI 2.0, with nothing able to turn it off.** This record's first draft. It removes public clients and secrets from a product others adopt, and locks out most mainstream OIDC libraries, because one tenant needs it.
- **`fapi2` as the default, with an opt-down.** The strictest default, but nearly every adopter would opt down on day one, and a setting everyone changes protects nobody.
- **A deployment-wide switch only.** One deployment can serve many tenants with different needs. `iam.security.minimum-profile` keeps the useful part.
- **A profile per client.** Discovery is per issuer, so it could not be truthful, and one weak client would sit under a tenant that claims a strict profile.
- **Independent switches instead of named profiles.** Combinations nobody has tested, and no way to run a conformance plan against "this tenant's settings".
- **Tying security to a tier.** Security would become something a tenant has to buy.
- **Removing rotation everywhere, since RFC 9700 accepts sender-constraint instead.** Simpler code, but it drops a theft signal that adopters on `standard` can use, and the code already exists.
- **Keeping `POST /login`, with CSRF protection added.** It would leave relying parties handling passwords, and the hosted page with themes does the same job (open item 2).
- **A lesser named bar instead of FAPI, such as RFC 9700 alone, as the strict profile.** It allows secrets, Bearer tokens and public clients, which is below what a bank-level tenant needs. It is what `standard` already meets.

## Open items

1. **Whether `standard` offers `none`.** ADR-IAM-007's rule says a state below the floor is not offered, yet a Bearer token for a declared confidential client is what most mainstream back-end-for-frontend libraries can receive today. *Recommendation:* offer it, off by default, per client, operator-declared, audited, counted per issuance, never for a public client or an agent. It needs ADR-IAM-007's rule 1 amended to allow one declared state below the default. The alternative raises the floor and shuts out those libraries, and D7's Basic OP plan, whose clients send no proof, would then need another answer.
2. **Removing `POST /login` for everyone.** *Recommendation:* remove it. If an adopter needs a same-site form, reopen this with CSRF protection in place.
3. **DPoP nonces and FAPI 2.0 Message Signing.** Nonces shorten the window for a replayed proof at the cost of a round trip; the profile lets a server use them and requires a client to support them. Message Signing adds non-repudiation. *Recommendation:* neither at first. Add each as a stricter choice when a tenant's regulation needs it.
4. **D8's areas.** *Recommendation:* decide user authentication first, because it is what a person meets every day and it changes the hosted page.
