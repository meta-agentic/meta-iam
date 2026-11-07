# ADR-IAM-011 — A realm is chosen by its issuer URL, and a realm is one opaque id

| Field | Value |
|---|---|
| Status | **Proposed** |
| Date | 2026-11-07 |
| Amends, once accepted | [ADR-IAM-003](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) D1, D2, D3, D4 and D5; [ADR-IAM-002](ADR-IAM-002-standalone-public-origin.md) D1 consequence 7 and its rejected alternative on the path; [ADR-IAM-005](ADR-IAM-005-oidf-basic-op-conformance-in-ci.md) D1 consequence 2 |
| Relates to | [ADR-IAM-007](ADR-IAM-007-token-exchange-and-agent-delegation-profile.md) (`act.iss`), [ADR-IAM-009](ADR-IAM-009-sender-constraint-refresh-binding-and-audience.md) (audience and the operator's declaration), [ADR-IAM-010](ADR-IAM-010-security-floor-and-tenant-profiles.md) (profiles; `fapi2` waits for per-realm issuers) |

---

## Background

An OpenID Connect client is configured with one thing: an issuer URL. It appends `/.well-known/openid-configuration`, reads the endpoints from the document, and refuses the document if its `issuer` is not identical to the URL it used (OIDC Discovery §4 and §4.3). Tessera must work for that client, because tessera is a provider other people adopt.

In single-tenant mode it does. In multi-tenant mode it does not. The realm comes from two request headers, a tenant id and an optional baseline id, which a gateway is expected to set. A request without them is a `400`, on discovery too, so a client holding only an issuer URL stops at its first request.

Facts the decisions rest on:
- No standard defines these headers. OIDC Core, OIDC Discovery and RFC 6749, 7009, 7517, 7662, 8414, 8707, 9068 and 9449 define no tenant, realm or baseline request header. They do define the answer: a path in the issuer "enables supporting multiple issuers per host", which is "required in some multi-tenant hosting configurations" (RFC 8414 §3, OIDC Discovery §4).
- `TenantResolutionFilter` checks nothing about who set the headers. Whoever reaches the server chooses the realm.
- ADR-IAM-003 planned per-realm issuers and kept the headers as the source of the realm. None of that plan is built. There is no registry, no realm route, and one configured issuer that every mint path, every client-assertion audience and the discovery document share.
- A realm is the pair `(tenant, baseline)`. A baseline is a version of an application's configuration, which no identity standard has a concept of. Seven tables carry `baseline_id`, so a user or a client exists separately per baseline, while signing keys are per tenant. A new configuration version would be a new empty set of users.
- Tokens carry two non-standard claims, `realm_tenant` and `realm_baseline`, because signatures cannot tell two baselines of a tenant apart and `iss` cannot tell two tenants apart.
- `tessera_session` is set with `Path=/`. Rows sit behind row-level security keyed by tenant, so a cookie from one tenant finds nothing in another.

What other identity servers do, read on 2026-11-07:

| Server | How a realm is chosen | What a stock client needs | Source |
|---|---|---|---|
| Keycloak | Path: `/realms/{realm-name}/.well-known/openid-configuration`, and every endpoint below that path. Realms are isolated from one another. The hostname is configured, not resolved from the request, which the guide calls "a security measure". A proxy overwrites forwarded headers | The realm's URL | `keycloak.org/securing-apps/oidc-layers`, `/server/hostname`, `/server/reverseproxy`, Server Administration Guide; pages for the latest version |
| Spring Authorization Server | Path: an issuer with a path component represents the "tenant identifier", and the issuer is the base URL of the protocol endpoints. It answers at both `/issuer1/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server/issuer1` | The issuer URL | `docs.spring.io/spring-authorization-server/reference/guides/how-to-multitenancy.html` |
| Amazon Cognito | Path: `https://cognito-idp.<region>.amazonaws.com/<user pool id>/.well-known/openid-configuration` | The pool's URL | `docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html` |
| Microsoft Entra ID | Path: the tenant is in the authority URL, and the configuration document is the authority plus the well-known path | The authority URL | `learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc` |
| ZITADEL | Host: the `Host` header picks a virtual instance. An ordered, configurable list (`InstanceHostHeaders`, default `x-zitadel-instance-host`) lets a proxy state the host in another header | The instance's URL | `zitadel.com/docs/self-hosting/manage/custom-domain`, `cmd/defaults.yaml` on `main` |

All five put the realm in the URL a client is given. ZITADEL is the one with a configurable header, and what it carries is the host of that URL, so the client's URL still decides.

## D1 — The issuer URL alone chooses the realm

**Decision.** With no fixed realm configured, the issuer of a realm is `base/realms/<opaque id>`, and every route of that realm is below it: discovery, JWKS, `/authorize`, `/token`, `/introspect`, `/revoke`, `/end_session`, the hosted sign-in, consent and logout routes, and `/userinfo` and `/par` when they are built. The RFC 8414 location, `/.well-known/oauth-authorization-server/realms/<opaque id>`, is served as well. The root routes answer `404`, and there is no default realm.

**What it means.** The realm is read from the matched route parameter, checked for form, and looked up in the registry (D1 of ADR-IAM-003). Only then is it bound to `TenantContext`, and only then does the transaction set the row-security variable. Naming a realm is not a credential. It decides whose clients, users and keys a request is checked against, and it grants nothing.

| A caller who names realm B can | A caller who names realm B cannot |
|---|---|
| Read B's discovery document and public keys | Read a row of B without B's credentials |
| See B's hosted sign-in page | Get a token without authenticating as a client or user of B |
| Try a credential against B, under B's budgets | Use a token, code, refresh token, assertion or session from realm A in B |

**Declared states.** One configuration point, `iam.tenancy.fixed-realm`, replaces `iam.tenancy.fixed-tenant`. A malformed value still stops the server at startup.

| State | Set by | Realm comes from | Issuer | Protects | Costs | Who picks it |
|---|---|---|---|---|---|---|
| Fixed realm | `iam.tenancy.fixed-realm=<id>` | Configuration; a request cannot influence it | `base`, with routes at the root; `/realms/*` is `404` | The smallest attack surface | One realm per deployment | A deployment for one organisation, or a central provider with one user base |
| Realms by URL | Unset | The issuer URL | `base/realms/<id>`, with routes below it; the root is `404` | Many realms on one origin, each a standard issuer | A registry, and one key set per realm | A deployment hosting separate organisations |

Both states are at the floor of ADR-IAM-010, and in both a request header decides nothing. Moving between them changes `iss`, so ADR-IAM-003 D3 consequences 4 and 5 stand.

**Consequences.**
1. A stock client signs in to any realm with its issuer URL and nothing else, as the walkthrough below shows.
2. Fail-closed tenancy keeps its shape. An unknown or malformed id is the same `404` and touches no tenant data. A registry read error is a `503`, never a default. A realm that is not bound leaves rows invisible under `FORCE ROW LEVEL SECURITY`, as today.
3. The raw path is not parsed. Encoded `/`, dot segments, matrix parameters and case variants are refused, as ADR-IAM-003 D2 consequence 2 requires. The forwarded-prefix setting stays off.
4. One function derives the issuer from the configured base and the realm id, and never from `Host`. `UseCaseProducer` stops handing one issuer string to the services, and every mint path, `AuthorizationResponses` (the `iss` of RFC 9207), `NimbusClientAssertionVerifier` and `DiscoveryDocument` asks that function.
5. A client assertion's `aud` is its realm's issuer. An assertion made for realm A is refused in realm B at the audience check, before any replay store. A workload's platform token must be minted for that audience. The global uniqueness of a workload's issuer and subject stays.
6. `iam.oidc.issuer` keeps its meaning as `base`, and `IssuerConsistencyCheck` compares bases. A proxy keeps the realm path byte for byte (ADR-IAM-003 D3 consequence 8).
7. Cookies move to `Path=/realms/<id>/`. Today a sign-in to a second realm in the same browser overwrites the first realm's session cookie. A cookie cannot reach another realm's routes, and row-level security stays the second barrier.
8. Realm resolution runs before the rate limiter, so an unknown id could cost a registry read for free. The registry port caches answers, negative ones too, with a bound. A rate-limit bucket is created only for a known realm, so random ids grow no state.
9. The per-tenant Argon2 share keeps its documented limit: several flooded realms together can fill the global cap. A caller could already do that with the headers, and the global cap stays the limit.
10. Discovery and JWKS have distinct URLs per realm, so the shared-cache defect of ADR-IAM-003 D5 consequence 3 ends, and `Vary` is not needed in either state.
11. `fapi2` opens to deployments with many realms, as ADR-IAM-010 D2 provides, because each realm has its own document.

**Why this reverses ADR-IAM-002 and ADR-IAM-003.** Those records rejected "the path as the tenant source" because it "lets the caller choose the tenant". That holds if the choice is an authority. On a provider that a stranger's browser must reach before anyone has signed in, the choice cannot be an authority, and tessera does not treat it as one: the boundaries are per-realm credentials, per-realm keys and row-level security. The header gave no stronger boundary, because nothing checks who sent it.

## D2 — A realm is one opaque id; baseline leaves tessera

**Decision.** `RealmKey(tenant, baseline)` becomes one server-minted opaque id. `BaselineId`, the `baseline_id` columns, the `realm_tenant` and `realm_baseline` claims and the zero-baseline convention are removed. The registry of ADR-IAM-003 D1 holds realms: id, tier, status and security profile. Tessera has no concept above a realm.

**What it means.** A user, a client, a session and a key set belong to a realm, and `(iss, sub)` identifies one user, as OIDC Core §2 expects. An application that versions its configuration keeps those versions in its own services. One that wants to separate staging from production uses two realms. One that groups realms by customer keeps that grouping itself.

**Consequences.**
1. The schema is edited in place and databases are recreated. No release carries data that must survive, so there is no backfill.
2. The row-security column and variable keep their mechanism and take the realm's name.
3. Signing keys are per realm. The D3 amendment's gap in ADR-IAM-003, where signatures could not separate two baselines, is gone. One key set per realm counts against the KMS quota (ADR-IAM-003 D4 consequence 6).
4. D4b's second check is `iss`: introspection and `id_token_hint` compare it with the request's realm. A token without `iss` or `exp` is inactive. So tenants keep two independent boundaries, keys and `iss`, and neither is a custom claim.
5. A relying party that needs its own tenant in a token gets it from a per-user claim through `ClaimSourcePort`, or maps `iss` itself. A relying party that reads `realm_tenant` must move first, so the per-user claim ships before the claims are removed.
6. Tier and security profile are per realm. Where ADR-IAM-010 says "tenant", read "realm". ADR-IAM-009 D5's declaration is keyed by realm and client. `act.iss` in ADR-IAM-007 is unchanged, because it was always the issuer URL.
7. The change is wide and mostly mechanical: 46 main source files mention a baseline, 30 of them through the type, the column or the claim, and 96 main and 48 test files use `RealmKey`.

## D3 — Tessera reads no realm-selecting header, and has no extension point for one

**Decision.** `TenantHeaders` and its header names are removed from code, OpenAPI, `application.properties`, the performance scripts, and the README, which documents the two states instead. No configuration names a header, and no resolver port is added. A forged header has nothing to read it.

**What it means.** A gateway in front of tessera is an ordinary OIDC client (ADR-IAM-002) or a plain router. It may terminate TLS, route, and rate-limit. It does not select a realm for tessera. What a deployment's gateway asserts to its own services is that deployment's business, in that deployment's configuration.

**Consequences.**
1. Every adopter gets the same security story: the tessera code that chooses a realm is small, public and the same everywhere.
2. A test sends each former header, and any other, to each route: with a realm path it changes nothing, and with no realm path it is a `404`. A build rule refuses a read of such a header in the realm filter.
3. Conformance has one route to test, and the result applies to every deployment.
4. An adopter who wanted a custom header writes a route rule that rewrites the path instead, which is a standard proxy feature. The issuer stays the canonical URL, as consequence 6 of D1 requires.

**Why not a configurable header, off by default.** It looks like a free compatibility option and it is not. A stock client calling a shared URL with a header added by the edge gets one of two answers. If `iss` is the shared base, two realms share `(iss, sub)`, which ADR-IAM-003 D3 forbids. If `iss` is the realm's URL, the client aborts at the check of OIDC Discovery §4.3. So such a header can serve only clients written for it. Keeping the floor would also take a proof that the sender is the edge, such as mTLS, plus `Vary` or `private` caching and a second conformance run, all for a state no known deployment uses.

**What would reopen this.** An adopter with a real deployment where the realm cannot be in the URL its clients use. The state would then have to be off by default, name its header only in that deployment's configuration, require an authenticated connection from the edge or fail startup, set `Vary` to that name, and keep the realm's own `iss`.

## D4 — Compatibility is proven by a stock client and the conformance suite

**Decision.** Two tests prove this record, and it is not implemented until both run.

1. **Stock clients, on every build.** Two unmodified libraries in different languages, `openid-client` for Node and Quarkus OIDC, each given only an issuer URL and client credentials, complete sign-in and refresh against a server with two realms in the realms-by-URL state. No test helper sets a header. The first uses `client.discovery(issuer, …)`, which by default reads the OIDC location and refuses an `issuer` that differs (read in `openid-client` and `oauth4webapi` sources, `main`, on 2026-11-07). Each client is also run against the RFC 8414 location.
2. **The OpenID Foundation suite, nightly.** ADR-IAM-005's harness stops needing fixed-tenant mode. The Basic OP plan runs against a realm's issuer, and also against a fixed realm, under ADR-IAM-005's rule on a committed list of known failures. ADR-IAM-005's three gaps still come first: nothing here is a conformance claim until then.

**Consequences.**
1. A failure-path matrix runs beside them, one behaviour and one input per case, in two real realms under real row-level security: a token, a code, a refresh token, an assertion and a session cookie from realm A, each presented in realm B; an unknown id; a malformed id; and a spoofed `Host`, generalising `DiscoveryEndpointTest.issuerIsConfiguredNotHost`.
2. Stock clients must still meet the floor. PKCE, a `nonce` and a registered sender constraint are tessera's rules, not realm rules, and the test clients are registered to fit them.

## What a stock client does, step by step

The client knows an issuer URL and its own credentials.

```mermaid
sequenceDiagram
    participant C as Stock client
    participant B as Browser
    participant T as Tessera
    participant R as Registry
    C->>T: GET /realms/4f9c/.well-known/openid-configuration
    T->>R: look up 4f9c (unknown is 404, read error is 503)
    R-->>T: realm, status
    T-->>C: issuer = base/realms/4f9c, identical to the URL held
    C->>B: redirect to /realms/4f9c/authorize (PKCE, nonce)
    B->>T: sign in, cookies below /realms/4f9c/
    T-->>B: redirect with code, state, iss
    B->>C: code, state, iss
    C->>T: POST /realms/4f9c/token
    T-->>C: tokens, iss = base/realms/4f9c, signed by the realm's key
    C->>T: GET /realms/4f9c/jwks
    T-->>C: the realm's public keys
```

**Today, multi-tenant.** No realm has a URL of its own, so the client can only hold the shared base.
1. `GET /.well-known/openid-configuration` carries no tenant header, because the client has none to send, and the answer is a `400`.
2. Sign-in cannot start.

**With this record.** The client holds `https://id.example/realms/4f9c`.
1. `GET /realms/4f9c/.well-known/openid-configuration`. The server looks up `4f9c`, and the document's `issuer` is the URL the client holds, so validation passes.
2. The browser goes to `/realms/4f9c/authorize` with PKCE and a `nonce`. No session means the hosted sign-in, whose cookies are below the realm's path.
3. The user signs in. The redirect carries `code`, `state` and `iss`, which the client compares (RFC 9207).
4. The client posts to `/realms/4f9c/token`. A client assertion, if used, names the issuer as `aud`.
5. The client fetches `/realms/4f9c/jwks`, verifies the ID token and compares `iss`.
6. A later refresh goes to the same `/token`. Nothing in any step was tessera-specific.

**With a configurable header instead.** Step 1 goes to a shared URL, with a header added by an edge. The answer's `issuer` then either differs from the URL, so the client aborts, or is shared by every realm, so `(iss, sub)` no longer identifies a user. If the edge routes by host, so that the URL differs per realm, then the URL is what chooses and the header adds nothing.

**With baseline removed and the headers kept.** The client's path is the same as today's multi-tenant path. D2 alone does not help a stock client, which is why D1 and D2 go together: D1 makes a realm reachable, and D2 makes one URL mean one realm.

## Order of work

| Step | Change | Needs |
|---|---|---|
| 1 | The per-user claim from `ClaimSourcePort`, so relying parties can leave the realm claims | Nothing |
| 2 | Remove baseline: one realm id, schema edited in place, claims removed | Step 1 |
| 3 | The registry, holding realms | Step 2 |
| 4 | Issuer per realm, realm routes, cookies, audience, headers removed | Step 3 |
| 5 | Per-realm discovery and JWKS, the RFC 8414 location, the TTL-under-dwell check | Step 4 |
| 6 | Stock-client tests in the build, conformance against a realm's issuer | Step 5, and ADR-IAM-005's gaps for conformance |

Single-tenant deployments keep working at every step. Until step 4, the existing multi-tenant mode keeps its cache defect, and its discovery and JWKS answers should be `Cache-Control: private` rather than naming the headers in `Vary`.

## Rejected alternatives

- **Rename the header to `X-Realm`.** It is still a header no standard client sends, and RFC 6648 deprecates the prefix.
- **A configurable trusted header, off by default.** See D3.
- **A realm-resolver port for deployments to implement.** The same outcome for a stock client as a header, and a security decision moved into code the project does not review.
- **Keep the path-must-agree rule of ADR-IAM-003 D2.** It leaves every stock client dependent on a gateway, and a request with both has one fact stated twice.
- **Keep baseline as a hidden second key, always zero.** Dead columns, and a second id every reader must learn is meaningless.
- **Keep a tenant above the realm.** Nothing in the standards or the code needs it once a realm is one id, and a deployment can group realms itself.
- **Choose the realm from a query parameter, `login_hint` or `acr_values`.** A client does not send one at discovery, and the keys differ per realm before any sign-in.
- **Per-realm subdomains by default.** ADR-IAM-003's reasons stand: DNS, certificates and internal addressing per realm.

## Open items

1. **How the routes are declared.** JAX-RS gives a class one path, and fixed-realm mode serves the same resources at the root. A sub-resource locator is the likely shape. Whether Quarkus REST applies the name-bound `TenantScoped` filter across a locator must be shown by a test before step 4 is planned. A pre-matching rewrite is the fallback, and it needs ADR-IAM-003 D2 consequence 2's refusals before it.
2. **A realm's own issuer name.** Some adopters will want `https://id.acme.example` for one realm. Keycloak's realm settings have a Frontend URL field. It would be a declared, verified value in the registry, and it is left out until someone needs it.
3. **The client-certificate header.** `X-Client-Certificate` is the same kind of custom name, though off by default and already generic. RFC 9440 defines `Client-Cert` for this, with rules on removing a client's own value (§2.4). Moving to it is a separate, small change.
4. **Review status.** This record has had no independent security review and no implementation. Acceptance is the maintainers' decision.
