# ADR-IAM-009 — Every token is bound under a per-client mode, a refresh proves that binding, and `aud` names the API a token is for

| Field | Value |
|---|---|
| Status | **Proposed** |
| Date | 2026-11-04 |
| Relates to | [ADR-IAM-010](ADR-IAM-010-fapi-2-security-profile-baseline.md) (the baseline this record applies), [ADR-IAM-003](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) (realm claims and issuer; D4b ratified by this record), [ADR-IAM-006](ADR-IAM-006-standalone-provider-for-many-sites-and-agents.md) (many relying parties), [ADR-IAM-007](ADR-IAM-007-token-exchange-and-agent-delegation-profile.md) (delegation; this record supplies the refresh path its D2 and D5 require), [threat model](../security/threat-model.md) row 14 and [the `iss`/`aud` decision](../security/threat-model.md#the-introspection-iss--aud-decision), [RFC 9700 checklist](../security/rfc9700-checklist.md) |

---

## Background

Tessera made sender-constraining mandatory: DPoP for public clients, a client certificate for confidential clients. It later added one switch, `iam.authflow.require-sender-constraint`, for a back-end-for-frontend relying party behind a TLS-terminating edge, which cannot present a certificate. Neither step was recorded in an ADR.

ADR-IAM-010 makes the FAPI 2.0 Security Profile the baseline, with no carry-over. It decides that clients are confidential, that every token is bound, and that a refresh token does not rotate. This record is the detail of how: the rule for each client, the refresh path, and the audience. It replaces an earlier draft of this record that kept a deployment switch, a `none` mode and adoption rules for older tokens.

Three defects meet on the token path:
1. The switch applies to the whole deployment, and turning it off issues tokens anyone can replay.
2. A refresh always mints an unbound token, so any binding holds only until the first refresh.
3. `aud` is the issuer on every code and refresh token, so a token for one API is valid at every API that accepts the issuer as audience.

Path abbreviations as in ADR-IAM-007. Code references are at `main` commit `adbc232`.

Facts the decisions rest on:
- `resolveBinding` requires a DPoP proof of a public client and a certificate of a confidential one, unless the flag is `false` and the client does not authenticate by mTLS (`api/TokenService.java:272-305`). A confidential client's DPoP proof is ignored. `client_credentials` repeats the rule (`api/ClientCredentialsService.java:152-161`).
- A refresh mints without `cnf`, with empty scope, without realm claims, with `aud` the issuer, and always answers `Bearer` (`api/RefreshService.java`). The refresh command carries neither a proof nor a certificate (`rest/TokenResource.java:148`). `RefreshBindingDowngradeProbeTest`, added with this record, reproduces this over HTTP.
- A family stores no binding and no audience (`dom/refresh/RefreshTokenFamily.java`; `mig/V3__iam_core_entities.sql`, `mig/V6`, `mig/V7`).
- `oauth_client.audiences` means what a client's `client_credentials` tokens may name, on its own behalf (`mig/V8__oauth_client_credentials_registration.sql`). `client_credentials` is its only reader (`api/ClientCredentialsService.java:142-151`). A client may hold that grant and the code grant together, so a value there says nothing about tokens for a person. `/authorize` takes no `resource` (`rest/AuthorizeResource.java:102-109`), and `/token` passes `resource` only to `client_credentials`.
- Introspection echoes neither `iss`, `aud` nor `cnf`, and reports `Bearer` for every access token (`rest/token/JwsAccessTokenIntrospector.java`; `api/IntrospectService.java`).
- Any confidential client in the realm gets `active:true` for another client's live refresh token, with its `sub` (`api/IntrospectService.java`), and `IntrospectFlowTest.activeRefreshTokenAndSupersededInactive` pins that.
- The audit log (`TenantAuditLog`) has no caller on any token path, and its only repository is in memory.
- The only client writer in the code is first-boot provisioning. It requires a fixed tenant and skips a client that already exists (`pers/bootstrap/FirstBootProvisioner.java`). Every other client write today is raw SQL.

Inputs that are not code:
- The maintainers answered the threat model's open `iss`/`aud` question on 2026-10-29: access tokens name the API they are for, through RFC 8707 `resource`; introspection echoes `iss`, `aud` and the `act` chain; ADR-IAM-003 D4b is ratified as part of this design. D3 implements that answer. ADR-IAM-010 D5 moves `resource` from `/authorize` to `/par`.
- ADR-IAM-003 no longer carries the open question that coupled `iss` and `aud`. The coupling itself is still in the code (`api/TokenService.java:224,227`).

## What the RFC text says

Read from the plain text at rfc-editor.org on 2026-11-04.

| Source | What it says | What it does not say |
|---|---|---|
| RFC 9449 §5 | A proof is required on every access token request for a DPoP-bound token, the refresh grant included. A confidential client's refresh token is not bound to the proof key, because client authentication already constrains it, which allows the key to change. An invalid proof is `invalid_dpop_proof`. | It names no error for a valid proof with the wrong key at refresh. It does not forbid a server being stricter. |
| RFC 8705 §7.1, §6.3 | A refresh token is bound to the client, and so indirectly to a certificate only for clients that authenticate by certificate. | Nothing covers a key-authenticated client that presents a certificate. No section defines a token type for a certificate-bound token. |
| RFC 8707 §2, §2.1, §2.2, §3 | `resource` is an absolute URI without a fragment and may repeat. `invalid_target` is the error. With none, a server MAY use a default or MAY fail with `invalid_target`. A refresh token stays bound to the full original grant even when an access token names a subset. A server SHOULD audience-restrict. | It defines no metadata member. It has no rule for a refresh that omits `resource`. |
| RFC 9700 §2.3, §4.14.2 | A refresh token MUST be bound to the scope and resource servers consented to. Access tokens SHOULD be audience-restricted. | |
| RFC 9068 §3, §4, §5 | With `resource`, `aud` SHOULD equal it. Without it, a default resource indicator MUST be used. A resource server MUST reject a token that does not name it. A server MUST use distinct `aud` values for distinct resources. | |
| RFC 6749 §6 | A requested scope MUST NOT exceed what was granted, and an omitted scope is treated as equal to it. | |
| RFC 7662 §2.2, §4 | If a token can be used only at certain resource servers, the server MUST determine whether it can be used at the one calling. It MAY answer different callers differently. | |
| RFC 9449 §6.2 | A resource server sends no proof to introspection, and the server does not validate the binding there. The resource server checks it locally from `cnf`. `token_type`, if present, MUST be `DPoP`. | |

So the answer to "does the refreshed token bind to the key in the refresh proof, or must it match the original?" is that the RFCs allow a confidential client's key to change, and tessera chooses not to allow that (D2).

## The rule table

Every client authentication by mode by grant. `Certificate` means a certificate tessera believes: the trust switch is on and the mode is not single-tenant. The audience rules A1 and A2 are in D3. Failures are under the table.

| # | Client authenticates by | Mode | Code grant: required, then `cnf` | Refresh must prove | Refreshed token binds to | Audience: code / refresh |
|---|---|---|---|---|---|---|
| 1 | `private_key_jwt` | `dpop` | Assertion and DPoP proof; `cnf.jkt`; `token_type` `DPoP` | Assertion and a proof for the grant's `jkt` | The same `jkt` | A1 / A2 |
| 2 | `private_key_jwt` | `mtls` | Assertion and certificate; `cnf["x5t#S256"]`; `Bearer` | Assertion and the grant's certificate | The same thumbprint | A1 / A2 |
| 3 | mTLS | `mtls` | Refused, `invalid_client`, until certificate matching is built. Then the certificate authenticates and binds | Refused until then. Its rule is written with certificate matching | The same thumbprint | A1 / A2 |
| 4 | mTLS | `dpop` | Refused at write and by a `CHECK` | never reached | never minted | none |
| 5 | Workload identity | either | Refused at `/par` and here, `invalid_client`. This client acts for itself: `client_credentials`, and token exchange under ADR-IAM-007 D1's stricter rule (ADR-IAM-010 D3) | Refused: it holds no refresh token | never minted on these grants | none |
| 6 | Secret, until ADR-IAM-010 D3 removes it | either | As rows 1 and 2, with the secret in place of the assertion | The same | The same | A1 / A2 |

`client_credentials` follows the same modes through the same function. It has no refresh token. Its audiences stay `oauth_client.audiences`, and it now names one of them, by A1's choice: today a request with no `resource` gets them all (`api/ClientCredentialsService.java:146-148`). Clients registered as agents, or for the exchange grant, follow these rows by how they authenticate; ADR-IAM-007's extra requirements on them still apply.

Failures, none of which change the grant:
- **Code grant.** A missing or invalid proof is `invalid_dpop_proof`. A missing certificate is `invalid_request`. Both are today's answers. A proof that does not match the request's `dpop_jkt` is `invalid_dpop_proof` (RFC 9449 §10 requires the refusal and names no error).
- **Refresh.** A proof failing validation is `invalid_dpop_proof` (RFC 9449 §5). A missing proof, a missing certificate, or a valid proof for another key is `invalid_grant`, with the same body as every other refresh failure.
- **Use of a stored `mtls` where the certificate is not believed.** `invalid_client`, with its event.

## D1 — The mode is per client and required

**Decision.** `oauth_client.sender_constraint` is `dpop` or `mtls`, not null, with no default. `iam.authflow.require-sender-constraint` is removed. One pure domain function decides the binding from the client and the presented proofs, and all three mint paths call it, so they cannot disagree.

**What it means.** A request never selects a mode. A `dpop` client that sends a certificate is still refused without a proof, and at the code grant an `mtls` client's DPoP proof is ignored.

**Consequences.**
1. The rule "a token with no `cnf` is rejected at the resource server" is true without exception, because no such token is issued.
2. `mtls` is usable only where the certificate is believed. In single-tenant mode, or with the trust switch off, the writer of D5 refuses it and a declared value fails startup. Stored rows sit behind per-tenant row-level security and cannot be scanned at startup, so a stored `mtls` is refused at use.
3. Each of these is a structured event with client, realm and grant, and no token material, plus a counter tagged by client and reason (`IamMetrics`): a binding mismatch or missing proof (expected method, presented thumbprint), and a certificate required but not believed. They go through the same log as other token-path security events until the audit log has a caller there. Alerting on the mismatch counter is the operator's detection of a stolen token.
4. Discovery advertises `dpop_signing_alg_values_supported`, and `tls_client_certificate_bound_access_tokens` only while the trust switch is on (ADR-IAM-010 D7).
5. A relying party on `dpop` must send a proof whose `htu` is the configured public token endpoint, compared exactly (`rest/token/NimbusDpopProofValidator.java`), not an address behind its edge. If it calls APIs with the token, it must send proofs to them too.
6. A relying party with several instances must share one DPoP key across them, or pin each session to an instance.
7. When client metadata is accepted at registration, `dpop_bound_access_tokens` true (RFC 9449 §5.2) is the same statement as `dpop`, and the two cannot disagree.
8. ADR-IAM-007 D5 consequence 3 says a resource server refuses a token with `cnf` presented as `Bearer`. An mTLS-bound token is exactly that, and RFC 8705 gives it no other type. That sentence holds for `cnf.jkt` only, and needs that small correction when this record is accepted.

## D2 — A refresh proves the grant's binding, and the new access token keeps it

**Decision.** A refresh token's family persists the binding decided at the first issuance: `binding_method` and `binding_thumbprint`, both not null. Every refresh must prove exactly that binding before anything is minted. The new access token carries the same `cnf`, the matching `token_type`, the realm claims and the family's granted scope, or a requested subset of it; a wider request is `invalid_scope` (RFC 6749 §6). A subset narrows that token only. The refresh token itself does not change (ADR-IAM-010 D6). A binding never moves to another key. A mismatch is `invalid_grant`, and the family is not revoked.

**The order on the refresh path.**
1. Take the realm from the request, as every other token path does, and authenticate the client: failure is `invalid_client`. No token lookup comes first, so an unknown token and a known one cannot answer differently here.
2. Validate the proof the client's mode requires. This depends on nothing about the token, so it reveals nothing.
3. Load the family and compare the token's secret with its stored hash in constant time. An unknown, expired or revoked token, a wrong secret, a token issued to another client, or a family created before the client's `grants_valid_after` (D5) is `invalid_grant`.
4. Check the binding: the family's method and thumbprint against what was presented. If the client's mode has changed since (D5), the family's method still decides, and a proof step 2 did not validate is validated here. An invalid one is `invalid_grant`.
5. Only then check the audience (D3) and the scope. A holder who has not proved the binding learns nothing from `invalid_target` or `invalid_scope`.
6. Mint. Nothing about the family is written on a refresh, so concurrent refreshes cannot conflict.

**Consequences.**
1. What a thief gets, by what they hold:

   | Holds | Gets |
   |---|---|
   | Refresh token, with or without the sender key | `invalid_client` |
   | Sender key | Nothing without an access token |
   | Client key, with or without the sender key | No existing grant. A new flow still needs a user to sign in, and the code goes to a registered redirect |
   | Refresh token and client key | The refresh is refused and writes the mismatch event. `/introspect` shows the token's `sub`, and `/revoke` signs that user out of this client. Both are the client's own rights, so both write an event |
   | All three | Silent refreshing until the absolute limit (ADR-IAM-010 D6, what it leaves) |

2. A DPoP key change on a grant means a new sign-in for that grant's user, or running old and new keys side by side until the old grants end. A change of the client's authentication key needs neither, because that key is checked per request against the client's current JWK Set. This goes beyond what RFC 9449 requires and is declared (open item 2).
3. ADR-IAM-007 D2 consequence 4 and D5 get what they require: a persisted, continuity-checked `cnf`, with the scope and the realm. `act` is added by the exchange change.
4. `RefreshBindingDowngradeProbeTest` then fails and is replaced by tests of this rule.

**Why strict, when the RFC allows a change.**
- A rebind would let whoever holds the refresh token and the client's authentication key move the grant to a key of their own. Strict continuity makes them steal the sender key as well, which can sit in a separate key store.
- ADR-IAM-007 requires it on the delegation paths, and one rule is simpler than two.

**Why no revocation on mismatch.** At step 4 the client has already authenticated, so a mismatch is either an operator's mistake at the scale of a whole client (an edge that stops forwarding certificates, an instance with the wrong DPoP key) or a stolen client key. Refusing recovers when a mistake is fixed, and revoking would sign out every user of that client. If it is a theft, the presenter gets nothing, the event is written at warning level, and the operator can revoke the client's grants through D5.

## D3 — `aud` is one resource from the client's registered list; a refresh never widens it

**Decision.**
- **Registered audiences.** `oauth_client.user_audiences` lists what tokens for a person may name. It is not null, and it starts empty. `oauth_client.audiences` keeps its meaning and stays with `client_credentials`; neither column feeds the other. Matching is by exact string, with no normalisation. A value must be an absolute URI with no fragment (RFC 8707 §2) and is never the realm's issuer. An empty list means the client can obtain no token for a person, so clearing a compromised client's list refuses it.
- **At `/par`.** `resource` may repeat. Each value must be registered, otherwise `invalid_target`, as JSON to the client (ADR-IAM-010 D5). The grant stores the named set, or the whole list if none was named. An empty list is `invalid_target` (RFC 8707 §2.1 allows this).
- **Rule A1, at `/token` for a code.** The candidates are the grant's set intersected with the client's current list. At most one `resource`, and it must be a candidate; more than one is `invalid_target`. With none named, a single candidate is used. Several candidates with none named, or no candidates at all, is `invalid_target`.
- **Rule A2, at refresh.** The family stores the full grant's set in `granted_resources`, not null, not the subset the first token named (RFC 8707 §2.2). The candidates are that set intersected with the client's current list, and A1's choice applies, after the binding check (D2). Audiences registered later never enter a family, and audiences removed later leave it at once.

**What it means.** Each access token for a person names exactly one resource, and it is never the issuer. A resource that receives a token cannot replay it at another (RFC 8707 §3). This matches ADR-IAM-007 D3's rule of one audience for delegated tokens and its permitted resource set.

**Introspection.** As the maintainers decided, the active response echoes `iss`, `aud` (string or array), `cnf`, the true `token_type`, and `act` once ADR-IAM-007 ships. Beyond their answer (open item 3), tessera also compares `aud`, because per-resource audiences make the check of RFC 7662 §4 applicable:
- `oauth_client.resource_identifier` is the attribute ADR-IAM-007 D2 and D7 already call for. A caller with no identifier is answered `active:false` for any token not issued to it.
- A caller gets `active:true` for an access token only if its identifier is in `aud`, or the token was issued to it. Otherwise `active:false`, with no other member.
- The binding is not checked here. The call carries no proof and RFC 9449 §6.2 leaves it to the resource server, so a gateway that introspects must itself check `cnf` and `token_type` against the request.
- A refresh token has no `aud`. It is `active:true` only to the client it was issued to, and `IntrospectFlowTest.activeRefreshTokenAndSupersededInactive` changes.

ADR-IAM-003 D4b is ratified, without its transition:
- Both mint paths stamp the realm claims.
- Introspection compares realm and `iss` from the start, and a token with no realm claims, `iss` or `exp` is inactive (today one with no `exp` is active, `api/IntrospectService.java:127`). D4b's emit-then-enforce phases protected tokens already in circulation, and the cut-over of D4 leaves none that matter: refresh tokens are deleted, and an older access token lives out its minutes and then fails.
- Threat model row 14 moves to pinned, `issAndAudAreNotAssertedByIntrospection` is replaced, and the threat model's position that the server does not assert audience is replaced by this section.

**Consequences.**
1. Discovery gains nothing: RFC 8707 defines no metadata member.
2. A client that registers several audiences must name one on every token request, including refresh. Asking for the list's first entry would give list order a hidden meaning.
3. A resource server's `client_id` allow-list, kept today as a workaround for `aud` being the issuer, can go, because it now accepts only its own audience.
4. A back-end-for-frontend that calls no API with the token still needs an entry, and registers its own public URL. Whether its library reads the access token's `aud` is checked when it moves (ADR-IAM-010 plan, step 4).
5. ID tokens are unchanged: their `aud` is the client. A UserInfo endpoint, when built, is a resource with its own audience.
6. An issuer change no longer changes `aud`, so ADR-IAM-003's open upgrade item gets smaller.
7. The consent screen naming resources belongs to the consent work of ADR-IAM-007 D4. Until consent is enforced, "as consented" in RFC 9700 §4.14.2 is what the operator registered.
8. Scope inference (RFC 9068 §3 SHOULD) is not implemented: tessera has no mapping from scope to resource, and the registered list stands in for one. This is a deliberate deviation.
9. For ADR-IAM-007 D3, an actor's registered audiences are `user_audiences` on a token for a person, and `audiences` on an autonomous root's token.

## D4 — The change is a cut-over

**Decision.** Nothing carries over. Old instances are drained first, then one migration runs. Like V14 it lifts row-level security inside its own transaction, because it crosses every tenant:
- Adds `sender_constraint`, setting `mtls` on a client that authenticates by mTLS and `dpop` on every other client, then makes it not null. `dpop` is the strictest value usable on every deployment, and a client that cannot prove it fails closed.
- Adds `user_audiences`, not null, empty, and a nullable `resource_identifier` and `grants_valid_after`.
- Deletes every refresh token family, then adds the not-null `binding_method`, `binding_thumbprint` and `granted_resources`, makes `granted_scope` not null, and drops the columns ADR-IAM-010 D6 names. A `CHECK` limits `binding_method` to `dpop` and `mtls`.
- Drops `refresh_family_directory`, with `RefreshTokenTenantResolverPort`: it existed so a replayed token could be traced to its realm, and there is no replay signal any more.
- Adds the history table of D5, and where D5 stores the highest declaration revision applied.

An authorization code in flight that decodes with no resources is refused.

**What it means.** Every user signs in once more. A client that has not been given audiences through D5 gets `invalid_target`, and one that does not send proofs gets `invalid_dpop_proof`, so a running relying party must be ready in the same deployment. There is no mixed-version window to defend: an old instance with the flag off still mints Bearer tokens on `client_credentials` and on code grants, which dropping columns would not stop, so the deployment drains old instances before the migration, and no database fence is built.

**Consequences.**
1. Rolling back needs a restore, because the families are gone. Their users would sign in again anyway, so the loss is small, and it fails closed.
2. `quarkus.flyway.migrate-at-start` is on, so the first new instance deletes the families. Deploying that release is the operator's decision, so its release notes and the deployment plan say so, and it ships in the deployment that also moves the relying parties (ADR-IAM-010 plan).
3. Implementation order is ADR-IAM-010's plan: the policy function with D2, the writer of D5, D1's stored mode together with D4's migration, then D3.

## D5 — One operator-only, audited writer for a client's mode and audiences

**Decision.** One application use case writes `sender_constraint`, `user_audiences`, `resource_identifier` and `grants_valid_after`, and it applies every write refusal of D1 and D3. `grants_valid_after` is a time: a family created before it is refused at refresh, which is how an operator revokes a whole client without a network endpoint. Its first caller is a declaration the operator owns, keyed by tenant, baseline and client id, applied at startup. It updates those four columns on an existing client and nothing else. There is no network endpoint. A provisioning API, when one is built, calls the same use case and brings its own authentication. Every change appends a row to a history table (client, column, old value, new value, database role, time), written by a database trigger on those columns, so a raw SQL write is recorded too. The application's database role holds no `UPDATE` or `DELETE` on the history table, as ADR-IAM-003 D1 consequence 3 does for its record, and a test pins that.

**What it means.**
- The operator is whoever controls the deployment's configuration. A restart is the act. That holds on a managed platform with no shell, and it adds nothing to the public origin of ADR-IAM-002.
- A declared value that a write would refuse fails startup: `mtls` where the certificate is not believed, a list value that is not an absolute URI or that equals the issuer.
- The declaration carries a revision number, and the highest one applied is stored. A startup with a lower revision writes nothing and logs a warning, so a replica restarting on old configuration during a rollout cannot undo a change. Going back on purpose is a new declaration with a higher revision.
- A client the declaration does not mention is left alone. Only a stated value writes. A list is emptied only by stating it empty.
- Removing an audience, changing a mode, or moving `grants_valid_after` also writes its event at warning level, which is ADR-IAM-007's rule 3. A mode change applies to new grants only, because a family keeps its binding (D2).

**Consequences.**
1. D1 and D3 can be operated without raw SQL, and raw SQL no longer goes unrecorded. It still bypasses the refusals that depend on the trust switch. Those are checked again at use, which fails closed.
2. The durable record is the history table, because `TenantAuditLog` has only an in-memory repository (ADR-IAM-010 D9).
3. A multi-tenant deployment gets this writer even though first-boot provisioning refuses to run there.
4. A registrant raising its own client (ADR-IAM-007 rule 2) waits for a registration surface.

**Why not extend first-boot provisioning.** It deliberately never overwrites a row (`pers/bootstrap/FirstBootProvisioner.java`), and it runs only with a fixed tenant. Why not the provisioning API: it has to decide what a tenant is first, and the fixes here should not wait for that.

## Rules that do not fail closed, and why

| Rule | Why it stays open | What bounds it |
|---|---|---|
| A resource server that does not check `cnf` accepts a bound token as Bearer | The token cannot enforce it, and RFC 9449 §6.2 puts the check on the resource server | The resource-server guide of ADR-IAM-007 requires it; tessera cannot close it |
| A binding mismatch does not revoke | D2: a mistake looks the same, and revoking signs out a whole client | The token endpoint's rate limit; the counter of D1, which an operator should alert on; the operator can revoke |
| A DPoP proof's `jti` is spent per instance until the shared store ships (`rest/token/NimbusDpopProofValidator.java`) | A replayed proof on another instance within `proofMaxAge` (default one minute) mints a token bound to the victim's key, which the thief cannot use | ADR-IAM-010 D4 requires the shared store before several instances run |
| The secret row of the table | ADR-IAM-010 D3 removes it, and the build order needs it until the first relying party has moved | Nothing new registers with a secret; every token is still bound |

## Rejected alternatives

- **A `none` mode, or keeping the deployment switch as a ceiling.** The profile allows only sender-constrained tokens, and a stored relaxation is a relaxation (ADR-IAM-010 D1).
- **An unset mode that follows a default.** A value nobody chose is how the switch's behaviour spread to every client.
- **Adopting a binding at first use for older families, or letting them expire on the old rules.** There is no legacy to protect, and either keeps the defect alive.
- **Moving a confidential client's grant to whatever key the refresh proof names.** The RFCs allow it, but a stolen client key and refresh token could then move a grant to the thief's key, and it conflicts with ADR-IAM-007 D2 and D5 (open item 2).
- **Revoking on a binding mismatch, at once or after some number of attempts.** It turns an operator's mistake into a sign-out of every user of the client (D2).
- **Storing client kind and mode on the family.** Redundant with the client id and the method.
- **Reusing `oauth_client.audiences` for tokens for a person.** A client holding both grants would get user tokens for what it registered for itself, such as an admin API.
- **`aud` equal to the issuer for a client with no list.** Any resource server accepting it could replay the token elsewhere, and RFC 9068 §5 is unmet.
- **Several audiences on one code or refresh token.** A resource that receives the token could replay it at another.
- **A default audience by list order or a new column.** The first gives order a hidden meaning. The second adds state that refusing an ambiguous request makes unnecessary.
- **Echo only at introspection.** It leaves the check of RFC 7662 §4 undone once tokens are per resource.
- **A network endpoint for the operator's writes.** A new credential and a new attack surface on a public origin, for a write that happens rarely.
- **A database fence against old instances during a rolling deployment.** It would stop only their refreshes, and they mint on other paths too. Draining them is simpler and covers all of it (D4).

## Open items

For the maintainers. Each has a recommendation, and the record holds under either answer unless stated.

1. **Where TLS terminates.** This decides when `mtls` is usable at all: until the trust switch is on at a trusted edge, every `mtls` row is refused, which fails closed. *Recommendation:* decide per deployment. Where no edge terminates mutual TLS, clients use `dpop`.
2. **DPoP key rotation on a grant.** Strict continuity costs a sign-in per grant on a key change, and needs a shared key across instances. *Recommendation:* strict now. If a relying party needs rotation, add a rebind by amendment, outside the delegation paths.
3. **The audience check at introspection.** The maintainers' answer of 2026-10-29 was to echo; this record also compares, because RFC 7662 §4 makes the check a MUST once tokens are per resource. *Recommendation:* accept it. The alternative is echo only, recorded as a deviation from §4, with every gateway checking `aud` itself.
4. **Review status.** An earlier draft had an adversarial round and an independent security review. This version was rewritten against ADR-IAM-010 and had one independent security review, whose findings are applied here. None of it is implemented. Acceptance is the maintainers' decision.
