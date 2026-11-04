# ADR-IAM-009 — Sender constraint is decided per client, a refresh keeps the binding it was issued with, and `aud` names the API a token is for

| Field | Value |
|---|---|
| Status | **Proposed** |
| Date | 2026-11-04 |
| Relates to | [ADR-IAM-003](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) (realm claims and issuer; D4b ratified by this record), [ADR-IAM-006](ADR-IAM-006-standalone-provider-for-many-sites-and-agents.md) (many relying parties), [ADR-IAM-007](ADR-IAM-007-token-exchange-and-agent-delegation-profile.md) (delegation; this record supplies the refresh path its D2 and D5 require), [threat model](../security/threat-model.md) row 14 and [the `iss`/`aud` decision](../security/threat-model.md#the-introspection-iss--aud-decision), [RFC 9700 checklist](../security/rfc9700-checklist.md) |

---

## Background

Tessera made sender-constraining mandatory: DPoP for public clients, a client certificate for confidential clients. It later added one switch, `iam.authflow.require-sender-constraint`, for a back-end-for-frontend relying party behind a TLS-terminating edge, which cannot present a certificate. Neither step was recorded in an ADR. This record is that record, and it amends both.

Three gaps meet on the token path:
1. The switch applies to the whole deployment. Relaxing it for one relying party relaxes every confidential client.
2. A refresh always mints an unbound token, so the mandatory binding holds only until the first refresh.
3. `aud` is the issuer on every code and refresh token, so a token for one API is valid at every API that accepts the issuer as audience.

The refresh grant decides both the binding and the audience of the token it mints, and the per-client policy decides what a refresh must preserve. So the three are decided together.

Path abbreviations as in ADR-IAM-007. Code references are at `main` commit `c937502`. The open change on branch `fix/token-client-auth` is taken as given: `X-Client-Certificate` is ignored unless `iam.client-certificate.trust-header` is on, and always in single-tenant mode; an mTLS client never authenticates by a secret and cannot authenticate at all until certificate matching is designed; basic and post secret methods are enforced.

Facts the decisions rest on:
- `resolveBinding` requires a DPoP proof of a public client and a certificate of a confidential one, unless the flag is `false` and the client does not authenticate by mTLS (`api/TokenService.java:269-302`). A confidential client's DPoP proof is ignored. `client_credentials` repeats the rule (`api/ClientCredentialsService.java:152-159`).
- A refresh mints without `cnf`, with empty scope, without realm claims, with `aud` the issuer, and always answers `Bearer` (`api/RefreshService.java:275-292`). The refresh command carries neither a proof nor a certificate (`rest/TokenResource.java:140-141`). `RefreshBindingDowngradeProbeTest` reproduces this over HTTP for an mTLS-bound confidential client and a DPoP-bound public client.
- `consumeAndRotate` runs before the client and realm checks, so a mismatched presentation of the live token rotates it and issues nothing (`api/RefreshService.java:204-209,222-228`). The next presentation by the real holder is then a replay and burns the family.
- A family stores no binding and no audience (`dom/refresh/RefreshTokenFamily.java:49-62`; `mig/V3__iam_core_entities.sql:97-109`, `mig/V6`, `mig/V7`). `granted_scope` is `NULL` for families older than V7.
- `oauth_client.audiences` means what a client's `client_credentials` tokens may name, on its own behalf (`mig/V8__oauth_client_credentials_registration.sql`). `client_credentials` is its only reader (`api/ClientCredentialsService.java:141-151`). A client may hold that grant and the code grant together, so a value there says nothing about tokens for a person. A public client has no such field (`dom/client/PublicClient.java:28-33`). `/authorize` takes no `resource` (`rest/AuthorizeResource.java:99-109`), and `/token` passes `resource` only to `client_credentials` (`rest/TokenResource.java:156-159`).
- A client assertion is accepted only on `client_credentials` (`rest/TokenResource.java:113-116`), so a key-authenticated client cannot use the code or refresh grant today.
- Introspection echoes neither `iss`, `aud` nor `cnf`, and reports `Bearer` for every access token (`rest/token/JwsAccessTokenIntrospector.java:186-194`; `api/IntrospectService.java:130-131`).
- The audit log (`tessera-observability`, `TenantAuditLog`) has no caller on any token path, and its only repository is in memory (`InMemoryTenantAuditLogRepository`). Refresh replay is a log line (`api/RefreshService.java:253-259`).
- The only client writer in the code is first-boot provisioning. It requires a fixed tenant and skips a client that already exists (`pers/bootstrap/FirstBootProvisioner.java:101,146-149`). There is no provisioning API, so every other client write today is raw SQL.
- `/revoke` accepts a public client by `client_id` alone, and revokes the family of a refresh token issued to it, with no proof (`api/RevokeService.java:78,102-105`; `api/ClientAuthentication.java:63-66`). RFC 7009 §2.1 requires credentials only of a confidential client. RFC 9449 does not mention revocation.
- Any confidential client in the realm gets `active:true` for another client's live refresh token, with its `sub` (`api/IntrospectService.java:102-118`), and `IntrospectFlowTest.activeRefreshTokenAndSupersededInactive` pins that.
- A SQL migration cannot read deployment configuration.

Inputs that are not code:
- The maintainers answered the threat model's open `iss`/`aud` question on 2026-10-29: access tokens name the API they are for, through RFC 8707 `resource` at `/authorize`; introspection echoes `iss`, `aud` and the `act` chain; ADR-IAM-003 D4b is ratified as part of this design. D3 implements that answer and does not reopen it.
- ADR-IAM-003 no longer carries the open question that coupled `iss` and `aud`. Its ratified rewrite (`c05e5f6`) dropped that label and text and kept one open item, the upgrade path for an issuer change. The coupling itself is still in the code (`api/TokenService.java:221,224`; `api/RefreshService.java:276`). D3 consequence 5 says what remains of it.

## What the RFC text says

Read from the plain text at rfc-editor.org on 2026-11-04.

| Source | What it says | What it does not say |
|---|---|---|
| RFC 9449 §5 | A proof is required on every access token request for a DPoP-bound token, the refresh grant included. A public client's refresh token MUST be bound to the proof key, the binding MUST be validated, and the client MUST present a proof for the same key each time. A confidential client's refresh token is not bound to the proof key, because client authentication already constrains it, which allows credential rotation. An invalid proof is `invalid_dpop_proof`. A server MAY issue a Bearer token, signalled by `token_type`. | It names no error for a valid proof with the wrong key at refresh. It does not forbid a server being stricter with a confidential client. |
| RFC 9449 §5.2 | With `dpop_bound_access_tokens` true, the server MUST reject a token request with no DPoP header. | |
| RFC 8705 §4 | This section covers **public** clients only: a server SHOULD bind their refresh token to the certificate and check the binding. | The spike's question about confidential clients is not answered here. |
| RFC 8705 §7.1, §6.3 | A refresh token is bound to the client, and so indirectly to a certificate only for clients that authenticate by certificate. Updating a certificate invalidates its access tokens, and the client typically gets a new one with its refresh token. | Nothing covers a secret-authenticated client that presents a certificate, which is what a confidential client with a certificate is in tessera today. No section defines a token type for a certificate-bound token. |
| RFC 8707 §2, §2.1, §2.2, §3 | `resource` is an absolute URI without a fragment and may repeat. `invalid_target` is the error. With none at `/authorize` a server MAY use a default or MAY fail with `invalid_target`. Policy may limit code and refresh requests to what was originally granted, and a refresh token stays bound to the full original grant even when an access token names a subset. A server SHOULD audience-restrict. | It defines no metadata member, so discovery has nothing to advertise. It has no rule for a refresh that omits `resource`. |
| RFC 9700 §2.2.2, §2.3, §4.14.2 | A public client's refresh token MUST be sender-constrained or rotated. A refresh token MUST be bound to the scope and resource servers consented to. On reuse the server revokes, because it cannot tell which party presented the invalid token. Access tokens SHOULD be audience-restricted. | It does not treat a binding mismatch as reuse. |
| RFC 9068 §3, §4, §5 | With `resource`, `aud` SHOULD equal it. Without it, a default resource indicator MUST be used, and scope SHOULD be used to infer it. A resource server MUST reject a token that does not name it. A server MUST use distinct `aud` values for distinct resources. | |
| RFC 6749 §6 | A requested scope MUST NOT exceed what was granted, and an omitted scope is treated as equal to it. The refresh token's scope stays that of the grant. | |
| RFC 7662 §2.2, §4 | If a token can be used only at certain resource servers, the server MUST determine whether it can be used at the one calling; it decides which checks apply. It MAY answer different callers differently. | |
| RFC 9449 §6.2 | A resource server sends no proof to introspection, and the server does not validate the binding there. The resource server checks it locally from `cnf`. `token_type`, if present, MUST be `DPoP`. | |

So the answer to "does the refreshed token bind to the key in the refresh proof, or must it match the original?" is: for a public client it must match (RFC 9449 §5). For a confidential client the RFCs allow the key to change. Tessera chooses not to allow that (D2).

## The rule table

Every client kind by mode by grant. `Certificate` means a certificate tessera believes: the trust switch is on and the mode is not single-tenant. The audience rules A1 and A2 are in D3. Failures are in the notes under the table. Rows 13 and 14 take precedence over the other rows.

| # | Client kind | Mode | Code grant: required, then `cnf` | Refresh must prove | Rotated token binds to | Audience: code / refresh |
|---|---|---|---|---|---|---|
| 1 | Public | `dpop` (the only mode; unset means `dpop`) | DPoP proof, `cnf.jkt`, `token_type` `DPoP` | Proof for the family's `jkt` (RFC 9449 §5) | The same `jkt` | A1 / A2 |
| 2 | Public | `mtls` | Refused at write, and by a `CHECK` | never reached | never minted | none |
| 3 | Public | `none` | Refused at write, and by a `CHECK` | never reached | never minted | none |
| 4 | Confidential, secret | `mtls`, or unset with flag `true` | Certificate, `cnf["x5t#S256"]`, `Bearer` | Client authentication and the family's certificate | The same thumbprint | A1 / A2 |
| 5 | Confidential, secret | `dpop` | DPoP proof, `cnf.jkt`, `DPoP` | Client authentication and a proof for the family's `jkt` | The same `jkt` | A1 / A2 |
| 6 | Confidential, secret | `none`, flag `false` | Nothing more; unbound, `Bearer`; a presented proof is ignored | Client authentication only (RFC 6749 §6) | Unbound; the event of D1 is written | A1 / A2 |
| 7 | Confidential, secret | `none`, flag `true` | `invalid_client` | `invalid_client` | never minted | none |
| 8 | Confidential, secret | unset, flag `false` | A certificate binds as row 4; without one, unbound as row 6, with reason `legacy-flag` | The family's binding: row 4 if bound, row 6 if not | The family's binding | A1 / A2 |
| 9 | Confidential, key (`private_key_jwt`, workload identity) | `mtls` or `dpop` | Refused today, `invalid_client` (`rest/TokenResource.java:113-116`). Once ADR-IAM-007's prerequisite ships: rows 4 and 5, with the assertion as client authentication | The same | The same | A1 / A2 |
| 10 | Confidential, key | `none` or unset | Refused today, as row 9. Then rows 6, 7 and 8 | The same | The same | A1 / A2 |
| 11 | Confidential, mTLS | `mtls` or unset | Refused today, `invalid_client`: no authentication is possible until certificate matching is designed | Refused today | never minted | none |
| 12 | Confidential, mTLS | `dpop` or `none` | Refused at write, and by a `CHECK` | never reached | never minted | none |
| 13 | Any client registered as an agent, or for the exchange grant | `none` | Refused at write; a stored value is `invalid_client` at use, whatever the flag (ADR-IAM-007 D5) | `invalid_client` | never minted | none |
| 14 | Same as row 13 | `dpop`, `mtls`, or unset. Unset means `dpop` on a public client and `mtls` on a confidential one, **under either flag**: row 8 never applies | Rows 1, 5 or 4 | The same, plus ADR-IAM-007 D2 consequence 4 (`act` re-emitted). A family recorded `none` or `NULL` is `invalid_grant`, unchanged, and is never adopted | The same key, never another (D2) | A1 / A2 with no issuer fallback: an unset or emptied list, or a grant or family with no recorded set, is `invalid_target` |

Failures, all without rotating or changing the family:
- **Code grant.** A missing or invalid proof is `invalid_dpop_proof`. A missing certificate is `invalid_request`. Both are today's answers (`api/TokenService.java:272-285,292-294`).
- **Refresh.** A proof the client's mode requires, failing validation, is `invalid_dpop_proof` (RFC 9449 §5). A missing proof, a missing certificate, or a valid proof for another key is `invalid_grant`, with the same body as every other refresh failure, so the existing collapse holds (`api/RefreshService.java:53-54`).

`client_credentials` follows the same modes through the same policy function (D1) and has no refresh token. Its audience rule is unchanged (`api/ClientCredentialsService.java:141-151`).

## D1 — The mode is per client; the flag becomes an operator ceiling

**Decision.** A client record gains `sender_constraint`: `dpop`, `mtls`, `none`, or unset. `iam.authflow.require-sender-constraint` stays, with a narrower meaning: whether `none` may take effect at all. One pure domain function decides the binding from the client, the flag and the presented proofs, and all three mint paths call it, so they cannot disagree.

Configuration point, under ADR-IAM-007's rule. `dpop` and `mtls` are two mechanisms at the same level, and `none` is below both.

| State | Behaviour | Protects | Costs | Who picks | Default |
|---|---|---|---|---|---|
| Flag `true` | No unbound token is minted for anyone. Unset confidential means `mtls`. A declared value of `none` fails startup (D5), a write of `none` is refused, and a stored `none` is `invalid_client` at use | The floor of RFC 9700 §2.2.1 for the deployment | A relying party that cannot prove possession cannot sign in | Operator | **Yes** |
| Flag `false` | A stored `none` takes effect. Unset confidential keeps the old meaning, row 8, except for an agent or exchange client (rows 13 and 14). A stored `dpop` or `mtls` is unaffected. Startup refuses this state while the exchange grant is enabled (ADR-IAM-007 D5) | Lets one relying party relax without relaxing the others, once the others have stored values | Below the floor for every `none` and unset client (open item 2) | Operator; audited | No |
| Client `dpop`, `mtls` | Requires that proof on every grant. Other proofs are ignored; a missing one is refused. `mtls` cannot be written while the certificate is not believed | Binding, whatever the flag | The relying party must hold a key; a resource server must verify | Operator, through D5; a registrant may raise once a registration surface exists; only the operator lowers | Public: `dpop`. Confidential: unset |
| Client `none` | Unbound token, `Bearer`. Never for a public, mTLS-authenticated or agent client | Nothing; it is the visible, per-client relaxation | A stolen token is usable by anyone until it expires | Operator only | No |

**What it means.** A request never selects a mode, with one legacy exception: row 8 keeps today's behaviour, where a certificate presented at the code grant decides whether that family is bound. A `none` client that sends a proof still gets a Bearer token (RFC 9449 §5 allows it), and a `dpop` client that sends a certificate is still refused without a proof. DPoP is offered to confidential clients on every grant, which ADR-IAM-007 D5 already lists as a prerequisite. It also gives a relying party behind an edge that cannot pass a client certificate, such as Cloud Run, a way to be bound.

**Consequences.**
1. Two clients in one deployment can differ: a back-end-for-frontend relying party on `none`, every other client on `mtls` or `dpop`. Setting the flag to `false` then relaxes only the first.
2. `none` is refused at write for a public client, an mTLS-authenticated client and an agent client, by the writer of D5, a domain invariant and a database `CHECK`. An agent can still exist with no stored mode, so rows 13 and 14 also hold at use: a later change of the flag never makes an agent unbound.
3. Each of these is a structured event with client, realm and family, and no token material, plus a counter tagged by client and reason (`IamMetrics`): a family recorded unbound (reason `none` or `legacy-flag`, and whether a proof was presented and valid, so an operator can see a client is ready to move); a binding adopted (old method, new method, thumbprint); a binding mismatch or missing proof (expected method, presented thumbprint); a certificate required but not believed. An unbound issuance on a refresh only increments the counter, because logging every refresh would bury the rest. These go through the same log as replay (`api/RefreshService.java:253-259`) until the audit log has a caller on the token path. Moving them there is separate work. Alerting on the mismatch counter is the operator's detection of a stolen token.
4. Discovery's `tls_client_certificate_bound_access_tokens` is true only while the trust switch is on, because the document advertises only what is enforced (`rest/dto/DiscoveryDto.java:13`).
5. The rule "a token with no `cnf` is rejected at the resource server" now reads: a resource server that requires binding refuses a token with no `cnf`, from any client. A resource server cannot read another client's mode. Tessera declaring which resources verify binding is ADR-IAM-007's registration attribute, not this record's.
6. **`mtls` is usable only where the certificate is believed.** In single-tenant mode, or with the trust switch off, no certificate is ever believed, so only `dpop` and `none` work. The writer of D5 refuses `mtls` there, and a declared value of `mtls` fails startup. Stored rows sit behind per-tenant row-level security and cannot be scanned at startup, so a stored `mtls` is refused at use, with its event.
7. A relying party moving to `dpop` must send a proof whose `htu` is the configured public token endpoint, compared exactly (`api/TokenService.java:277-278`; `rest/config/UseCaseProducer.java:115`; `rest/token/NimbusDpopProofValidator.java:110-113`), not an address behind the edge. It must also send proofs to its APIs. Sending proofs before the operator sets the mode is harmless: no token request is refused for them until then, and the event says whether they are valid, so an `htu` naming an internal address shows up before it can lock the client out.
8. When client metadata is accepted at registration, `dpop_bound_access_tokens` true (RFC 9449 §5.2) is the same statement as `dpop`, and the two cannot disagree.
9. ADR-IAM-007 D5 consequence 3 says a resource server refuses a token with `cnf` presented as `Bearer`. An mTLS-bound token is exactly that (`api/TokenService.java:57`), and RFC 8705 gives it no other type. That sentence holds for `cnf.jkt` only, and needs that small correction when this record is accepted.

## D2 — A refresh proves the family's binding, and the rotated token keeps it

**Decision.** A family persists the binding decided at its first issuance. Every later refresh must prove exactly that binding, for every client kind, before anything rotates. The rotated access token carries the same `cnf`, the matching `token_type`, the realm claims and the family's granted scope, or a requested subset of it; a wider request is `invalid_scope` (RFC 6749 §6). A subset narrows that token only, not the family. A binding, once recorded, never weakens and never moves to another key. A mismatch is `invalid_grant`. The family stays unchanged and is not revoked.

**What it means.**
- The family gains `binding_method` (`dpop`, `mtls`, `none`, or `NULL` for a family older than this change) and `binding_thumbprint`. Client kind and mode are not stored: the kind comes from the client id and does not change, and the method is the mode that applied. `cnf` is rebuilt from the two columns.
- The order on the refresh path:
  1. Parse the token, resolve the realm, and authenticate the client, as today.
  2. If the client's effective mode requires a proof, validate a presented one. This depends on nothing about the token, so it reveals nothing. A proof the mode does not require refuses nothing: it is only reported in the event of D1.
  3. Load the family.
  4. If the presented token could issue anything (the live token, or the predecessor inside the reuse grace), check the binding, whichever client id was presented. If the family is bound but the client's mode no longer requires that proof, the proof is validated here, and an invalid one is `invalid_grant`.
  5. Only then check the audience (D3) and the scope. A holder who has not proved the binding therefore learns nothing from `invalid_target` or `invalid_scope`, and the `invalid_grant` collapse holds.
  6. Run `consumeAndRotate`.
  7. On `Reissue`, check the binding again against the family the store returned, which is the row after any concurrent rotation. The check in step 4 may have read a family that was not yet bound. A family still unbound while the client's effective mode requires a binding, because its last rotation ran on an old instance or before the mode was raised, also fails here. A failure is `invalid_grant` with no burn, like the existing refusals on that branch (`api/RefreshService.java:237-246`). `Reissue` never adopts a binding: only the winning rotation records one.
- A superseded token outside the grace goes to the replay path and burns the family, with or without a proof, as today (RFC 9700 §4.14.2). Only a required proof failing at step 2 stops the request first, and that burns nothing.
- Changing a client's mode affects only new families and those D4 upgrades. A bound family keeps its method even if the client is later lowered or moved to another method. Lowering the flag changes nothing for it.

**Consequences.**
1. A thief with a live refresh token and no key cannot consume it. That includes presenting it under another public `client_id`, which today rotates the token and leads to the victim's family being burned. The thief can still sign the user out through `/revoke` if the client is public (open item 7).
2. The reuse grace checks the binding on both presentations, the second against the row after the first. Concurrent requests carry their own proofs, so a second presenter with another key or no proof gets neither the token nor the derived successor refresh secret.
3. A key or certificate change on a bound family means a new sign-in for that family's user, or running the old and new keys side by side until the old families end. A relying party with several instances must share one DPoP key across them, or pin each session to an instance. This goes beyond what the RFCs require for a confidential client and is declared (open item 3).
4. ADR-IAM-007 D2 consequence 4 and D5 get what they require: a persisted, continuity-checked `cnf`, with the scope and the realm. `act` is added by the exchange change.
5. A public client that sends no proof at refresh, against RFC 9449 §5, stops working. `RefreshBindingDowngradeProbeTest` then fails and is replaced by tests of this rule.

**Why strict for confidential clients too.**
- A rebind would let whoever holds the refresh token and the client's secret, both stored at the client, move the family to a key of their own. Strict continuity makes them steal the private key as well, which can sit in a KMS.
- It is one rule for every row, and ADR-IAM-007 requires it on the delegation paths anyway.
- Certificate-authenticated clients are the case RFC 8705 §7.1 describes as rotating freely. They cannot authenticate today, and their rule is written with certificate matching.

**Why no revocation on mismatch.** Denying a thief the power to sign a user out is not the reason: a thief of a public client's token already has it through `/revoke` (open item 7), and one who passes a confidential client's authentication has the same. There are two reasons. RFC 9700 revokes on reuse because the server cannot tell which party is the attacker, and on a mismatch it can: the presenter does not hold the key, and gets nothing. And a mismatch is also what an operator's mistake looks like, at the scale of a whole client: an edge that stops forwarding certificates, or one instance with the wrong DPoP key. Refusing recovers when the mistake is fixed. Revoking would sign out every user of that client. The token is still known to be stolen if the mismatch is real, so the attempt writes an event and increments a counter, and the operator can revoke the family. A revoke after some number of attempts has the same cost, so it is not offered.

## D3 — `aud` is one resource from the client's registered list; a refresh never widens it

**Decision.**
- **Registered audiences.** A new nullable column, `oauth_client.user_audiences`, lists what tokens for a person may name, on both client kinds. `oauth_client.audiences` keeps its meaning and stays with `client_credentials`; neither column feeds the other. Registering a value is the explicit opt-in. The list has three states: **unset** (`NULL`, never opted in), values, and **emptied** (opted in, now nothing). Only unset leads to `aud` = the issuer, and a list never returns to unset (D5), so clearing a compromised client's list refuses it and does not widen its tokens. Matching is by exact string, with no normalisation. A value must be an absolute URI with no fragment (RFC 8707 §2) and is never the realm's issuer.
- **At `/authorize`.** `resource` may repeat. Each value must be registered, otherwise `invalid_target`, delivered like every other authorize-time error (`rest/AuthorizeResource.java:113-121`). The code's grant stores the named set, or, if none was named, the whole list at that moment. With an unset list it records no set, and an emptied list is `invalid_target` (RFC 8707 §2.1 allows this).
- **Rule A1, at `/token` for a code.** The candidates are the grant's set intersected with the client's current list. At most one `resource`, and it must be a candidate. More than one is `invalid_target`. With none, a single candidate is used. Several candidates with none named, or no candidates at all, is `invalid_target`. Only a grant with no recorded set gets `aud` = the issuer, and any `resource` from it is `invalid_target`; if the client's list has since been emptied, the grant is refused with `invalid_target` too.
- **Rule A2, at refresh.** The family stores the full grant's set in `granted_resources`, not the subset the first token named (RFC 8707 §2.2). The candidates are that set intersected with the client's current list, and A1's choice applies, checked after the binding and before rotation (D2). A failure is `invalid_target` with the family unchanged. Audiences registered later never enter a family, and audiences removed later leave it at once. A family with no recorded set, issued before this change or to a client with an unset list, keeps `aud` = the issuer for its whole life and never adopts a list, unless the list has been emptied, which refuses it (D4).

**What it means.** Each code and refresh access token names exactly one resource. A resource that receives a token cannot replay it at another (RFC 8707 §3), and scope correlation under RFC 9068 §5 is trivially met. This matches ADR-IAM-007 D3's rule of one audience for delegated tokens and its permitted resource set.

**Introspection.** As the maintainers decided, the active response echoes `iss`, `aud` (string or array), `cnf`, the true `token_type`, and `act` once ADR-IAM-007 ships. Beyond their answer (open item 6), tessera also compares `aud`, because per-resource audiences make the check of RFC 7662 §4 applicable. A client that introspects may hold a registered resource identifier, the attribute ADR-IAM-007 D2 and D7 already call for, so one attribute serves both:
- A caller with an identifier gets `active:true` only if the identifier is in `aud`, the token was issued to that caller, or `aud` is still the issuer (until the end date in open item 5). Otherwise `active:false`, with no other member.
- A caller with no identifier keeps the echo only, with its event, until that end date.
- The binding is not checked here. The call carries no proof and RFC 9449 §6.2 leaves it to the resource server, so a gateway that introspects must itself check `cnf` and `token_type` against the request.
- A refresh token has no `aud`, and no resource server uses one. It is `active:true` only to the client it was issued to, and `active:false` to any other caller, at once and with no transition. A public client cannot introspect, so its refresh tokens are then inactive to every caller, and `IntrospectFlowTest.activeRefreshTokenAndSupersededInactive` changes.

ADR-IAM-003 D4b is ratified:
- Both mint paths stamp the realm claims.
- Introspection compares realm and `iss`, in its two phases: emit, wait one access-token lifetime, enforce.
- Threat model row 14 moves to pinned, `issAndAudAreNotAssertedByIntrospection` is replaced, and the threat model's position that the server does not assert audience is replaced by this section.

**Consequences.**
1. Discovery gains nothing: RFC 8707 defines no metadata member.
2. A client that registers several audiences must name one on every token request, including refresh. Asking for the list's first entry would give list order a hidden meaning. No `default_audience` column is needed.
3. A resource server's `client_id` allow-list, kept today as a workaround for `aud` being the issuer, stays for as long as it accepts `aud` = the issuer, because any client on the issuer audience holds a token it could replay there. It goes when that resource server accepts only its own audience.
4. ID tokens are unchanged: their `aud` is the client. A UserInfo endpoint, when built, is a resource with its own audience (none is served today, `rest/dto/DiscoveryDto.java:15-16`).
5. An issuer change is an audience change only for clients still on `aud` = the issuer. ADR-IAM-003's open upgrade item should say so when it is taken up.
6. The consent screen naming resources belongs to the consent work of ADR-IAM-007 D4. Until consent is enforced, "as consented" in RFC 9700 §4.14.2 is what the operator registered.
7. Scope inference (RFC 9068 §3 SHOULD) is not implemented: tessera has no mapping from scope to resource, and the registered list stands in for one. This is a deliberate deviation.
8. For ADR-IAM-007 D3, an actor's registered audiences are `user_audiences` on a token for a person, and `audiences` on an autonomous root's token.

## D4 — Running deployments carry over without a forced sign-out

**Decision.** The migration is additive and copies nothing: nullable `sender_constraint` and `user_audiences` on `oauth_client`, a nullable `resource_identifier` for clients that introspect, and on `refresh_token_family` nullable `binding_method`, `binding_thumbprint`, `granted_resources` and `binding_checked_generation`, plus `scope_on_refresh` (not null, default false, true on every new family), and the history table of D5. A `CHECK` requires a thumbprint exactly when the method is `dpop` or `mtls`. An unset client follows the flag, which is ADR-IAM-007's rule for a client with no stored value. A family's binding upgrades at its next refresh; its audience and scope rules do not change for life.

A database fence stops an old instance downgrading a bound family during a rolling deployment, whatever the deployment order. New code sets `binding_checked_generation` to the new generation in its rotation. A `BEFORE UPDATE` trigger refuses a change of `current_token_hash` on a family bound to `dpop` or `mtls` when `NEW.binding_checked_generation IS DISTINCT FROM NEW.generation`, so a `NULL` cannot slip through. Old code does not set the column, so its rotation fails before it mints anything (`api/RefreshService.java:204-209`), and the request errors. Unbound and legacy families are untouched.

| Family at refresh | Client's effective mode | What happens |
|---|---|---|
| `binding_method` `NULL`, or `none` | `dpop` or `mtls`, not an agent | The required proof must be presented. Its key is recorded inside the rotation's compare-and-swap, and the family is bound from then on |
| `NULL` or `none` | An agent or exchange client, any mode | `invalid_grant`, unchanged: ADR-IAM-007 D2 consequence 4 requires continuity, and adoption is not continuity |
| `NULL` | Unset with flag `false` | A presented certificate is recorded as `mtls`. Otherwise the family records `none` and stays unbound |
| `none` | Unset with flag `false` | Stays unbound; a certificate presented later is ignored (row 8) |
| `NULL` or `none` | `none` with flag `false` | Records `none`, stays unbound |
| `NULL` or `none` | `none` with flag `true` | `invalid_client` |
| `dpop` or `mtls` | Anything | D2: that proof, or `invalid_grant` |
| `granted_resources` `NULL` | Not an agent; list unset or with values | `aud` stays the issuer. Any `resource` is `invalid_target`. No list is adopted, even if the client has since registered one |
| `granted_resources` `NULL` | An agent, or a client whose list was emptied | `invalid_target` |
| `scope_on_refresh` false | Any | Scope stays empty, as today: the upgrade gives a token stolen before it no new power. The family's scope is still used for the ID token decision |
| `granted_scope` `NULL` (older than V7) | Any | Scope stays empty, as today: unknown is not widened |

An authorization code in flight that decodes with no resources is a grant with no recorded set.

**Consequences.**
1. A deployment on flag `true` stays closed: its confidential clients stay on `mtls`, and a client that cannot prove possession is refused at the next refresh, as it already is at the code grant.
2. A deployment on flag `false`, such as a demo whose back-end-for-frontend gateway receives unbound tokens today, sees no change for that gateway and no sign-out. The operator then pins it to `none`. Every other confidential client moves only when it is ready, in this order: the client starts sending proofs, the event of D1 shows valid ones arriving, and the operator then sets `dpop` through D5. Setting a mode on a client that cannot yet prove it refuses that client's code grants and the refresh of its legacy families. `mtls` is an option only where certificates are believed (D1 consequence 6).
3. Public relying parties must send a proof at refresh and handle `token_type` `DPoP` on the refreshed token, as they already do for the first token. A single-page app needs a key that survives a reload: one kept only in memory strands a persisted refresh token, and the user signs in again.
4. A confidential relying party on `mtls` must have its edge forward the certificate at refresh too.
5. A client opts in to per-resource audiences when the operator writes `user_audiences` through D5. Only new sign-ins get them, so its resource server accepts both values, with its allow-list, until the client's last older family ends or the end date in open item 5, whichever is first.
6. On flag `true` with no believed certificate, unset confidential clients are already refused at the code grant once the `fix/token-client-auth` change merges. Their older families now stop refreshing too, so such a deployment should set `dpop` or `none` first.
7. Rolling back to old code leaves the fence in place: bound families cannot refresh on it, and their users sign in again. That fails closed, and a later migration can drop the trigger.
8. Implementation order: the policy function with D2 first, which needs no stored value; then the writer of D5; then D1's stored mode, then D3. The first ships after the `fix/token-client-auth` change merges.

## D5 — One operator-only, audited writer for a client's mode and audiences

**Decision.** One application use case writes `sender_constraint`, `user_audiences` and `resource_identifier`, and it applies every write refusal of D1 and D3. Its first caller is a declaration the operator owns, keyed by tenant, baseline and client id, applied at startup. It updates those three columns on an existing client and nothing else. There is no network endpoint. A provisioning API, when one is built, calls the same use case and brings its own authentication. Every change appends a row to a history table (client, column, old value, new value, database role, time), written by a database trigger on those columns, so a raw SQL write is recorded too. The application's database role holds no `UPDATE` or `DELETE` on the history table, as ADR-IAM-003 D1 consequence 3 does for its record, and a test pins that.

**What it means.**
- The operator is whoever controls the deployment's configuration. A restart is the act. That holds on a managed platform with no shell, and it adds nothing to the public origin of ADR-IAM-002.
- A declared value that a write would refuse fails startup: `none` under flag `true`, `mtls` where the certificate is not believed, `none` on a public, mTLS-authenticated or agent client, a list value that is not an absolute URI or that equals the issuer.
- The declaration carries a revision number, and the highest one applied is stored. A startup with a lower revision writes nothing and logs a warning, so a replica restarting on old configuration during a rollout cannot lower a client again. Going back on purpose is a new declaration with a higher revision.
- A client the declaration does not mention is left alone. Only a stated value writes. A list is emptied only by stating it empty. Neither a list nor a mode returns to unset, through this writer or through raw SQL, which the trigger refuses, because an unset mode or list is a relaxation.
- A write that lowers (`none`, or an audience removed) also writes its event at warning level, which is ADR-IAM-007's rule 3. Raising needs nothing more.

**Consequences.**
1. D1 and D3 can be operated without raw SQL, and raw SQL no longer goes unrecorded. It still bypasses the refusals that depend on the flag or the trust switch. Those are checked again at use, which fails closed.
2. The durable record is the history table, because `TenantAuditLog` has only an in-memory repository and a restart would lose it. Moving the record to the audit log is part of giving the audit log a durable store.
3. A multi-tenant deployment gets this writer even though first-boot provisioning refuses to run there. Creating clients in such a deployment stays as it is today.
4. A registrant raising its own client (ADR-IAM-007 rule 2) waits for a registration surface.

**Why not extend first-boot provisioning.** It deliberately never overwrites a row (`pers/bootstrap/FirstBootProvisioner.java:146-149`), and it runs only with a fixed tenant. Why not the provisioning API: it has to decide what a tenant is first, and the fixes here should not wait for that.

## Rules that do not fail closed, and why

| Rule | Why it stays open | What bounds it |
|---|---|---|
| Unset confidential client under flag `false` (row 8) | Closing it at the upgrade breaks the relying party the flag exists for. Omitting the certificate at the code grant leaves that family unbound for life, which contradicts "a request never selects a mode" | The event of D1 lists every such client; a stored mode closes it per client; end date in open item 5 |
| `aud` = the issuer for a client with an unset list, and for grants and families with no recorded set | Closing it at the upgrade refuses every token to every such relying party. It also deviates from RFC 9068 §5, and such a token stays replayable at any resource server that accepts the issuer | Resource servers keep their allow-list (D3 consequence 3); a new sign-in for a client with a list never gets it; end date in open item 5 |
| A caller of introspection with no resource identifier gets the echo only | Refusing it at the upgrade breaks every current caller. A gateway that reads only `active` accepts another API's token | The event of D3; registering an identifier closes it per caller; end date in open item 5 |
| A gateway that does not check `cnf` accepts a bound token as Bearer | The call carries no proof, and RFC 9449 §6.2 puts the check on the resource server | The resource-server guide of ADR-IAM-007 requires it; tessera cannot close it |
| First-use adoption for a legacy public family (D4) | The original key was never stored, so the only closed option is signing out every user | No worse than today. A thief who binds first is caught at the victim's next refresh, as replay, and the window ends with the family. The operator may close it (open item 4) |
| First-use adoption for a legacy confidential family (D4, first row) | The same: the certificate was never stored. Whoever holds the refresh token and the client's credential binds it to their own key | The client's credential is needed as well; caught as replay at the victim's next refresh; the event records every adoption |
| A certificate-bound legacy family records `none` at its first refresh, for an unset client under flag `false` | Today no client need send its certificate at refresh (`rest/TokenResource.java:140-141`), so its absence proves nothing, and refusing would sign out a relying party that never needed to | Only under flag `false`, with an unset client; the event records it; a stored mode closes it by requiring the proof |
| A thief of a live refresh token of a public client signs the user out through `/revoke` (`api/RevokeService.java:78,102-105`) | RFC 7009 §2.1 lets a public client revoke by `client_id`. It gives no access | Open item 7 |
| Row 6, a stored `none` | It is the declared relaxation | Operator only, flag `false` only, counted per issuance, out of reach of agents and subject tokens |
| A superseded token burns a bound family without a proof | This fails safe, not open: the thief gains no access but can force a sign-out. RFC 9700 §4.14.2 | Existing behaviour |
| A live token of an unbound family, presented under another public `client_id`, still rotates and issues nothing | Existing deliberate ordering (`api/RefreshService.java:44-51`); it gives no access | Unbound families only; bound families are closed by D2 |
| Instances on old and new versions at once, predecessor inside the reuse grace | The fence stops a rotation on an old instance. A `Reissue` writes nothing, so the trigger does not see it, and an old instance can mint unbound there | Only for the rollout, a confidential client's own credential is needed, the predecessor must be seconds old, and the grace is off by default |
| A binding mismatch does not revoke | A thief can retry until the family expires, gaining nothing (D2) | The token endpoint's rate limit (`rest/TokenResource.java:59`); the counter of D1, which an operator should alert on; the operator can revoke |
| A DPoP proof's `jti` is spent per instance (`rest/token/NimbusDpopProofValidator.java:39,125-130`) | A thief with the refresh token and a captured proof can replay it on another instance within `proofMaxAge` (default one minute). The token is bound to the victim's key and useless to the thief, but the rotation signs the victim out | A captured proof is needed as well; the shared store of ADR-IAM-007 D7 closes it, and should come first in any deployment running several instances with bound clients |
| An authorization code is not bound to a DPoP key | `dpop_jkt` (RFC 9449 §10) is not built; the first key is whichever redeems the code, and PKCE still protects the redemption | ADR-IAM-007 D5 lists it as a prerequisite |

## Rejected alternatives

- **Keep the deployment switch alone.** One relying party relaxes all of them.
- **Map clients to `none` or `mtls` in the migration.** SQL cannot read the flag, and it would freeze a relaxation into every row.
- **Remove the flag now.** Operators lose the ceiling, and ADR-IAM-007 D5 refers to it.
- **Bind the rotated token to whatever key the refresh proof names, for confidential clients.** The RFCs allow it, but a stolen secret and refresh token could then move a family to the thief's key, and it conflicts with ADR-IAM-007 D2 and D5 on delegated paths (see open item 3).
- **Bind the rotated token to the refresh proof for public clients.** Forbidden by RFC 9449 §5.
- **A DPoP-bound refresh token with a Bearer access token for public clients** (RFC 9449 §5 MAY). A public client's access token stays bound.
- **Certificate-bound public clients** (RFC 8705 §4). Needs a self-signed mutual-TLS stack tessera does not have, and the TLS decision is open.
- **Revoke the family on a binding mismatch.** Gives a keyless thief a sign-out lever (D2).
- **Check the binding after rotation, as the client and realm checks are.** A keyless thief could consume the live token.
- **Store client kind and mode on the family.** Redundant with the client id and the method.
- **A family issued before this change stays unbound for life.** Public families were bound at their first token and only lost the key record. This would keep the defect alive until they expire.
- **Sign everyone out at the upgrade.** Closed, but it is what the upgrade path must avoid (see open item 4).
- **Reusing `oauth_client.audiences` for tokens for a person.** A client holding both grants would, with no operator action, get user tokens for what it registered for itself, such as an admin API, and its relying party's `aud` check would start refusing them.
- **A legacy family adopting the client's list at its next refresh.** The same surprise at scale. A list of several would fail every legacy refresh, and it contradicts "a refresh never widens".
- **Giving legacy families their full scope at the upgrade.** RFC 6749 §6 would have it, but a refresh token stolen before the upgrade would gain power. New families get it.
- **Telling operators to bridge a rolling deployment by keeping the mixed window short.** A keyless thief can retry until an old instance answers.
- **Revoking a family after some number of mismatches.** The same sign-out lever at a higher price (D2).
- **An emptied list falling back to `aud` = the issuer.** Clearing a compromised client would widen its tokens.
- **Letting a stored mode or list return to unset.** An unset mode under flag `false`, and an unset list, are the relaxations open item 5 retires. A client that has left them should not be able to go back.
- **A network endpoint for the operator's writes.** A new credential and a new attack surface on a public origin, for a write that happens rarely.
- **Several audiences on one code or refresh token.** A resource that receives the token could replay it at another.
- **A default audience by list order or a new column.** The first gives order a hidden meaning. The second adds state that refusing an ambiguous request makes unnecessary.
- **Echo only at introspection, for every caller, for good.** It leaves the check of RFC 7662 §4 undone once tokens are per resource.
- **`active:false` at once for every caller with no resource identifier.** Breaks every current caller at the upgrade.
- **`aud` always the issuer plus a client allow-list at each resource server.** Every resource server repeats the work, and RFC 9068 §5 is unmet.

## Open items

For the maintainers. Each has a recommendation, and the record holds under either answer unless stated.

1. **Where TLS terminates.** This decides when `mtls` is usable at all: until the trust switch is on at a trusted edge, every `mtls` row is refused, which fails closed. *Recommendation:* decide per deployment. Where no edge terminates mutual TLS, register confidential clients as `dpop`, or as `none` if their APIs do not verify DPoP yet.
2. **`none` under the maintainers' rule.** ADR-IAM-007 says a state below the floor is not offered, yet restricts this flag rather than removing it, and refuses `false` while the exchange grant is enabled. So a deployment cannot run a `none` relying party and the exchange grant together. *Recommendation:* keep ADR-IAM-007 as written for now. When one deployment needs both, amend its D5 so that `none` is allowed for a client that is never an agent, since an unbound subject token is already refused (its D2 consequence 4).
3. **Key rotation for confidential clients.** Strict continuity costs a sign-out per family on rotation, and needs a shared DPoP key across instances. *Recommendation:* strict now. If a relying party needs rotation, add a rebind only for key-authenticated clients outside the delegation paths, by amendment.
4. **Legacy public families.** Adopt at first use, or revoke at the upgrade. *Recommendation:* adopt, and state in the upgrade notes that an operator who prefers closed can mark families with `binding_method IS NULL` of public clients as `reused`, signing those users out.
5. **End dates for the three legacy relaxations**: unset under flag `false`, `aud` = the issuer, and introspection callers with no resource identifier. *Recommendation:* announce all three in the changelog at this change and end them, unconditionally, in the first minor release after it. A relying party that is not ready stays on the earlier release. Unset then means `mtls` under either flag, which is refused where certificates are not believed. A client with an unset list, or a family with no recorded set, is refused with `invalid_target`, as `client_credentials` already refuses a client with no audience. A caller with no identifier gets `active:false` for any token not issued to it.
6. **The audience check at introspection.** The maintainers' answer of 2026-10-29 was to echo; this record also compares, because RFC 7662 §4 makes the check a MUST once tokens are per resource. *Recommendation:* accept it. The alternative is echo only, recorded as a deviation from §4, with every gateway checking `aud` itself.
7. **`/revoke` without the family's proof.** A thief of a public client's live refresh token can sign the user out, though not gain access. The alternative is to require the family's DPoP proof at `/revoke`. *Recommendation:* leave `/revoke` as it is and keep this as an open rule. Revocation is a safety action, and a client that has lost its key must still be able to sign out. A proof at `/revoke` is defined nowhere (RFC 7009 §2.1, RFC 9449), so standard client libraries would not send one. And a thief holding a superseded token can force the same sign-out anyway.
8. **Review status.** This record has had its adversarial round and one independent security review. The reviewer confirmed that the review's findings are closed in this text, and found two more in D5, the revision number and the history table's permissions, which this version adds. None of it is implemented. Acceptance is the maintainers' decision.
