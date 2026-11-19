# MCP authorization against tessera, measured

| Field | Value |
|---|---|
| Date | 2026-11-19 |
| Status | Measured. It supersedes the MCP rows of the [agentic IAM landscape, October 2026](agentic-iam-landscape-2026-10.md), which mapped requirements by reading. |
| Question | Can a stock MCP client reach an MCP server through tessera today, under the MCP specification and its extensions as they stand on the day? What stops it, in which deployment mode, and what removes each block? |
| Answer | **In single-tenant mode, yes, for a client that does DPoP and is pre-registered.** Metadata discovery and the DPoP scenarios of the official conformance suite pass. A client without DPoP is refused at the token endpoint, which is the security floor, by design. **In multi-tenant mode, no:** a client holding only an issuer URL is stopped at discovery (`400`, no tenant header), until the issuer chooses the realm (ADR-IAM-011). Five requirements are not met today, and each is listed below with what removes it. |
| Source state | tessera `main` `93c0a93` plus an unrelated change to the tenant registry (suspension), built `prod,singlenode` on PostgreSQL 17. The MCP specification repository is at `c5c0da7` (2026-11-18), revision **2026-07-28** in force. ext-auth is at `15ca394` (2026-10-23). The conformance suite `modelcontextprotocol/conformance` is at `96a6f94` (2026-11-10). |

## Sources read on the day

- **MCP core, 2026-07-28, authorization** (`basic/authorization/`: index, authorization-server discovery, client registration, security considerations). It is still the revision in force: the repository's `draft` folder is newer, but not released.
- **ext-auth, stable at 2026-07-28:** OAuth Client Credentials and Enterprise-Managed Authorization (ID-JAG).
  - The experimental DPoP extension is not on ext-auth's `main` at `15ca394`. The conformance suite already tests it, under the authorization-server scenario `dpop`.
  - Workload identity federation has no specification text on `main`.
- **Conformance suite.** Its authorization-server scenarios are `authorization-server-metadata-endpoint`, `authorization-code-grant` and `dpop`. Its requirement sets deliberately exclude authorization-server scenarios, since the MCP specification puts the authorization server out of its scope. The results below are therefore evidence, not a conformance claim.

## Conformance results

The suite was run with `authorization --url <issuer> --client-id <public client> --spec-version 2026-07-28`. The client was public, pre-registered with the redirect `http://127.0.0.1:3000/callback` and the scope `offline_access`. A scripted user agent signed in and allowed consent.

| Scenario | Single-tenant (fixed realm) | Multi-tenant (realm by header) |
|---|---|---|
| `authorization-server-metadata-endpoint` | **pass**, from the OIDC location. The RFC 8414 location is `404`. The CIMD check is a warning: `client_id_metadata_document_supported` is absent. | **fail:** `400` at every metadata location, because a stock client sends no `X-Tenant-Id` |
| `authorization-code-grant` | **fail:** `400` at `/token`. The scenario sends no DPoP proof, and tessera requires one from a public client (`invalid_dpop_proof`). Everything before `/token` passed: redirect URI, `code`, `state` and `iss` checks. | **fail** (no metadata) |
| `dpop` | **pass**, 3 of 3: `dpop_signing_alg_values_supported` is advertised, no `none` or symmetric algorithm, and the access token is bound (`cnf.jkt`, `token_type: DPoP`) | **fail** (no metadata) |

## The realm question

The client follows RFC 9728 `authorization_servers` to an issuer URL, then reads that issuer's metadata.
- **With a fixed realm**, the issuer URL is the deployment's origin, so every step works.
- **With realms chosen by header**, the issuer is shared and the realm comes from a header that only a trusted gateway sets. A stock client cannot set it, and must not be able to. It is stopped at its first request.

ADR-IAM-011 chooses the realm by issuer URL. Once its issuer-per-realm routes and per-realm discovery ship, each realm has its own issuer, with both metadata locations under it. A protected resource then names that realm's issuer in `authorization_servers`, and the same flow works per realm. Until then, MCP clients are served in single-tenant mode only.

## Requirement by requirement

Each row is met today (with evidence), covered by an item that was re-checked and still covers it, by design, or a gap.

| Requirement (MCP 2026-07-28 unless stated) | State | Evidence or what removes it |
|---|---|---|
| Discovery: RFC 8414 **or** OIDC Discovery (AS MUST provide one) | **met** | OIDC location served, and the metadata scenario passes |
| RFC 8414 location as well | covered | Per-realm discovery serves both locations (ADR-IAM-011, step 5). Clients MUST try both, so this is interop, not conformance |
| `code_challenge_methods_supported` in OIDC metadata (AS MUST) | **met** | `["S256"]` |
| PKCE S256 | **met** | Code-grant scenario passed every pre-token check |
| Exact redirect URI match (AS MUST) | **met** | `RedirectUriPolicy`, loopback `http` for public clients only |
| RFC 9207: include `iss` (SHOULD), and **advertise** `authorization_response_iss_parameter_supported` when included (MUST) | **gap, covered** | `iss` is sent on success and on error, but the flag is absent, which breaks the MUST. A small discovery change already planned removes it |
| RFC 8707 `resource` at `/authorize` and `/token`, and audience validation by the MCP server (MUST) | **gap, covered** | `resource` is ignored on the code grant, and `aud` is the issuer, so an MCP server cannot tell a token meant for it from one meant for another resource. ADR-IAM-009 D3 (per-resource `aud`) removes it |
| Client ID Metadata Documents (AS and client SHOULD) | **gap** | Not supported: `client_id_metadata_document_supported` absent, no fetch. A new item, with the SSRF controls of the CIMD draft §6 |
| Dynamic Client Registration | by design | Deprecated by MCP in favour of CIMD. Open registration is not offered, and pre-registration works |
| `token_endpoint_auth_methods_supported` includes `none` when public clients are served | **gap** | Public clients are served, but `none` is not advertised. A client that checks the list before using a public flow stops. A small discovery-honesty change removes it |
| Refresh-token rotation for public clients (AS MUST) | **met** | Single-use rotation with reuse detection |
| Refresh and step-up scope accumulation | **met**, with registration | A scope not registered for the client is `invalid_scope` on the error redirect, with `iss`. An MCP server's scopes must be registered for the client, and consent asks again for new scopes. Silent narrowing would also be allowed: tessera refuses instead |
| Short-lived access tokens (SHOULD) | **met** | 5 minutes |
| HTTPS on every AS endpoint (MUST) | deployment | Production redirects `http` to `https`, and the local run turned that off |
| Token passthrough forbidden: an MCP server calls upstream with a separate token | covered | ADR-IAM-007's intermediary rule needs token exchange (RFC 8693), which the token-exchange item builds |
| Client credentials extension (stable) | **met** | `client_secret_basic` and `private_key_jwt` are advertised, with `token_endpoint_auth_signing_alg_values_supported` |
| Enterprise-managed authorization, ID-JAG (stable) | **gap** | Tessera as resource authorization server would need the `jwt-bearer` grant validating an ID-JAG, and `authorization_grant_profiles_supported`. Tessera as identity provider would need token exchange issuing ID-JAGs. Neither is built, and which role tessera takes is a decision. A new item |
| DPoP extension (experimental) | **met**, except code binding | The scenario passes. `dpop_jkt` code binding (RFC 9449 §10, SHOULD in the extension) is covered by the item that binds codes to a DPoP key |
| A client without DPoP, as a public client | by design | Refused (`invalid_dpop_proof`). Tessera's floor binds every public client's token, and MCP's base specification does not require DPoP, so such clients cannot use tessera as public clients. A confidential client is bound by mTLS, or by DPoP once ADR-IAM-009 D1 ships |

## Recommendation

1. **Support MCP clients first in single-tenant mode,** for clients that do DPoP and PKCE and are pre-registered. That works today, as measured.
2. **Then close, in this order:**
   1. the RFC 9207 flag and `none` in the auth methods (both small discovery changes);
   2. per-resource `aud` with RFC 8707 at `/authorize` (ADR-IAM-009 D3), the one gap that weakens the MCP server's own check;
   3. `dpop_jkt` code binding;
   4. issuer per realm with per-realm discovery (ADR-IAM-011), which opens multi-tenant mode;
   5. Client ID Metadata Documents;
   6. token exchange, for MCP servers calling upstream;
   7. ID-JAG, once the role decision is made.
3. **Keep the security floor.** Supporting MCP clients without DPoP as public clients would mean unbound public tokens. Tessera's floor rules that out, so no mode is offered for them.

## For the end-to-end prototype

The prototype (agent → tessera → MCP server) should run the measured path:
- single-tenant mode, a pre-registered public client with DPoP and PKCE, and the MCP server's scopes registered for that client;
- the MCP server publishes RFC 9728 metadata naming the deployment's issuer.

Until per-resource `aud` ships, the MCP server receives `aud` = the issuer. It must not treat that as proof that the token was meant for it. It has to check `client_id` against what it expects, the stop-gap a relying party already uses today.
