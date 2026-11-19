# Can a Quarkus OIDC back end send DPoP proofs on the code flow?

| Field | Value |
|---|---|
| Date | 2026-11-19 |
| Status | Measured locally. Answers the question that [ADR-IAM-009](../adr/ADR-IAM-009-sender-constraint-refresh-binding-and-audience.md) open item 5 and [ADR-IAM-010](../adr/ADR-IAM-010-security-floor-and-tenant-profiles.md) D4 consequence 2 leave open. Showing a production relying party sending proofs, as open item 5 requires before the cut-over, is still that relying party's work. |
| Question | Can a back-end-for-frontend built on `quarkus-oidc` (`application-type=web-app`) send a DPoP proof (RFC 9449) when it redeems a code and when it refreshes, and does the library accept the `token_type` `DPoP` that tessera then returns? |
| Answer | **Yes, through `OidcRequestFilter`.** A filter on the `TOKEN` endpoint adds the `DPoP` header to code redemption and to refresh. `quarkus-oidc` accepts `token_type: DPoP`, and the access token carries `cnf.jkt` set to the back end's key. |
| Source state | tessera `main` at `93c0a93`, built with `-Dquarkus.profile=prod,singlenode`. `quarkus-oidc` 3.40.1.1. The Quarkus platform is the same version tessera uses. |

## How it was measured

- **Tessera:** single-tenant mode on PostgreSQL 17, with first boot provisioning a key and a password user.
- **Client:** a public client (`PUBLIC`, `authorization_code,refresh_token`, redirect `http://localhost:8081/callback`) was inserted by hand. Until ADR-IAM-009 D1 is built, tessera binds DPoP for public clients only. The filter does not depend on the client type, so a confidential client's back end uses the same hook once D1 ships.
- **Back end:** a Quarkus 3.40.1.1 application with `quarkus-oidc` (`web-app`, PKCE, nonce, scopes `offline_access profile`) and one `@Authenticated` endpoint.
- **Browser:** a scripted stand-in that follows redirects, fills the sign-in form and allows consent. Python `requests` does not send a `Secure` cookie to `http://localhost`, though a browser does, so the script cleared that flag on the cookies it received.

The filter that does the work:

```java
@ApplicationScoped
@Unremovable
@OidcEndpoint(OidcEndpoint.Type.TOKEN)
public class DpopTokenRequestFilter implements OidcRequestFilter {

    @Inject
    DpopProofs proofs;          // one P-256 key, RFC 9449 proofs signed ES256 with the public JWK in the header

    @ConfigProperty(name = "app.token-endpoint")
    String tokenEndpoint;       // the htu claim: the token endpoint URL from discovery

    @Override
    public void filter(OidcRequestContext context) {
        context.request().putHeader("DPoP", proofs.proof("POST", tokenEndpoint, null));
    }
}
```

An `OidcResponseFilter` on the same endpoint recorded each response's status and `token_type`.

## Results

| Run | Token request | Proof sent | Tessera answered | Back end |
|---|---|---|---|---|
| Code flow | `authorization_code` | yes | `200`, `token_type: DPoP`, access token `cnf.jkt` = the back end's key thumbprint | session established, `200` |
| Refresh (forced with `quarkus.oidc.token.refresh-token-time-skew=PT10M`) | `refresh_token` | yes | `200`, `token_type: Bearer`, no `cnf` | session kept, `200` |
| Control: filter switched off | `authorization_code` | no | `400 invalid_dpop_proof` | `401` |

- **The library side works on both requests.** `quarkus-oidc` passes the filter's header through on code redemption and on refresh. It accepts `DPoP` and `Bearer` alike as `token_type`, and it validated tessera's EdDSA ID token.
- **The refresh result is tessera's known defect, not the library's.** The proof was sent, and tessera still minted an unbound token. `RefreshBindingDowngradeProbeTest` pins this behaviour, and ADR-IAM-009 D2 removes it: a refresh proves the family's binding, and the new token keeps it. Once D2 ships, the same filter is what keeps the refresh working.
- **Tessera enforces the binding at redemption.** The control run shows that a public client's code is not redeemed without a proof.

## What a relying party still has to do

The library question is closed. These points belong to the relying party's own change, and none of them blocks it:

1. **One key per relying party, shared by its instances.** Under ADR-IAM-009 open item 2 (strict continuity), a refresh must prove the key the family was bound to. A back end with several instances needs that key from a shared secret store, or a refresh served by another instance is refused once D2 ships. The spike used one in-memory key per process.
2. **Calls to resource servers.** A DPoP-bound access token needs a fresh proof, with `ath`, on every request to a resource server (RFC 9449 §7). `quarkus-oidc`'s token propagation sends a `Bearer` header and makes no proof. A back end that forwards the token needs its own client filter that builds the proof, and each resource server must verify it, or must introspect and check `cnf` and `token_type` itself (ADR-IAM-009 D3, introspection).
3. **Server nonces.** Tessera does not ask for a DPoP nonce. An `OidcRequestFilter` cannot retry a request that is answered `use_dpop_nonce` (RFC 9449 §8), so a server that required nonces would need more than this hook.
4. **The alternative stays available.** Where a trusted edge terminates mutual TLS, `mtls` (ADR-IAM-009 open item 1) avoids the key handling above. It is not needed for this library.

## Reproducing

Build tessera with `mvn package -pl tessera-server -am -Dquarkus.profile=prod,singlenode -DskipTests`, start PostgreSQL, and run `tessera-server/target/quarkus-app/quarkus-run.jar` with the following settings:
- `QUARKUS_DATASOURCE_*` pointing at a role that owns the database;
- `QUARKUS_HTTP_INSECURE_REQUESTS=enabled`;
- a random `IAM_KEYS_MASTER_KEY`;
- `TESSERA_FIXED_TENANT`, `TESSERA_OIDC_ISSUER=http://localhost:8080`;
- `TESSERA_BOOTSTRAP_ENABLED=true` with a client and a user.

Then insert the public client into `oauth_client` for the fixed tenant at the zero baseline, with `user_scopes` `offline_access profile email`. Point the back end's `quarkus.oidc.auth-server-url` at tessera and add the filter above.
