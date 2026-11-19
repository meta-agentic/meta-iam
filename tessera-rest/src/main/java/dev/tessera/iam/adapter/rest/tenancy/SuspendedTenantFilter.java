package dev.tessera.iam.adapter.rest.tenancy;

import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Optional;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;

/**
 * Answers a suspended tenant at the sign-in flow's browser endpoints with a {@code 403} error page,
 * before any sign-in and with no redirect to the client (ADR-IAM-011 D5, the suspended row;
 * ADR-IAM-003 D1 consequence 2). Without it a user of a suspended tenant would sign in and receive a
 * code that {@code /token} then refuses.
 *
 * <p>It runs after {@link TenantResolutionFilter}, which binds the realm, and only on endpoints
 * marked {@link RefusesSuspendedTenant}: discovery and the key set keep answering a suspended tenant,
 * and {@code /token}, {@code /introspect} and {@code /revoke} apply the rule their own way. An
 * unregistered tenant passes here and is refused at {@code /token}; answering it {@code 404} on every
 * endpoint comes with the realm registry. An unreadable registry fails the request, which the edge
 * answers with {@code 503}, never a default.
 */
public class SuspendedTenantFilter {

    private static final System.Logger LOG = System.getLogger(SuspendedTenantFilter.class.getName());

    /** The page has no form, no script and no link, so its policy allows nothing. */
    static final String POLICY =
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    static final String PAGE = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sign-in unavailable</title>
            </head>
            <body>
            <main>
            <h1>Sign-in is unavailable</h1>
            <p>This organisation's account is suspended. Contact its administrator.</p>
            </main>
            </body>
            </html>
            """;

    @Inject
    TenantContext tenantContext;

    @Inject
    TenantRegistryPort registry;

    @ServerRequestFilter(priority = Priorities.AUTHENTICATION + 5)
    @RefusesSuspendedTenant
    public Uni<Response> filter(ContainerRequestContext request) {
        Optional<RealmKey> realm = tenantContext.realmIfPresent();
        if (realm.isEmpty()) {
            return Uni.createFrom().nullItem();
        }
        return registry.find(realm.get().tenant()).map(found -> {
            if (found.isEmpty() || found.get().isActive()) {
                return null;
            }
            LOG.log(System.Logger.Level.WARNING, "{0} refused: tenant {1} is {2}",
                    request.getUriInfo().getPath(), realm.get().tenant().value(),
                    found.get().status().wireName());
            return suspendedPage();
        });
    }

    static Response suspendedPage() {
        return Response.status(Response.Status.FORBIDDEN)
                .type(MediaType.TEXT_HTML + ";charset=UTF-8")
                .entity(PAGE)
                .header("Content-Security-Policy", POLICY)
                .header("Referrer-Policy", "no-referrer")
                .header("Cache-Control", "no-store")
                .build();
    }
}
