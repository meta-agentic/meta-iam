// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import dev.tessera.iam.adapter.rest.signin.ThemeDirectory.Asset;
import io.smallrye.common.annotation.NonBlocking;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * Serves theme files to the sign-in page, from what {@link SignInThemes} read at boot. A request
 * path is only ever a key into that map, so it cannot reach the file system.
 *
 * <p>Not tenant-scoped: a browser sends no tenant with a stylesheet request, and a theme holds
 * nothing private (ADR-IAM-008 D1).
 */
@Path("/assets/themes")
@Tag(name = "sign-in", description = "Hosted sign-in page for the authorization code flow.")
public class SignInThemeResource {

    private static final String CACHE = "public, max-age=300";

    @Inject
    SignInThemes themes;

    @GET
    @Path("{theme}/{path:.+}")
    @NonBlocking
    @Operation(operationId = "signInThemeAsset", summary = "A file of a sign-in page theme")
    public Response asset(@PathParam("theme") String theme, @PathParam("path") String path) {
        Asset asset = themes.asset(theme, path);
        if (asset == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(asset.bytes())
                .type(asset.contentType())
                .header("Cache-Control", CACHE)
                .build();
    }
}
