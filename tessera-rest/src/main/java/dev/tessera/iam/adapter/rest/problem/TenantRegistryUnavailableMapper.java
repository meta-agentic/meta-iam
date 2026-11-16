package dev.tessera.iam.adapter.rest.problem;

import dev.tessera.iam.application.port.out.TenantRegistryUnavailableException;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;

/**
 * Answers a request refused because the tenant registry could not be read with {@code 503}. It is
 * not an OAuth error: nothing about the client or the tenant was decided, and the request is never
 * served on a default (ADR-IAM-003 D1 consequence 2).
 */
public class TenantRegistryUnavailableMapper {

    @ServerExceptionMapper
    public Response unavailable(TenantRegistryUnavailableException unavailable) {
        return ProblemResponse.registryUnavailable();
    }
}
