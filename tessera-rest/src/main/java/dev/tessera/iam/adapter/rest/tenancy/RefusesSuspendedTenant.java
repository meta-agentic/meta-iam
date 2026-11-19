package dev.tessera.iam.adapter.rest.tenancy;

import jakarta.ws.rs.NameBinding;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a browser-facing endpoint of the sign-in flow ({@code /authorize}, the sign-in, login and
 * consent pages) that answers a suspended tenant with a {@code 403} error page and no redirect to
 * the client, before any sign-in (ADR-IAM-011 D5, the suspended row). {@link SuspendedTenantFilter}
 * does the check. Every such resource is also {@link TenantScoped}, so the realm is resolved first.
 */
@NameBinding
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RefusesSuspendedTenant {
}
