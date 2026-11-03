// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import dev.tessera.iam.adapter.rest.config.ClientAssertionConfig;
import io.vertx.mutiny.core.Vertx;
import jakarta.enterprise.inject.Alternative;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Clock;

/**
 * {@link TrustedIssuerJwks} as configured, fetching from the {@link StubIssuer} over real TLS with
 * the production transport (no redirects, no proxy, the deadline and the size limit), trusting
 * only the stub's certificate. Enabled by a test profile, never by default.
 *
 * <p>Two things differ from production, both because the stub runs on the loopback interface. The
 * address check is given a public documentation address (203.0.113.7) for {@code localhost}, since
 * a loopback target is refused, which {@code TrustedIssuerJwksTest} covers. And the cache's clock
 * runs {@link StubIssuer#ahead()} of the real one, so a test passes the refresh interval without
 * waiting; the verifier's own clock, which judges {@code exp}, is the real one.
 */
@Alternative
@Singleton
public class StubIssuerJwks extends TrustedIssuerJwks {

    @Inject
    public StubIssuerJwks(Vertx vertx, Clock clock, ClientAssertionConfig config) {
        super(vertx, () -> clock.instant().plus(StubIssuer.get().ahead()), config,
                https(DEADLINE, StubIssuer.get().clientTls()), StubIssuerJwks::resolve);
    }

    private static InetAddress[] resolve(String host) throws UnknownHostException {
        if (!"localhost".equals(host)) {
            throw new UnknownHostException(host);
        }
        return new InetAddress[] {InetAddress.getByName("203.0.113.7")};
    }
}
