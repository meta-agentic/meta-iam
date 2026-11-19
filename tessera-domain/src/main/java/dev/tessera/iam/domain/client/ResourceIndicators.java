// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.domain.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The audience rules for tokens issued for a person (ADR-IAM-009 D3, RFC 8707).
 *
 * <p>A client registers the resources such tokens may name ({@code user_audiences}). An
 * authorization request may name some of them with {@code resource}. The grant holds that set,
 * or the whole list when none is named. Each token then names exactly one resource from the
 * grant's set, intersected with the client's current list, so an audience removed from the
 * client leaves its grants at once and one registered later never enters them. The realm's issuer
 * is never an audience.
 *
 * <p>Framework-free and total: every method answers, and a refusal is {@code invalid_target}.
 */
public final class ResourceIndicators {

    private ResourceIndicators() {
    }

    /**
     * @param value a candidate resource identifier
     * @return {@code true} iff it is an absolute URI with no fragment (RFC 8707 §2), compared later
     *         by exact string
     */
    public static boolean isResourceIdentifier(String value) {
        if (value == null || value.isEmpty() || value.chars().anyMatch(Character::isWhitespace)) {
            return false;
        }
        try {
            URI uri = new URI(value);
            return uri.isAbsolute() && uri.getRawFragment() == null;
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /** The outcome of a rule: the resources it settled on, or the reason it refused. */
    public sealed interface Outcome permits Outcome.Granted, Outcome.Refused {

        /** @param resources the resources settled on (never empty) */
        record Granted(Set<String> resources) implements Outcome {
            public Granted {
                resources = Set.copyOf(new LinkedHashSet<>(resources));
            }
        }

        /** @param description why, for {@code error_description} */
        record Refused(String description) implements Outcome {
        }
    }

    /**
     * The grant's set at {@code /authorize}: the named resources, each registered, or the whole
     * registered list when none is named.
     *
     * @param requested  the {@code resource} values on the request (never {@code null}, may be empty)
     * @param registered the client's {@code user_audiences} (never {@code null})
     * @return the set to store on the grant, or a refusal
     */
    public static Outcome grantSet(Set<String> requested, Set<String> registered) {
        if (registered.isEmpty()) {
            return new Outcome.Refused("the client has no resource registered for tokens issued for a person");
        }
        if (requested.isEmpty()) {
            return new Outcome.Granted(registered);
        }
        for (String resource : requested) {
            if (!registered.contains(resource)) {
                return new Outcome.Refused("a requested resource is not registered for this client");
            }
        }
        return new Outcome.Granted(requested);
    }

    /**
     * The one audience of a token minted from a grant (rule A1 at {@code /token}, rule A2 at
     * refresh).
     *
     * @param granted    the grant's or family's resource set (never {@code null})
     * @param registered the client's current {@code user_audiences} (never {@code null})
     * @param named      the {@code resource} values on the token request (never {@code null})
     * @param issuer     the realm's issuer, which is never an audience
     * @return a single-element set, or a refusal
     */
    public static Outcome audience(
            Set<String> granted, Set<String> registered, Collection<String> named, String issuer) {
        Set<String> candidates = new LinkedHashSet<>(granted);
        candidates.retainAll(registered);
        candidates.remove(issuer);
        if (named.size() > 1) {
            return new Outcome.Refused("at most one resource may be named on a token request");
        }
        if (named.size() == 1) {
            String resource = named.iterator().next();
            return candidates.contains(resource)
                    ? new Outcome.Granted(Set.of(resource))
                    : new Outcome.Refused("the requested resource was not granted to this client");
        }
        if (candidates.size() == 1) {
            return new Outcome.Granted(candidates);
        }
        return new Outcome.Refused(candidates.isEmpty()
                ? "no granted resource is still registered for this client"
                : "the grant holds several resources: name one with the resource parameter");
    }
}
