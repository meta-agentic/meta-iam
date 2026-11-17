package dev.tessera.iam.domain.client;

import dev.tessera.iam.domain.tenancy.SecurityProfile;

/**
 * The one function that decides whether a client meets its tenant's security profile
 * (ADR-IAM-010 D2 and D3). Every endpoint that authenticates a client asks it after the client
 * authenticated and before anything is issued or answered; a client that does not meet the profile
 * is {@code invalid_client}.
 *
 * <ul>
 *   <li>{@code standard}: confidential and public clients, any registered authentication method.
 *       The floor (D1) is enforced where each rule lives and is not repeated here.</li>
 *   <li>{@code fapi2}: met by no client until its requirements are built (ADR-IAM-010 plan step 7),
 *       so a tenant stored on it is refused everywhere. Its rows of D3 (confidential clients only,
 *       {@code private_key_jwt} or mTLS, the workload-identity deviation for clients acting for
 *       themselves) are added here when that step ships.</li>
 * </ul>
 */
public final class ProfileConformance {

    private ProfileConformance() {
    }

    /** The verdict, with a reason for the server log (never sent to the caller). */
    public sealed interface Verdict permits Verdict.Meets, Verdict.Fails {

        /** The client meets the profile. */
        record Meets() implements Verdict {
        }

        /** @param reason why it does not, for the log */
        record Fails(String reason) implements Verdict {
        }

        /** Whether the client meets the profile. */
        default boolean meets() {
            return this instanceof Meets;
        }
    }

    private static final Verdict MEETS = new Verdict.Meets();

    /**
     * Decides whether {@code client} meets {@code profile} for {@code use}.
     *
     * @param profile the tenant's profile (never {@code null})
     * @param client  the authenticated client (never {@code null})
     * @param use     what it authenticated for (never {@code null})
     * @return the verdict
     */
    public static Verdict check(SecurityProfile profile, Client client, ClientUse use) {
        if (profile == null || client == null || use == null) {
            throw new IllegalArgumentException("profile, client and use must not be null");
        }
        return switch (profile) {
            case STANDARD -> MEETS;
            case FAPI2 -> new Verdict.Fails("the fapi2 profile is not available yet");
        };
    }
}
