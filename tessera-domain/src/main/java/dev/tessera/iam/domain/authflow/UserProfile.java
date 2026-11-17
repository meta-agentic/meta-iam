package dev.tessera.iam.domain.authflow;

/**
 * What the user record says about a person that a relying party may read under the standard
 * scopes (OIDC Core §5.4): {@code email} and {@code email_verified} under {@code email},
 * {@code name} under {@code profile}.
 *
 * @param email         the address, or {@code null} when none is set
 * @param emailVerified whether the address was verified. An address the operator declared counts
 *                      as administratively verified; a future self-service path sets {@code false}
 *                      until it has sent verification mail. Meaningless when {@code email} is null.
 * @param name          the full name for display, or {@code null} when none is set
 */
public record UserProfile(String email, boolean emailVerified, String name) {

    /** A profile with nothing set. */
    public static final UserProfile EMPTY = new UserProfile(null, false, null);

    public UserProfile {
        if (email != null && email.isBlank()) {
            throw new IllegalArgumentException("UserProfile email, when present, must not be blank");
        }
        if (name != null && name.isBlank()) {
            throw new IllegalArgumentException("UserProfile name, when present, must not be blank");
        }
    }
}
