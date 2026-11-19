package dev.tessera.iam.domain.refresh;

import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/**
 * An immutable snapshot of a refresh-token lineage (a "family"), loaded from the store so the
 * pure {@link RefreshReuseDetection} rule can reason over it.
 *
 * <p>A family models single-use rotation with replay detection. Each redemption issues a fresh
 * token and advances the family:
 * <ul>
 *   <li>{@link #currentTokenHash()} is the hash of the latest (live) token — never the token
 *       itself;</li>
 *   <li>{@link #previousTokenHash()} is the hash of the immediately superseded token (or
 *       {@code null} at generation 0). Presenting it is a replay signal;</li>
 *   <li>{@link #generation()} counts rotations;</li>
 *   <li>{@link #reused()} is {@code true} once a replay has been detected — the whole family is
 *       then revoked and no token in it is redeemable.</li>
 * </ul>
 *
 * <p>The {@link #realm()} is the family's <strong>authoritative</strong> tenant, stored
 * server-side; it is the source of truth for the family's ownership, resolved independently of
 * any request header. Hashing is an adapter concern — the domain compares opaque hash strings and
 * never sees a raw token.
 *
 * @param id                the family identity (never {@code null})
 * @param realm             the authoritative realm that owns the family (never {@code null})
 * @param userId            the owning end-user id (never {@code null} or blank)
 * @param clientId          the client the family was issued to (never {@code null})
 * @param currentTokenHash  hash of the latest live token (never {@code null} or blank)
 * @param previousTokenHash hash of the immediately superseded token, or {@code null} at generation 0
 * @param generation        rotation counter ({@code >= 0})
 * @param reused            whether a replay has been detected (the family is then revoked)
 * @param createdAt         when the family was created (never {@code null})
 * @param expiresAt         when the family expires, or {@code null} if it does not
 * @param rotatedAt         when the family last rotated, or {@code null} if it never has; bounds
 *                          the reuse grace of the superseded token
 * @param rotationSalt      the random salt of the last rotation, or {@code null}; the successor of
 *                          a re-presented predecessor is derived from it, so a server key and an old
 *                          token alone never yield a newer token
 * @param grantedScopes     the scopes of the grant the family was issued under (empty if unknown,
 *                          for families created before they were recorded); a refresh re-issues an
 *                          ID token only when they include {@code openid}
 * @param grantedResources  the whole resource set of the grant the family was issued under
 *                          (ADR-IAM-009 D3 rule A2, RFC 8707 §2.2); empty for a family created
 *                          before it was recorded, which mints no token for a person
 */
public record RefreshTokenFamily(
        FamilyId id,
        RealmKey realm,
        String userId,
        ClientId clientId,
        String currentTokenHash,
        String previousTokenHash,
        int generation,
        boolean reused,
        Instant createdAt,
        Instant expiresAt,
        Instant rotatedAt,
        String rotationSalt,
        Set<String> grantedScopes,
        Set<String> grantedResources) {

    /** A family whose granted resources are not recorded. */
    public RefreshTokenFamily(
            FamilyId id,
            RealmKey realm,
            String userId,
            ClientId clientId,
            String currentTokenHash,
            String previousTokenHash,
            int generation,
            boolean reused,
            Instant createdAt,
            Instant expiresAt,
            Instant rotatedAt,
            String rotationSalt,
            Set<String> grantedScopes) {
        this(id, realm, userId, clientId, currentTokenHash, previousTokenHash, generation, reused,
                createdAt, expiresAt, rotatedAt, rotationSalt, grantedScopes, Set.of());
    }

    /** A family that has never rotated, issued under {@code grantedScopes}. */
    public RefreshTokenFamily(
            FamilyId id,
            RealmKey realm,
            String userId,
            ClientId clientId,
            String currentTokenHash,
            String previousTokenHash,
            int generation,
            boolean reused,
            Instant createdAt,
            Instant expiresAt,
            Set<String> grantedScopes) {
        this(id, realm, userId, clientId, currentTokenHash, previousTokenHash, generation, reused,
                createdAt, expiresAt, null, null, grantedScopes);
    }

    /** A family that has never rotated and whose granted scopes are not recorded. */
    public RefreshTokenFamily(
            FamilyId id,
            RealmKey realm,
            String userId,
            ClientId clientId,
            String currentTokenHash,
            String previousTokenHash,
            int generation,
            boolean reused,
            Instant createdAt,
            Instant expiresAt) {
        this(id, realm, userId, clientId, currentTokenHash, previousTokenHash, generation, reused,
                createdAt, expiresAt, null, null, Set.of());
    }

    public RefreshTokenFamily {
        grantedScopes = grantedScopes == null ? Set.of() : Set.copyOf(grantedScopes);
        grantedResources = grantedResources == null ? Set.of() : Set.copyOf(grantedResources);
        if (id == null) {
            throw new IllegalArgumentException("RefreshTokenFamily id must not be null");
        }
        if (realm == null) {
            throw new IllegalArgumentException("RefreshTokenFamily realm must not be null");
        }
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("RefreshTokenFamily userId must not be null or blank");
        }
        if (clientId == null) {
            throw new IllegalArgumentException("RefreshTokenFamily clientId must not be null");
        }
        if (currentTokenHash == null || currentTokenHash.isBlank()) {
            throw new IllegalArgumentException("RefreshTokenFamily currentTokenHash must not be blank");
        }
        if (generation < 0) {
            throw new IllegalArgumentException("RefreshTokenFamily generation must not be negative");
        }
        if (createdAt == null) {
            throw new IllegalArgumentException("RefreshTokenFamily createdAt must not be null");
        }
        if (expiresAt != null && !expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("RefreshTokenFamily expiresAt must be after createdAt");
        }
    }

    /** The same family after a rotation at {@code now} to {@code newTokenHash}, with its salt. */
    public RefreshTokenFamily rotatedTo(String newTokenHash, Instant now, String salt) {
        return new RefreshTokenFamily(id, realm, userId, clientId, newTokenHash, currentTokenHash,
                generation + 1, false, createdAt, expiresAt, now, salt, grantedScopes, grantedResources);
    }

    /** The same family, revoked. */
    public RefreshTokenFamily burned() {
        return new RefreshTokenFamily(id, realm, userId, clientId, currentTokenHash, previousTokenHash,
                generation, true, createdAt, expiresAt, rotatedAt, rotationSalt, grantedScopes, grantedResources);
    }

    /**
     * True if the family rotated less than {@code grace} before {@code now}: the window in which the
     * token it superseded may still be presented without being treated as a replay.
     */
    public boolean rotatedWithin(Duration grace, Instant now) {
        return rotatedAt != null
                && grace != null
                && !grace.isNegative()
                && !grace.isZero()
                && now.isBefore(rotatedAt.plus(grace));
    }

    /** True if the family has an expiry and it is at or before {@code now}. */
    public boolean isExpired(Instant now) {
        return expiresAt != null && !now.isBefore(expiresAt);
    }
}
