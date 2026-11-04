// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import dev.tessera.iam.adapter.rest.signin.ThemeDirectory.Asset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/**
 * Verifies the manifest the operator's CI signs once a theme has passed its checks
 * (ADR-IAM-008 D6).
 *
 * <p>The manifest is a compact JWS, {@code ES256} and {@code typ} {@value #TYPE} only, whose payload
 * names the theme and lists the SHA-256 of every file:
 * <pre>{"theme":"acme","files":{"theme.css":"&lt;hex&gt;","fonts/a.woff2":"&lt;hex&gt;"}}</pre>
 *
 * <p>A theme fails if the signature does not verify under the configured key, if the manifest names
 * another theme, or if a file is missing, added or changed. Messages name the theme and the reason,
 * never key material.
 */
final class ThemeManifest {

    /** The {@code typ} header of a manifest, so no other token from the same key can pass for one. */
    static final String TYPE = "tessera-theme-manifest+jws";

    private ThemeManifest() {
    }

    /**
     * Parses the configured public key.
     *
     * @param json the key as a JWK
     * @return the key
     * @throws IllegalStateException when it is not a public {@code P-256} key; the message does not
     *                               repeat the value, in case private material was configured
     */
    static ECKey publicKey(String json) {
        JWK key;
        try {
            key = JWK.parse(json);
        } catch (ParseException e) {
            throw new IllegalStateException("iam.signin.themes.public-key is not a JWK");
        }
        if (!(key instanceof ECKey ec) || !Curve.P_256.equals(ec.getCurve())) {
            throw new IllegalStateException("iam.signin.themes.public-key is not a P-256 key");
        }
        if (ec.isPrivate()) {
            throw new IllegalStateException("iam.signin.themes.public-key holds private key material");
        }
        return ec;
    }

    /**
     * Verifies a theme's manifest against its files.
     *
     * @param theme    the name of the theme's directory
     * @param manifest the manifest file's bytes
     * @param assets   the theme's files
     * @param key      the public key
     * @throws IllegalStateException when the theme fails verification
     */
    static void verify(String theme, byte[] manifest, Map<String, Asset> assets, ECKey key) {
        Map<String, Object> payload = verifiedPayload(theme, manifest, key);
        if (!theme.equals(payload.get("theme"))) {
            throw failure(theme, "its manifest names a different theme");
        }
        if (!(payload.get("files") instanceof Map<?, ?> listed)) {
            throw failure(theme, "its manifest lists no files");
        }
        Set<?> names = listed.keySet();
        for (Object name : names) {
            if (!assets.containsKey(name)) {
                throw failure(theme, "a file its manifest lists is missing: " + name);
            }
        }
        for (Map.Entry<String, Asset> asset : assets.entrySet()) {
            if (!names.contains(asset.getKey())) {
                throw failure(theme, "a file its manifest does not list is present: " + asset.getKey());
            }
            if (!(listed.get(asset.getKey()) instanceof String expected) || !MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.US_ASCII),
                    sha256(asset.getValue().bytes()).getBytes(StandardCharsets.US_ASCII))) {
                throw failure(theme, "a file differs from its manifest: " + asset.getKey());
            }
        }
    }

    private static Map<String, Object> verifiedPayload(String theme, byte[] manifest, ECKey key) {
        JWSObject jws;
        try {
            jws = JWSObject.parse(new String(manifest, StandardCharsets.US_ASCII).strip());
        } catch (ParseException e) {
            throw failure(theme, "its manifest is not a JWS");
        }
        if (!JWSAlgorithm.ES256.equals(jws.getHeader().getAlgorithm())) {
            throw failure(theme, "its manifest is not ES256");
        }
        if (!new JOSEObjectType(TYPE).equals(jws.getHeader().getType())) {
            throw failure(theme, "its manifest has the wrong type");
        }
        try {
            if (!jws.verify(new ECDSAVerifier(key))) {
                throw failure(theme, "its manifest's signature does not verify");
            }
            Map<String, Object> payload = jws.getPayload().toJSONObject();
            if (payload == null) {
                throw failure(theme, "its manifest's payload is not JSON");
            }
            return payload;
        } catch (JOSEException e) {
            throw failure(theme, "its manifest's signature cannot be checked");
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static IllegalStateException failure(String theme, String reason) {
        return new IllegalStateException("Sign-in theme " + theme + " is refused: " + reason);
    }
}
