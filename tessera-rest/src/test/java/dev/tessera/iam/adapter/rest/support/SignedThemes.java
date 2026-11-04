// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/** Writes themes signed as the operator's CI signs them, under a key made for the test. */
public final class SignedThemes {

    private SignedThemes() {
    }

    /** A new signing key. */
    public static ECKey newKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Writes the files of a theme under {@code root} and signs its manifest. */
    public static Path write(Path root, ECKey key, String theme, Map<String, byte[]> files) throws IOException {
        Path dir = root.resolve(theme);
        Map<String, Object> hashes = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> file : files.entrySet()) {
            Path path = dir.resolve(file.getKey());
            Files.createDirectories(path.getParent());
            Files.write(path, file.getValue());
            hashes.put(file.getKey(), sha256(file.getValue()));
        }
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("manifest.jws"),
                manifest(key, JWSAlgorithm.ES256, "tessera-theme-manifest+jws", Map.of("theme", theme, "files", hashes)));
        return dir;
    }

    /** A compact JWS with the given header values and payload. */
    public static String manifest(ECKey key, JWSAlgorithm algorithm, String type, Map<String, Object> payload) {
        try {
            JWSObject jws = new JWSObject(
                    new JWSHeader.Builder(algorithm).type(new JOSEObjectType(type)).build(), new Payload(payload));
            jws.sign(new ECDSASigner(key));
            return jws.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
